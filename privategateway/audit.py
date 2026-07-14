from __future__ import annotations

import hashlib
import json
import msvcrt
import os
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator


_AUDIT_FILE = "audit.v1.jsonl"
_LOCK_FILE = "audit.v1.lock"
_CHAIN_VERSION = 1
_ALLOWED_FIELDS_BY_EVENT = {
    "import_sanitized": {
        "blocked", "can_export", "event", "job_id", "policy_fingerprint", "project_id", "review_actor", "review_reason",
    },
    "mapping_opened": {"artifact_id", "event", "job_id", "project_id", "purpose"},
}


def append_audit_event(secure_root: str | Path, event: dict[str, Any]) -> None:
    """Append safe operational metadata to a locally integrity-chained audit log."""
    payload = _validated_payload(event)
    root = Path(secure_root)
    root.mkdir(parents=True, exist_ok=True)
    with _audit_lock(root):
        path = root / _AUDIT_FILE
        previous_hash, _ = _read_chain_state(path)
        record = {
            **payload,
            "chain_version": _CHAIN_VERSION,
            "previous_hash": previous_hash,
        }
        record["event_hash"] = _event_hash(record)
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())


def verify_audit_log(secure_root: str | Path) -> dict[str, Any]:
    """Verify the current audit chain without exposing any raw or mapping data."""
    path = Path(secure_root) / _AUDIT_FILE
    if not path.exists():
        return {"valid": True, "event_count": 0, "last_hash": None, "error": None}
    try:
        last_hash, event_count = _read_chain_state(path)
    except ValueError as exc:
        return {"valid": False, "event_count": 0, "last_hash": None, "error": str(exc)}
    return {"valid": True, "event_count": event_count, "last_hash": last_hash, "error": None}


def _validated_payload(event: dict[str, Any]) -> dict[str, Any]:
    event_type = event.get("event")
    allowed = _ALLOWED_FIELDS_BY_EVENT.get(event_type)
    if allowed is None:
        raise ValueError("Unsupported audit event type")
    unexpected = set(event) - allowed
    if unexpected:
        raise ValueError(f"Unsupported audit fields: {sorted(unexpected)}")
    payload = {**event, "timestamp": datetime.now(UTC).isoformat()}
    if any(isinstance(value, (dict, list, tuple, set, bytes, bytearray)) for value in payload.values()):
        raise ValueError("Audit event values must be scalar metadata")
    return payload


def _read_chain_state(path: Path) -> tuple[str | None, int]:
    previous_hash: str | None = None
    event_count = 0
    if not path.exists():
        return previous_hash, event_count
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError("audit log cannot be read") from exc
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"event {line_number} is not valid JSON") from exc
        if not isinstance(record, dict) or record.get("chain_version") != _CHAIN_VERSION:
            raise ValueError(f"event {line_number} has an unsupported chain version")
        event_hash = record.pop("event_hash", None)
        if not isinstance(event_hash, str) or event_hash != _event_hash(record):
            raise ValueError(f"event {line_number} hash mismatch")
        if record.get("previous_hash") != previous_hash:
            raise ValueError(f"event {line_number} previous hash mismatch")
        previous_hash = event_hash
        event_count += 1
    return previous_hash, event_count


def _event_hash(record: dict[str, Any]) -> str:
    canonical = json.dumps(record, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


@contextmanager
def _audit_lock(root: Path) -> Iterator[None]:
    path = root / _LOCK_FILE
    with path.open("a+b") as handle:
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        try:
            yield
        finally:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
