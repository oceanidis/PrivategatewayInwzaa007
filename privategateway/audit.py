from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4


_ALLOWED_FIELDS = {
    "blocked",
    "can_export",
    "event",
    "job_id",
    "policy_fingerprint",
    "project_id",
    "review_actor",
    "review_reason",
}


def append_audit_event(secure_root: str | Path, event: dict[str, Any]) -> None:
    unexpected = set(event) - _ALLOWED_FIELDS
    if unexpected:
        raise ValueError(f"Unsupported audit fields: {sorted(unexpected)}")
    if event.get("event") != "import_sanitized":
        raise ValueError("Unsupported audit event type")
    payload = {
        **event,
        "timestamp": datetime.now(UTC).isoformat(),
    }
    if any(isinstance(value, (dict, list, tuple, set, bytes, bytearray)) for value in payload.values()):
        raise ValueError("Audit event values must be scalar metadata")
    root = Path(secure_root)
    root.mkdir(parents=True, exist_ok=True)
    path = root / "audit.jsonl"
    line = json.dumps(payload, sort_keys=True, ensure_ascii=True) + "\n"
    temporary = root / f".audit-{os.getpid()}-{uuid4().hex}.tmp"
    try:
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
        temporary.write_text(existing + line, encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
