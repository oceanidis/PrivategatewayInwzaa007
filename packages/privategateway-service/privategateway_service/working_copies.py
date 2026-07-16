from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4


class WorkingCopyError(RuntimeError):
    pass


class WorkingCopyStore:
    def __init__(self, safe_root: Path) -> None:
        self.root = safe_root / "working-copies"
        self.root.mkdir(parents=True, exist_ok=True)

    def create(self, *, suffix: str, content: bytes, source_fingerprint: str, policy_fingerprint: str, ttl_seconds: int = 3600) -> dict[str, str]:
        if not suffix.startswith(".") or len(content) > 20 * 1024 * 1024:
            raise WorkingCopyError("SAFE_COPY_INVALID")
        copy_id = uuid4().hex
        path = self.root / f"{copy_id}{suffix}"
        path.write_bytes(content)
        metadata = {"copy_id": copy_id, "path": path.name, "sha256": hashlib.sha256(content).hexdigest(), "source_fingerprint": source_fingerprint, "policy_fingerprint": policy_fingerprint, "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat()}
        (self.root / f"{copy_id}.json").write_text(json.dumps(metadata, sort_keys=True), encoding="utf-8")
        return {"copy_id": copy_id, "suffix": suffix}

    def resolve(self, copy_id: str) -> Path:
        try:
            metadata = json.loads((self.root / f"{copy_id}.json").read_text(encoding="utf-8"))
            path = self.root / metadata["path"]
            if datetime.fromisoformat(metadata["expires_at"]) <= datetime.now(timezone.utc):
                self.revoke(copy_id)
                raise WorkingCopyError("SAFE_COPY_EXPIRED")
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != metadata["sha256"]:
                raise WorkingCopyError("SAFE_COPY_INTEGRITY_FAILED")
            return path
        except FileNotFoundError as exc:
            raise WorkingCopyError("SAFE_COPY_NOT_FOUND") from exc

    def revoke(self, copy_id: str) -> None:
        for path in (self.root / f"{copy_id}.json", *self.root.glob(f"{copy_id}.*")):
            if path.exists():
                path.unlink()

    def purge_expired(self) -> int:
        removed = 0
        for metadata_path in self.root.glob("*.json"):
            try:
                if datetime.fromisoformat(json.loads(metadata_path.read_text(encoding="utf-8"))["expires_at"]) <= datetime.now(timezone.utc):
                    self.revoke(metadata_path.stem)
                    removed += 1
            except (OSError, ValueError, KeyError, json.JSONDecodeError):
                continue
        return removed
