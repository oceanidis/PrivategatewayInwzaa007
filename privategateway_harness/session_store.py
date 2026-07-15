from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import msvcrt

from .config import HarnessConfig
from .errors import HarnessError


@dataclass
class Session:
    root: Path
    manifest: dict[str, Any]
    _lock_handle: Any

    @property
    def manifest_path(self) -> Path:
        return self.root / "manifest.json"

    def save_manifest(self, manifest: dict[str, Any]) -> None:
        _validate_manifest(manifest)
        _atomic_json_write(self.manifest_path, manifest)
        self.manifest = manifest

    def close(self) -> None:
        if self._lock_handle is None:
            return
        self._lock_handle.seek(0)
        msvcrt.locking(self._lock_handle.fileno(), msvcrt.LK_UNLCK, 1)
        self._lock_handle.close()
        self._lock_handle = None


class SessionStore:
    def __init__(self, config: HarnessConfig) -> None:
        self.config = config

    def create(self, session_id: str) -> Session:
        root = self._root_for(session_id)
        if root.exists():
            raise HarnessError("SESSION_ALREADY_EXISTS")
        for directory in (root, root / "safe", root / "output", root / "policies" / "approvals"):
            directory.mkdir(parents=True, exist_ok=True)
        lock = _acquire_lock(root / "session.lock")
        manifest = {"manifest_version": 1, "session_id": session_id, "status": "ACTIVE", "artifacts": {}}
        _atomic_json_write(root / "manifest.json", manifest)
        return Session(root=root, manifest=manifest, _lock_handle=lock)

    def open(self, session_id: str) -> Session:
        root = self._root_for(session_id)
        manifest_path = root / "manifest.json"
        if not manifest_path.is_file():
            raise HarnessError("SESSION_NOT_FOUND")
        lock = _acquire_lock(root / "session.lock")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            _validate_manifest(manifest)
            if manifest["session_id"] != session_id:
                raise HarnessError("INVALID_MANIFEST")
            return Session(root=root, manifest=manifest, _lock_handle=lock)
        except Exception:
            _release_lock(lock)
            raise

    def _root_for(self, session_id: str) -> Path:
        if not session_id or any(character in session_id for character in "\\/:"):
            raise HarnessError("INVALID_SESSION_ID")
        return self.config.sessions_root / session_id


def _acquire_lock(path: Path) -> Any:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+b")
    if handle.tell() == 0:
        handle.write(b"0")
        handle.flush()
    handle.seek(0)
    try:
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    except OSError as exc:
        handle.close()
        raise HarnessError("SESSION_ALREADY_IN_USE") from exc
    return handle


def _release_lock(handle: Any) -> None:
    handle.seek(0)
    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    handle.close()


def _atomic_json_write(path: Path, value: dict[str, Any]) -> None:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    temporary = path.with_name(f"{path.name}.tmp-{os.getpid()}")
    try:
        with temporary.open("wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _validate_manifest(manifest: dict[str, Any]) -> None:
    if not isinstance(manifest, dict) or manifest.get("manifest_version") != 1:
        raise HarnessError("INVALID_MANIFEST")
    artifacts = manifest.get("artifacts", {})
    if not isinstance(artifacts, dict):
        raise HarnessError("INVALID_MANIFEST")
    for artifact in artifacts.values():
        if not isinstance(artifact, dict):
            raise HarnessError("INVALID_MANIFEST")
        safe_path = artifact.get("safe_path")
        if safe_path is not None and (not isinstance(safe_path, str) or Path(safe_path).is_absolute() or ".." in Path(safe_path).parts):
            raise HarnessError("INVALID_MANIFEST")
