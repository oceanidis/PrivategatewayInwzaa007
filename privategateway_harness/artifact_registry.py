from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from .contracts import SafeArtifactRef
from .errors import HarnessError
from .session_store import Session


class ArtifactRegistry:
    def __init__(self, session: Session) -> None:
        self.session = session

    def register_ready(
        self,
        artifact_path: Path,
        policy_fingerprint: str,
        schema_fingerprint: str,
        report_fingerprint: str,
    ) -> SafeArtifactRef:
        resolved = artifact_path.resolve()
        safe_root = (self.session.root / "safe").resolve()
        if safe_root not in resolved.parents or not resolved.is_file():
            raise HarnessError("INVALID_SAFE_ARTIFACT_PATH")
        artifact_id = uuid4().hex[:16]
        record = {
            "kind": "table",
            "safe_path": resolved.relative_to(self.session.root).as_posix(),
            "sha256": _sha256(resolved),
            "policy_fingerprint": policy_fingerprint,
            "schema_fingerprint": schema_fingerprint,
            "report_fingerprint": report_fingerprint,
            "status": "READY",
            "created_at": datetime.now(UTC).isoformat(),
        }
        manifest = {**self.session.manifest, "artifacts": {**self.session.manifest["artifacts"], artifact_id: record}}
        self.session.save_manifest(manifest)
        return SafeArtifactRef(self.session.manifest["session_id"], artifact_id)

    def inspect(self, reference: SafeArtifactRef) -> dict[str, str]:
        record = self._record(reference)
        return {"ref": reference.uri, "status": record["status"], "kind": record["kind"]}

    def resolve(self, reference: SafeArtifactRef) -> Path:
        record = self._record(reference)
        if record["status"] != "READY":
            raise HarnessError("ARTIFACT_NOT_READY")
        path = (self.session.root / record["safe_path"]).resolve()
        safe_root = (self.session.root / "safe").resolve()
        if safe_root not in path.parents or not path.is_file() or _sha256(path) != record["sha256"]:
            raise HarnessError("ARTIFACT_INTEGRITY_FAILED")
        return path

    def revoke(self, reference: SafeArtifactRef) -> None:
        record = {**self._record(reference), "status": "REVOKED"}
        artifacts = {**self.session.manifest["artifacts"], reference.artifact_id: record}
        self.session.save_manifest({**self.session.manifest, "artifacts": artifacts})

    def _record(self, reference: SafeArtifactRef) -> dict[str, str]:
        if reference.session_id != self.session.manifest["session_id"]:
            raise HarnessError("CROSS_SESSION_ARTIFACT_DENIED")
        try:
            return self.session.manifest["artifacts"][reference.artifact_id]
        except KeyError as exc:
            raise HarnessError("ARTIFACT_NOT_FOUND") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
