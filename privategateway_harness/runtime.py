from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

import pandas as pd

from .artifact_registry import ArtifactRegistry
from .config import HarnessConfig
from .contracts import SafeArtifactRef
from .errors import HarnessError
from .policy_review import PolicyReviewStore, schema_fingerprint
from .session_store import Session, SessionStore


class GatewayBackend(Protocol):
    def sanitize(self, input_path: Path, output_path: Path, **kwargs: object) -> dict[str, object]: ...


class HarnessRuntime:
    def __init__(self, config: HarnessConfig, backend: GatewayBackend) -> None:
        self.config = config
        self.backend = backend
        self.store = SessionStore(config)
        self.session: Session | None = None

    def create_session(self, session_id: str) -> None:
        self.session = self.store.create(session_id)

    def resume_session(self, session_id: str) -> None:
        self.session = self.store.open(session_id)

    def close_session(self) -> None:
        if self.session is not None:
            self.session.close()
            self.session = None

    def approve_policy(self, policy_path: Path, schema: dict[str, dict[str, str]], *, actor: str, reason: str) -> dict[str, str]:
        return PolicyReviewStore(self._session()).approve(policy_path, schema_fingerprint(schema), actor=actor, reason=reason)

    def import_dataset(
        self, input_path: Path, input_type: str, policy_path: Path, schema: dict[str, dict[str, str]]
    ) -> SafeArtifactRef:
        session = self._session()
        policy_hash = hashlib.sha256(policy_path.read_bytes()).hexdigest()
        schema_hash = schema_fingerprint(schema)
        if not PolicyReviewStore(session).is_approved(policy_hash, schema_hash):
            raise HarnessError("POLICY_APPROVAL_REQUIRED")
        suffix = {"csv": ".csv", "excel": ".xlsx", "json": ".json"}.get(input_type, ".json")
        output_path = session.root / "safe" / f"artifact-{uuid4().hex}{suffix}"
        result = self.backend.sanitize(input_path, output_path, input_type=input_type, project_id=self.config.project_id, policy_path=policy_path)
        report_hash = hashlib.sha256(json.dumps(result.get("redaction_report", {}), sort_keys=True).encode("utf-8")).hexdigest()
        return ArtifactRegistry(session).register_ready(output_path, policy_hash, schema_hash, report_hash)

    def describe_table(self, safe_ref: str) -> dict[str, object]:
        path = ArtifactRegistry(self._session()).resolve(SafeArtifactRef.parse(safe_ref))
        if path.suffix.lower() != ".csv":
            raise HarnessError("UNSUPPORTED_SAFE_ARTIFACT")
        frame = pd.read_csv(path)
        numeric: dict[str, dict[str, float]] = {}
        for column in frame.select_dtypes(include="number"):
            values = frame[column]
            numeric[str(column)] = {"min": float(values.min()), "max": float(values.max()), "mean": float(values.mean())}
        return {
            "rows": int(len(frame)), "columns": int(len(frame.columns)),
            "null_counts": {str(column): int(frame[column].isna().sum()) for column in frame.columns},
            "numeric": numeric,
        }

    def _session(self) -> Session:
        if self.session is None:
            raise HarnessError("NO_ACTIVE_SESSION")
        return self.session
