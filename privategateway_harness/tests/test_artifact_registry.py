from pathlib import Path

import pytest

from privategateway_harness.artifact_registry import ArtifactRegistry
from privategateway_harness.config import HarnessConfig
from privategateway_harness.errors import HarnessError
from privategateway_harness.session_store import SessionStore


def test_ready_artifact_is_projected_without_internal_path(tmp_path: Path):
    session = SessionStore(HarnessConfig("demo", tmp_path / "sessions")).create("session-001")
    artifact = session.root / "safe" / "artifact.csv"
    artifact.write_text("amount\n100\n", encoding="utf-8")
    registry = ArtifactRegistry(session)

    reference = registry.register_ready(artifact, "policy-1", "schema-1", "report-1")

    assert registry.inspect(reference) == {"ref": reference.uri, "status": "READY", "kind": "table"}
    assert str(session.root) not in str(registry.inspect(reference))
    session.close()


def test_cross_session_and_revoked_refs_are_denied(tmp_path: Path):
    store = SessionStore(HarnessConfig("demo", tmp_path / "sessions"))
    first = store.create("session-001")
    second = store.create("session-002")
    artifact = first.root / "safe" / "artifact.csv"
    artifact.write_text("amount\n100\n", encoding="utf-8")
    reference = ArtifactRegistry(first).register_ready(artifact, "policy-1", "schema-1", "report-1")

    with pytest.raises(HarnessError, match="CROSS_SESSION_ARTIFACT_DENIED"):
        ArtifactRegistry(second).resolve(reference)

    first_registry = ArtifactRegistry(first)
    first_registry.revoke(reference)
    with pytest.raises(HarnessError, match="ARTIFACT_NOT_READY"):
        first_registry.resolve(reference)
    first.close()
    second.close()
