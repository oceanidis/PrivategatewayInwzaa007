from pathlib import Path

from privategateway_harness.artifact_registry import ArtifactRegistry
from privategateway_harness.config import HarnessConfig
from privategateway_harness.runtime import HarnessRuntime
from privategateway_harness.session_store import SessionStore


class _UnusedBackend:
    pass


def test_read_safe_rows_returns_paginated_sanitized_records(tmp_path: Path):
    config = HarnessConfig("demo", tmp_path / "sessions")
    session = SessionStore(config).create("session-001")
    safe = session.root / "safe" / "safe.csv"
    safe.write_text("email,amount\nEMAIL_001,100\nEMAIL_002,200\n", encoding="utf-8")
    reference = ArtifactRegistry(session).register_ready(safe, "policy", "schema", "report")
    session.close()
    runtime = HarnessRuntime(config, _UnusedBackend())
    runtime.resume_session("session-001")

    assert runtime.read_safe_rows(reference.uri, offset=1, limit=1) == {
        "offset": 1,
        "limit": 1,
        "total_rows": 2,
        "rows": [{"email": "EMAIL_002", "amount": 200}],
    }
    runtime.close_session()
