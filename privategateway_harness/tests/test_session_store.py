from pathlib import Path

import pytest

from privategateway_harness.config import HarnessConfig
from privategateway_harness.errors import HarnessError
from privategateway_harness.session_store import SessionStore


def test_create_session_writes_a_relative_path_manifest(tmp_path: Path):
    store = SessionStore(HarnessConfig(project_id="demo", sessions_root=tmp_path / "sessions"))

    session = store.create("session-001")

    assert session.manifest["manifest_version"] == 1
    assert session.manifest["session_id"] == "session-001"
    assert (session.root / "safe").is_dir()
    assert (session.root / "output").is_dir()
    assert session.manifest_path.is_file()


def test_manifest_rejects_internal_absolute_artifact_paths(tmp_path: Path):
    store = SessionStore(HarnessConfig(project_id="demo", sessions_root=tmp_path / "sessions"))
    session = store.create("session-001")

    with pytest.raises(HarnessError, match="INVALID_MANIFEST"):
        session.save_manifest({**session.manifest, "artifacts": {"a1b2c3d4": {"safe_path": "C:/secret.xlsx"}}})


def test_opening_an_active_session_twice_is_denied(tmp_path: Path):
    store = SessionStore(HarnessConfig(project_id="demo", sessions_root=tmp_path / "sessions"))
    first = store.create("session-001")

    with pytest.raises(HarnessError, match="SESSION_ALREADY_IN_USE"):
        store.open("session-001")

    first.close()
    reopened = store.open("session-001")
    reopened.close()
