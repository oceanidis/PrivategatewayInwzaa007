from pathlib import Path

import pytest

from privategateway_service.working_copies import WorkingCopyError, WorkingCopyStore


def test_working_copy_is_sanitized_and_integrity_checked(tmp_path: Path) -> None:
    store = WorkingCopyStore(tmp_path)
    copy = store.create(suffix=".txt", content=b"[REDACTED_EMAIL]", source_fingerprint="a" * 64, policy_fingerprint="b" * 64, ttl_seconds=60)
    path = store.resolve(copy["copy_id"])
    assert path.read_bytes() == b"[REDACTED_EMAIL]"
    path.write_bytes(b"tampered")
    with pytest.raises(WorkingCopyError, match="SAFE_COPY_INTEGRITY_FAILED"):
        store.resolve(copy["copy_id"])


def test_revoke_makes_copy_unavailable(tmp_path: Path) -> None:
    store = WorkingCopyStore(tmp_path)
    copy = store.create(suffix=".csv", content=b"safe", source_fingerprint="a" * 64, policy_fingerprint="b" * 64)
    store.revoke(copy["copy_id"])
    with pytest.raises(WorkingCopyError, match="SAFE_COPY_NOT_FOUND"):
        store.resolve(copy["copy_id"])
