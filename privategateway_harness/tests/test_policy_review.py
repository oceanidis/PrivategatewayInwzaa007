from pathlib import Path

from privategateway_harness.config import HarnessConfig
from privategateway_harness.policy_review import PolicyReviewStore, schema_fingerprint
from privategateway_harness.session_store import SessionStore


def test_approval_binds_policy_and_schema_without_raw_source_path(tmp_path: Path):
    session = SessionStore(HarnessConfig("demo", tmp_path / "sessions")).create("session-001")
    policy = tmp_path / "policy.yaml"
    policy.write_text("columns:\n  email: tokenize\n", encoding="utf-8")
    schema = schema_fingerprint({"Sheet1": {"email": "object"}})

    approval = PolicyReviewStore(session).approve(policy, schema, actor="reviewer", reason="approved")

    assert approval["policy_fingerprint"] in session.manifest["approvals"]
    assert "source_path" not in approval
    assert PolicyReviewStore(session).is_approved(approval["policy_fingerprint"], schema)
    session.close()
