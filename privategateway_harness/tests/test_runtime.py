from pathlib import Path

from privategateway_harness.config import HarnessConfig
from privategateway_harness.runtime import HarnessRuntime


class FakeGatewayBackend:
    def sanitize(self, input_path: Path, output_path: Path, **_: object) -> dict[str, object]:
        output_path.write_text("email,amount\nEMAIL_001,100\nEMAIL_002,200\n", encoding="utf-8")
        return {"redaction_report": {"action_counts": {"tokenize": 2}}}


def test_approved_import_produces_safe_ref_that_can_be_described(tmp_path: Path):
    runtime = HarnessRuntime(HarnessConfig("demo", tmp_path / "sessions"), FakeGatewayBackend())
    runtime.create_session("session-001")
    policy = tmp_path / "policy.yaml"
    policy.write_text("columns:\n  email: tokenize\n", encoding="utf-8")
    schema = {"Sheet1": {"email": "object", "amount": "int64"}}
    runtime.approve_policy(policy, schema, actor="reviewer", reason="test")

    reference = runtime.import_dataset(tmp_path / "raw.csv", "csv", policy, schema)
    summary = runtime.describe_table(reference.uri)

    assert reference.uri.startswith("safe://session-001/")
    assert summary == {"rows": 2, "columns": 2, "null_counts": {"email": 0, "amount": 0}, "numeric": {"amount": {"min": 100.0, "max": 200.0, "mean": 150.0}}}
