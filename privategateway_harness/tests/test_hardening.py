from pathlib import Path

import pytest

from privategateway_harness.config import HarnessConfig
from privategateway_harness.contracts import ToolCall, ToolResult
from privategateway_harness.dispatcher import ToolDispatcher
from privategateway_harness.errors import HarnessError
from privategateway_harness.path_policy import PathPolicy
from privategateway_harness.runtime import HarnessRuntime


def test_path_policy_rejects_raw_input_outside_allowlist(tmp_path: Path):
    policy = PathPolicy((tmp_path / "raw",))
    (tmp_path / "raw").mkdir()

    with pytest.raises(HarnessError, match="RAW_PATH_DENIED"):
        policy.validate_raw_input(tmp_path / "outside.csv")


def test_dispatcher_rejects_duplicate_call_ids():
    dispatcher = ToolDispatcher(lambda call: ToolResult(call.call_id, True))
    call = ToolCall("call-001", "safe_tool", {}, "session-001", "agent")

    assert dispatcher.dispatch(call).ok
    assert dispatcher.dispatch(call).error_code == "DUPLICATE_TOOL_CALL"


class _Backend:
    def sanitize(self, _input: Path, output: Path, **_: object) -> dict[str, object]:
        output.write_text("amount\n100\n", encoding="utf-8")
        return {"redaction_report": {}}


def test_resume_rejects_modified_safe_artifact(tmp_path: Path):
    config = HarnessConfig("demo", tmp_path / "sessions")
    runtime = HarnessRuntime(config, _Backend())
    runtime.create_session("session-001")
    policy = tmp_path / "policy.yaml"
    policy.write_text("columns: {}\n", encoding="utf-8")
    schema = {"Sheet1": {"amount": "int64"}}
    runtime.approve_policy(policy, schema, actor="reviewer", reason="test")
    reference = runtime.import_dataset(tmp_path / "raw.csv", "csv", policy, schema)
    assert runtime.session is not None
    safe_path = runtime.session.root / runtime.session.manifest['artifacts'][reference.artifact_id]['safe_path']
    runtime.close_session()
    safe_path.write_text("amount\n999\n", encoding="utf-8")

    with pytest.raises(HarnessError, match="ARTIFACT_INTEGRITY_FAILED"):
        runtime.resume_session("session-001")
