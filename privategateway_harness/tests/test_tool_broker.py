from privategateway_harness.contracts import ToolCall, ToolCategory, ToolResult, ToolSpec
from privategateway_harness.errors import HarnessError
from privategateway_harness.tool_broker import ToolBroker


def test_safe_read_blocks_raw_path_before_handler_runs():
    called = []
    broker = ToolBroker("session-001", [ToolSpec("describe_table", ToolCategory.SAFE_READ, lambda call: called.append(call) or ToolResult(call.call_id, True), frozenset({"safe_artifact"}))])
    call = ToolCall("call-001", "describe_table", {"artifact": "C:\\raw\\file.xlsx"}, "session-001", "agent")

    result = broker.dispatch(call)

    assert result.error_code == "RAW_DATA_REQUIRES_IMPORT"
    assert called == []


def test_safe_read_rejects_stringified_capability_container():
    broker = ToolBroker("session-001", [ToolSpec("describe_table", ToolCategory.SAFE_READ, lambda call: ToolResult(call.call_id, True), frozenset({"safe_artifact"}))])
    call = ToolCall("call-001", "describe_table", {"artifact": '{"ref":"safe://session-001/a07d1298"}'}, "session-001", "agent")

    assert broker.dispatch(call).error_code == "INVALID_SAFE_ARTIFACT_REF"
