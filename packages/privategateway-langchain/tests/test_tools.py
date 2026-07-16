import json

from privategateway_langchain import privategateway_tools


class FakeGatewayClient:
    def browse_directory(self, **kwargs):
        return {"ok": True, "items": []}

    def inspect_file(self, **kwargs):
        return {"ok": True, "name": "note.txt"}

    def read_safe_table(self, **kwargs):
        return {"ok": True, "rows": [{"email": "[REDACTED_EMAIL]"}]}

    def read_safe_text(self, **kwargs):
        return {"ok": True, "text": "[REDACTED_SECRET]"}


def test_safe_tool_names_are_stable() -> None:
    names = {tool.name for tool in privategateway_tools(FakeGatewayClient())}
    assert names == {"browse_protected_directory", "inspect_protected_file", "read_safe_table", "read_safe_text", "create_safe_working_copy", "safe_export"}


def test_read_safe_text_returns_gateway_payload_not_raw() -> None:
    tool = next(tool for tool in privategateway_tools(FakeGatewayClient()) if tool.name == "read_safe_text")
    result = tool.invoke({"path": "C:/protected/note.txt", "max_chars": 1000})
    assert "raw-secret-sentinel" not in result
    assert "[REDACTED_SECRET]" in result


def test_bounds_are_rejected_before_gateway_call() -> None:
    tool = next(tool for tool in privategateway_tools(FakeGatewayClient()) if tool.name == "read_safe_table")
    assert json.loads(tool.invoke({"path": "C:/protected/table.csv", "limit": 1001}))["error_code"] == "INVALID_PAGINATION"
