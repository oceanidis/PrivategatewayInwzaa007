from types import SimpleNamespace

from privategateway_capabilities import Capability, CapabilityBroker, CapabilityRegistry
from privategateway_langchain import PrivateGatewayMiddleware


class FakeClient:
    def read_safe_text(self, **kwargs):
        return {"ok": True, "text": "[REDACTED_EMAIL]"}


def _middleware() -> PrivateGatewayMiddleware:
    registry = CapabilityRegistry.strict()
    registry.register_gateway_tool("read_safe_text", Capability.SAFE_TEXT_READ, resource_fields=("path",))
    return PrivateGatewayMiddleware.enforcing(CapabilityBroker(registry=registry, client=FakeClient()))


def test_route_decision_does_not_call_original_handler() -> None:
    calls = []
    request = SimpleNamespace(tool_call={"id": "call-1", "name": "read_safe_text", "args": {"path": "C:/protected/a.txt"}}, runtime=None)
    result = _middleware().wrap_tool_call(request, lambda _: calls.append(True))
    assert calls == []
    assert "[REDACTED_EMAIL]" in result.content


def test_unknown_tool_is_denied_before_handler() -> None:
    calls = []
    request = SimpleNamespace(tool_call={"id": "call-2", "name": "unregistered_reader", "args": {"path": "C:/protected/a.txt"}}, runtime=None)
    result = _middleware().wrap_tool_call(request, lambda _: calls.append(True))
    assert calls == []
    assert result.content == '{"ok":false,"error_code":"CAPABILITY_DENIED"}'
