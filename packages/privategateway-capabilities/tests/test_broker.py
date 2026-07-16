from privategateway_capabilities import Capability, CapabilityBroker, CapabilityRegistry, Decision, ExecutionRequest


class FakeClient:
    def read_safe_text(self, **kwargs):
        return {"safe": kwargs["path"]}


def test_model_cannot_spoof_capability() -> None:
    registry = CapabilityRegistry.strict()
    registry.register_gateway_tool("read_safe_text", Capability.SAFE_TEXT_READ, resource_fields=("path",))
    broker = CapabilityBroker(registry=registry, client=FakeClient())
    request = ExecutionRequest("call_1", "ordinary_tool", {"capability": "safe_text_read", "path": "C:/raw/a.txt"})
    assert broker.decide(request).decision is Decision.DENY


def test_registered_safe_read_routes_only_after_authorization() -> None:
    registry = CapabilityRegistry.strict()
    registry.register_gateway_tool("read_safe_text", Capability.SAFE_TEXT_READ, resource_fields=("path",))
    broker = CapabilityBroker(registry=registry, client=FakeClient())
    request = ExecutionRequest("call_2", "read_safe_text", {"path": "C:/raw/a.txt"})
    authorization = broker.decide(request)
    assert authorization.decision is Decision.ROUTE_TO_GATEWAY
    assert broker.route(request, authorization) == {"safe": "C:/raw/a.txt"}


def test_unsandboxed_execution_is_denied() -> None:
    registry = CapabilityRegistry.strict()
    registry.register_execution_tool("python", sandboxed=False)
    assert CapabilityBroker(registry=registry, client=None).decide(ExecutionRequest("call_3", "python", {})).reason_code == "UNSANDBOXED_EXECUTION"


def test_authorization_cannot_be_replayed_for_another_tool() -> None:
    registry = CapabilityRegistry.strict()
    registry.register_gateway_tool("read_safe_text", Capability.SAFE_TEXT_READ, resource_fields=("path",))
    broker = CapabilityBroker(registry=registry, client=FakeClient())
    request = ExecutionRequest("call_4", "read_safe_text", {"path": "C:/raw/a.txt"})
    authorization = broker.decide(request)
    try:
        broker.route(ExecutionRequest("call_4", "other", {"path": "C:/raw/a.txt"}), authorization)
    except ValueError as error:
        assert str(error) == "INVALID_AUTHORIZATION"
    else:
        raise AssertionError("authorization replay was accepted")
