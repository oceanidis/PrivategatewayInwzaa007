from __future__ import annotations

from .contracts import Authorization, Capability, Decision, ExecutionRequest
from .registry import CapabilityRegistry


class CapabilityBroker:
    def __init__(self, *, registry: CapabilityRegistry, client: object | None) -> None:
        self.registry = registry
        self.client = client

    def decide(self, request: ExecutionRequest) -> Authorization:
        spec = self.registry.get(request.tool_name)
        if spec is None:
            return self._deny(request, "CAPABILITY_DENIED")
        if not request.request_id or not isinstance(request.arguments, dict):
            return self._deny(request, "INVALID_REQUEST")
        if any(not isinstance(request.arguments.get(field), str) or not request.arguments[field] for field in spec.resource_fields):
            return self._deny(request, "MISSING_RESOURCE")
        if spec.capability is Capability.SANDBOXED_EXECUTION:
            return Authorization(Decision.ALLOW, request.request_id, request.tool_name, spec.capability) if spec.sandboxed else self._deny(request, "UNSANDBOXED_EXECUTION")
        if self.client is None:
            return self._deny(request, "GATEWAY_UNAVAILABLE")
        return Authorization(Decision.ROUTE_TO_GATEWAY, request.request_id, request.tool_name, spec.capability)

    def route(self, request: ExecutionRequest, authorization: Authorization):
        if authorization.decision is not Decision.ROUTE_TO_GATEWAY or authorization.request_id != request.request_id or authorization.tool_name != request.tool_name or authorization.capability is None:
            raise ValueError("INVALID_AUTHORIZATION")
        methods = {
            Capability.DIRECTORY_BROWSE: "browse_directory",
            Capability.METADATA_INSPECT: "inspect_file",
            Capability.SAFE_TABLE_READ: "read_safe_table",
            Capability.SAFE_TEXT_READ: "read_safe_text",
            Capability.SAFE_COPY_CREATE: "create_safe_working_copy",
            Capability.SAFE_EXPORT: "safe_export",
        }
        method_name = methods.get(authorization.capability)
        if method_name is None or self.client is None:
            raise ValueError("GATEWAY_UNAVAILABLE")
        method = getattr(self.client, method_name, None)
        if not callable(method):
            raise ValueError("GATEWAY_UNAVAILABLE")
        return method(**dict(request.arguments))

    @staticmethod
    def _deny(request: ExecutionRequest, reason: str) -> Authorization:
        return Authorization(Decision.DENY, request.request_id, request.tool_name, reason_code=reason)
