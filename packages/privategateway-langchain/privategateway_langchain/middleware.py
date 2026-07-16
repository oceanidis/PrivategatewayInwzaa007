from __future__ import annotations

import json
import warnings
from typing import Any, Callable

from langchain.agents.middleware import AgentMiddleware
from langchain.messages import ToolMessage

from privategateway_capabilities import CapabilityBroker, Decision

from .conversion import execution_request_from_tool_call


class PrivateGatewayMiddleware(AgentMiddleware):
    def __init__(self, broker: CapabilityBroker, *, mode: str = "strict") -> None:
        if mode not in {"strict", "audit_only"}:
            raise ValueError("INVALID_PRIVACY_MODE")
        self.broker = broker
        self.mode = mode
        if mode == "audit_only":
            warnings.warn("audit_only mode provides no enforcement guarantee", RuntimeWarning, stacklevel=2)

    @classmethod
    def enforcing(cls, broker: CapabilityBroker) -> "PrivateGatewayMiddleware":
        return cls(broker, mode="strict")

    def wrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
        try:
            execution = execution_request_from_tool_call(request)
            authorization = self.broker.decide(execution)
        except Exception:
            return self._error("unknown", "PRIVACY_TOOL_FAILED")
        if self.mode == "audit_only" or authorization.decision is Decision.ALLOW:
            return handler(request)
        if authorization.decision is Decision.DENY:
            return self._error(execution.request_id, authorization.reason_code or "CAPABILITY_DENIED")
        try:
            response = self.broker.route(execution, authorization)
            payload = response.to_dict() if hasattr(response, "to_dict") else response
            return ToolMessage(content=json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str), tool_call_id=execution.request_id, name=execution.tool_name)
        except Exception:
            return self._error(execution.request_id, "PRIVACY_TOOL_FAILED")

    @staticmethod
    def _error(call_id: str, code: str) -> ToolMessage:
        return ToolMessage(content=json.dumps({"ok": False, "error_code": code}, separators=(",", ":")), tool_call_id=call_id or "privacy-error", status="error")
