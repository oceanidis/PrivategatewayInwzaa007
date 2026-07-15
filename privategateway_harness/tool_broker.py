from __future__ import annotations

from collections.abc import Iterable

from .contracts import ToolCall, ToolResult, ToolSpec
from .data_guard import validate_call
from .errors import HarnessError


class ToolBroker:
    def __init__(self, session_id: str, specs: Iterable[ToolSpec]) -> None:
        self.session_id = session_id
        self.specs = {spec.name: spec for spec in specs}

    def dispatch(self, call: ToolCall) -> ToolResult:
        try:
            spec = self.specs[call.tool_name]
        except KeyError:
            return ToolResult.failure(call, HarnessError("UNKNOWN_TOOL"))
        try:
            validate_call(call, spec, self.session_id)
            return spec.handler(call)
        except HarnessError as error:
            return ToolResult.failure(call, error)
        except Exception:
            return ToolResult.failure(call, HarnessError("TOOL_EXECUTION_FAILED"))
