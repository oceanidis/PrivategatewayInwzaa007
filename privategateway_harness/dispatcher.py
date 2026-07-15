from __future__ import annotations

from collections.abc import Callable

from .contracts import ToolCall, ToolResult
from .errors import HarnessError


class ToolDispatcher:
    def __init__(self, dispatch: Callable[[ToolCall], ToolResult]) -> None:
        self._dispatch = dispatch
        self._call_ids: set[str] = set()

    def dispatch(self, call: ToolCall) -> ToolResult:
        if call.call_id in self._call_ids:
            return ToolResult.failure(call, HarnessError('DUPLICATE_TOOL_CALL'))
        self._call_ids.add(call.call_id)
        return self._dispatch(call)
