from __future__ import annotations

from privategateway_capabilities import ExecutionRequest


def execution_request_from_tool_call(request: object) -> ExecutionRequest:
    tool_call = getattr(request, "tool_call", None)
    if not isinstance(tool_call, dict):
        raise ValueError("INVALID_TOOL_CALL")
    name = tool_call.get("name")
    arguments = tool_call.get("args", tool_call.get("arguments", {}))
    call_id = tool_call.get("id")
    if not isinstance(name, str) or not isinstance(arguments, dict) or not isinstance(call_id, str):
        raise ValueError("INVALID_TOOL_CALL")
    runtime = getattr(request, "runtime", None)
    actor_id = str(getattr(runtime, "user_id", "unknown"))
    trace_id = str(getattr(runtime, "run_id", ""))
    return ExecutionRequest(call_id, name, arguments, actor_id=actor_id, trace_id=trace_id)
