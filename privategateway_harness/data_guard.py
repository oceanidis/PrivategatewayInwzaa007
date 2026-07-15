from __future__ import annotations

import json
from typing import Any

from .contracts import SafeArtifactRef, ToolCall, ToolCategory, ToolSpec
from .errors import HarnessError


def validate_call(call: ToolCall, spec: ToolSpec, current_session_id: str) -> None:
    if call.session_id != current_session_id:
        raise HarnessError("CROSS_SESSION_CALL_DENIED")
    if spec.category not in {ToolCategory.SAFE_READ, ToolCategory.SAFE_TRANSFORM}:
        return
    _reject_raw_paths(call.arguments)
    if "safe_artifact" in spec.accepted_inputs:
        value = call.arguments.get("artifact")
        if isinstance(value, str) and value.lstrip().startswith("{"):
            try:
                json.loads(value)
            except json.JSONDecodeError:
                pass
            else:
                raise HarnessError("INVALID_SAFE_ARTIFACT_REF")
        SafeArtifactRef.parse(value)


def _reject_raw_paths(value: Any) -> None:
    if isinstance(value, dict):
        for nested in value.values():
            _reject_raw_paths(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            _reject_raw_paths(nested)
    elif isinstance(value, str) and (value.startswith("\\\\") or value.startswith("/") or (len(value) > 2 and value[1:3] in {":\\", ":/"})):
        raise HarnessError("RAW_DATA_REQUIRES_IMPORT")
