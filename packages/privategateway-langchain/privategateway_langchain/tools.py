from __future__ import annotations

import json
from typing import Any

from langchain_core.tools import StructuredTool


def _safe_payload(value: Any) -> str:
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    if isinstance(value, dict) and value.get("ok") is False:
        return json.dumps({"ok": False, "error_code": value.get("error_code", "PRIVACY_TOOL_FAILED")}, separators=(",", ":"))
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def _call(client: object, method: str, **kwargs: Any) -> str:
    target = getattr(client, method, None)
    if not callable(target):
        return json.dumps({"ok": False, "error_code": "GATEWAY_CAPABILITY_UNAVAILABLE"}, separators=(",", ":"))
    try:
        return _safe_payload(target(**kwargs))
    except Exception:
        return json.dumps({"ok": False, "error_code": "PRIVACY_TOOL_FAILED"}, separators=(",", ":"))


def privategateway_tools(client: object) -> list[StructuredTool]:
    def browse_protected_directory(path: str, include_hidden: bool = False) -> str:
        """Browse allowed protected-directory metadata."""
        return _call(client, "browse_directory", path=path, include_hidden=include_hidden)

    def inspect_protected_file(path: str) -> str:
        """Inspect allowed protected-file metadata without reading its content."""
        return _call(client, "inspect_file", path=path)

    def read_safe_table(path: str, offset: int = 0, limit: int = 200) -> str:
        """Read a sanitized table page through PrivateGateway."""
        if offset < 0 or not 1 <= limit <= 1000:
            return json.dumps({"ok": False, "error_code": "INVALID_PAGINATION"}, separators=(",", ":"))
        return _call(client, "read_safe_table", path=path, offset=offset, limit=limit)

    def read_safe_text(path: str, max_chars: int = 50_000) -> str:
        """Read sanitized text through PrivateGateway."""
        if not 1 <= max_chars <= 200_000:
            return json.dumps({"ok": False, "error_code": "INVALID_TEXT_LIMIT"}, separators=(",", ":"))
        return _call(client, "read_safe_text", path=path, max_chars=max_chars)

    def create_safe_working_copy(path: str, output_format: str | None = None) -> str:
        """Create a sanitized ephemeral working copy through PrivateGateway."""
        return _call(client, "create_safe_working_copy", path=path, output_format=output_format)

    def safe_export(copy_id: str, destination: str) -> str:
        """Export a previously approved sanitized working copy."""
        return _call(client, "safe_export", copy_id=copy_id, destination=destination)

    functions = (browse_protected_directory, inspect_protected_file, read_safe_table, read_safe_text, create_safe_working_copy, safe_export)
    return [StructuredTool.from_function(function) for function in functions]
