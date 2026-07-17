from __future__ import annotations

import json
from pathlib import Path, PurePath
from typing import Any, Protocol


_TABLE_TYPES = {".csv": "csv", ".xlsx": "excel", ".xls": "excel", ".json": "json"}
_TEXT_TYPES = {".txt": "text", ".log": "text", ".md": "text"}


class _Runtime(Protocol):
    def ensure_client(self) -> object: ...


class SafeFileReader:
    """Thin path-to-Gateway-operation facade for the Codex adapter."""

    def __init__(self, runtime: _Runtime, *, max_response_bytes: int = 900_000) -> None:
        self._runtime = runtime
        self._max_response_bytes = max_response_bytes

    def read(self, path: str, *, offset: int = 0, limit: int = 200, max_chars: int = 50_000) -> dict[str, Any]:
        resolved_path = self._resolve_supported_path(path)
        if resolved_path is None:
            return {"ok": False, "error_code": "UNSUPPORTED_SAFE_READ_TYPE"}
        if resolved_path == "ambiguous":
            return {"ok": False, "error_code": "AMBIGUOUS_SAFE_READ_PATH"}
        suffix = PurePath(resolved_path).suffix.lower()
        file_type = _TABLE_TYPES.get(suffix) or _TEXT_TYPES.get(suffix)
        if file_type is None:
            return {"ok": False, "error_code": "UNSUPPORTED_SAFE_READ_TYPE"}

        try:
            client = self._runtime.ensure_client()
            if suffix in _TABLE_TYPES:
                response = client.read_safe_table(resolved_path, offset=offset, limit=limit)
                result = self._table_response(response, file_type)
            else:
                response = client.read_safe_text(resolved_path, max_chars=max_chars)
                result = self._text_response(response, file_type)
        except Exception:
            return {"ok": False, "error_code": "GATEWAY_UNAVAILABLE"}
        return self._bounded(result)

    @staticmethod
    def _resolve_supported_path(path: str) -> str | None:
        candidate = Path(path)
        supported = set(_TABLE_TYPES) | set(_TEXT_TYPES)
        if candidate.suffix.lower() in supported:
            return path
        if candidate.suffix:
            return None
        try:
            matches = [item for item in candidate.parent.iterdir() if item.is_file() and item.stem == candidate.name and item.suffix.lower() in supported]
        except OSError:
            return None
        if len(matches) == 1:
            return str(matches[0])
        return "ambiguous" if matches else None
    @staticmethod
    def _payload(response: object) -> dict[str, Any] | None:
        to_dict = getattr(response, "to_dict", None)
        value = to_dict() if callable(to_dict) else response
        if not isinstance(value, dict) or value.get("ok") is not True:
            return None
        payload = value.get("payload")
        return payload if isinstance(payload, dict) else None

    def _table_response(self, response: object, file_type: str) -> dict[str, Any]:
        payload = self._payload(response)
        if payload is None:
            return {"ok": False, "error_code": self._error_code(response)}
        rows = payload.get("rows")
        if not isinstance(rows, list):
            return {"ok": False, "error_code": "INVALID_GATEWAY_RESPONSE"}
        offset = payload.get("offset")
        limit = payload.get("limit")
        if not isinstance(offset, int) or not isinstance(limit, int):
            return {"ok": False, "error_code": "INVALID_GATEWAY_RESPONSE"}
        return {
            "ok": True,
            "kind": "table",
            "file_type": file_type,
            "sheet_scope": payload.get("sheet_scope", "default_sheet_only"),
            "rows": rows,
            "pagination": {"offset": offset, "limit": limit, "returned": len(rows)},
            "redaction_summary": {"sanitized": True},
        }

    def _text_response(self, response: object, file_type: str) -> dict[str, Any]:
        payload = self._payload(response)
        if payload is None:
            return {"ok": False, "error_code": self._error_code(response)}
        text = payload.get("text")
        if not isinstance(text, str):
            return {"ok": False, "error_code": "INVALID_GATEWAY_RESPONSE"}
        return {
            "ok": True,
            "kind": "text",
            "file_type": file_type,
            "text": text,
            "returned_chars": payload.get("returned_chars", len(text)),
            "truncated": payload.get("truncated", False),
            "redaction_summary": {"sanitized": True},
        }

    @staticmethod
    def _error_code(response: object) -> str:
        to_dict = getattr(response, "to_dict", None)
        value = to_dict() if callable(to_dict) else response
        if isinstance(value, dict) and isinstance(value.get("error_code"), str):
            return value["error_code"]
        return "PRIVACY_TOOL_FAILED"

    def _bounded(self, response: dict[str, Any]) -> dict[str, Any]:
        try:
            size = len(json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        except (TypeError, ValueError):
            return {"ok": False, "error_code": "INVALID_GATEWAY_RESPONSE"}
        if size > self._max_response_bytes:
            return {"ok": False, "error_code": "SAFE_RESPONSE_TOO_LARGE"}
        return response
