from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import uuid4

import pandas as pd

from privategateway import CoreSanitizer
from privategateway_protocol import (
    GatewayError,
    GatewayOperation,
    GatewayRequest,
    OutputClassification,
    SanitizedEnvelope,
)

from .audit import AuditWriteError, append_service_audit
from .config import ServiceConfig
from .path_policy import PathPolicy, ServicePathError

_MAX_TEXT_CHARS = 50_000
_MAX_TABLE_ROWS = 200


class GatewayOperations:
    def __init__(self, config: ServiceConfig, *, core: CoreSanitizer | None = None) -> None:
        self.config = config
        self.path_policy = PathPolicy(config.protected_roots, config.safe_root)
        self.core = core or CoreSanitizer()
        self._handlers = {
            GatewayOperation.BROWSE_DIRECTORY: self._browse_directory,
            GatewayOperation.INSPECT_FILE: self._inspect_file,
            GatewayOperation.READ_SAFE_TABLE: self._read_safe_table,
            GatewayOperation.READ_SAFE_TEXT: self._read_safe_text,
            GatewayOperation.HEALTH: self._health,
        }

    @classmethod
    def from_config(cls, config: ServiceConfig) -> "GatewayOperations":
        return cls(config)

    def execute(self, request: GatewayRequest) -> SanitizedEnvelope | GatewayError:
        handler = self._handlers.get(request.operation)
        if handler is None:
            return self._error(request, "OPERATION_DENIED")
        try:
            response = handler(request)
        except ServicePathError:
            return self._error(request, "PATH_DENIED")
        except (TypeError, ValueError, UnicodeError):
            return self._error(request, "INVALID_ARGUMENT")
        except Exception:
            return self._error(request, "SANITIZATION_FAILED")
        try:
            append_service_audit(
                self.path_policy.safe_root,
                request_id=request.request_id,
                operation=request.operation.value,
                outcome="ok",
            )
        except AuditWriteError:
            return GatewayError(code="AUDIT_WRITE_FAILED", request_id=request.request_id)
        return response

    def _error(self, request: GatewayRequest, code: str) -> GatewayError:
        try:
            append_service_audit(
                self.path_policy.safe_root,
                request_id=request.request_id,
                operation=request.operation.value,
                outcome=code,
            )
        except AuditWriteError:
            code = "AUDIT_WRITE_FAILED"
        return GatewayError(code=code, request_id=request.request_id)

    def _browse_directory(self, request: GatewayRequest) -> SanitizedEnvelope:
        directory = self.path_policy.resolve_directory(self._path_arg(request))
        include_hidden = self._bool_arg(request, "include_hidden", False)
        items = []
        for child in directory.iterdir():
            if not include_hidden and child.name.startswith("."):
                continue
            info = child.stat()
            items.append({"name": child.name, "is_directory": child.is_dir(), "size": info.st_size})
        items.sort(key=lambda item: str(item["name"]).casefold())
        return self._envelope(request, OutputClassification.METADATA, {"items": items})

    def _inspect_file(self, request: GatewayRequest) -> SanitizedEnvelope:
        source = self.path_policy.resolve_input(self._path_arg(request))
        info = source.stat()
        return self._envelope(
            request,
            OutputClassification.METADATA,
            {"name": source.name, "suffix": source.suffix.lower(), "size": info.st_size},
        )

    def _read_safe_text(self, request: GatewayRequest) -> SanitizedEnvelope:
        max_chars = self._bounded_int(request, "max_chars", default=_MAX_TEXT_CHARS, minimum=1, maximum=_MAX_TEXT_CHARS)
        source = self.path_policy.resolve_input(self._path_arg(request))
        if source.suffix.lower() not in {".txt", ".log", ".md"}:
            raise ValueError("unsupported text input")
        raw = source.read_text(encoding="utf-8", errors="strict")[:max_chars]
        result = self.core.sanitize_text(raw, policy_path=self.config.policy_path, project_id=self.config.project_id, job_id=f"read_{uuid4().hex}")
        if not result.can_export:
            raise RuntimeError("sanitization blocked")
        return self._envelope(request, OutputClassification.SANITIZED, {"text": result.safe_dataset})

    def _read_safe_table(self, request: GatewayRequest) -> SanitizedEnvelope:
        offset = self._bounded_int(request, "offset", default=0, minimum=0, maximum=2_000_000)
        limit = self._bounded_int(request, "limit", default=_MAX_TABLE_ROWS, minimum=1, maximum=_MAX_TABLE_ROWS)
        source = self.path_policy.resolve_input(self._path_arg(request))
        frame = self._read_table(source)
        result = self.core.sanitize_table(frame, policy_path=self.config.policy_path, project_id=self.config.project_id, job_id=f"table_{uuid4().hex}")
        if not result.can_export or result.safe_dataset is None:
            raise RuntimeError("sanitization blocked")
        page = result.safe_dataset.iloc[offset : offset + limit]
        return self._envelope(request, OutputClassification.SANITIZED, {"rows": page.to_dict(orient="records"), "offset": offset, "limit": limit})

    def _health(self, request: GatewayRequest) -> SanitizedEnvelope:
        return self._envelope(request, OutputClassification.METADATA, {"status": "ok"})

    def _read_table(self, source: Path) -> pd.DataFrame:
        suffix = source.suffix.lower()
        if suffix == ".csv":
            return pd.read_csv(source)
        if suffix in {".xlsx", ".xls"}:
            return pd.read_excel(source)
        if suffix == ".json":
            return pd.read_json(source)
        raise ValueError("unsupported table input")

    def _envelope(self, request: GatewayRequest, classification: OutputClassification, payload: dict[str, Any]) -> SanitizedEnvelope:
        encoded = repr(payload).encode("utf-8")
        digest = sha256(encoded).hexdigest()
        return SanitizedEnvelope(request.request_id, classification, payload, "service-policy", digest, digest)

    @staticmethod
    def _path_arg(request: GatewayRequest) -> str:
        path = request.arguments.get("path")
        if not isinstance(path, str) or not path.strip():
            raise ValueError("path is required")
        return path

    @staticmethod
    def _bool_arg(request: GatewayRequest, name: str, default: bool) -> bool:
        value = request.arguments.get(name, default)
        if not isinstance(value, bool):
            raise ValueError("invalid boolean")
        return value

    @staticmethod
    def _bounded_int(request: GatewayRequest, name: str, *, default: int, minimum: int, maximum: int) -> int:
        value = request.arguments.get(name, default)
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise ValueError("invalid range")
        return value
