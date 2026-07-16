from __future__ import annotations

from pathlib import Path

import pytest

from privategateway.key_provider import init_project
from privategateway_protocol import GatewayOperation, GatewayRequest, OutputClassification
from privategateway_service import GatewayOperations, ServiceConfig
from privategateway_service.audit import AuditWriteError


def _operations(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[GatewayOperations, Path]:
    raw = tmp_path / "raw"
    raw.mkdir()
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
security:
  store_raw_copy: false
  require_presidio: false
columns:
  email: tokenize
default:
  unknown_column: keep
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    init_project("service_test")
    return GatewayOperations.from_config(ServiceConfig((raw,), tmp_path / "safe", policy, "service_test")), raw


def test_safe_text_read_never_returns_raw_email(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    operations, raw = _operations(tmp_path, monkeypatch)
    source = raw / "note.txt"
    source.write_text("Contact alice@example.com", encoding="utf-8")

    response = operations.execute(GatewayRequest("req-text", GatewayOperation.READ_SAFE_TEXT, {"path": str(source)}))
    payload = response.to_dict()

    assert payload["classification"] == OutputClassification.SANITIZED.value
    assert "alice@example.com" not in str(payload)


def test_metadata_operations_do_not_read_content(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    operations, raw = _operations(tmp_path, monkeypatch)
    source = raw / "secret.txt"
    source.write_text("alice@example.com", encoding="utf-8")

    inspect = operations.execute(GatewayRequest("req-inspect", GatewayOperation.INSPECT_FILE, {"path": str(source)})).to_dict()
    browse = operations.execute(GatewayRequest("req-browse", GatewayOperation.BROWSE_DIRECTORY, {"path": str(raw)})).to_dict()

    assert "alice@example.com" not in str(inspect)
    assert "alice@example.com" not in str(browse)
    assert inspect["payload"]["name"] == "secret.txt"


def test_invalid_arguments_and_unknown_operation_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    operations, raw = _operations(tmp_path, monkeypatch)
    source = raw / "note.txt"
    source.write_text("x", encoding="utf-8")

    invalid = operations.execute(GatewayRequest("req-invalid", GatewayOperation.READ_SAFE_TEXT, {"path": str(source), "max_chars": 50_001})).to_dict()
    unknown = operations.execute(GatewayRequest("req-unknown", GatewayOperation.CREATE_SAFE_WORKING_COPY, {})).to_dict()

    assert invalid == {"ok": False, "request_id": "req-invalid", "error_code": "INVALID_ARGUMENT"}
    assert unknown == {"ok": False, "request_id": "req-unknown", "error_code": "INVALID_ARGUMENT"}


def test_safe_table_read_is_paginated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    operations, raw = _operations(tmp_path, monkeypatch)
    source = raw / "customers.csv"
    source.write_text("email\nalice@example.com\n", encoding="utf-8")

    response = operations.execute(GatewayRequest("req-table", GatewayOperation.READ_SAFE_TABLE, {"path": str(source), "offset": 0, "limit": 1})).to_dict()

    assert response["classification"] == OutputClassification.SANITIZED.value
    assert "alice@example.com" not in str(response)

class _FailingCore:
    def sanitize_text(self, *args, **kwargs):
        raise RuntimeError("alice@example.com must never escape")


def test_core_failure_returns_safe_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    operations, raw = _operations(tmp_path, monkeypatch)
    operations.core = _FailingCore()
    source = raw / "note.txt"
    source.write_text("x", encoding="utf-8")

    response = operations.execute(GatewayRequest("req-core", GatewayOperation.READ_SAFE_TEXT, {"path": str(source)})).to_dict()

    assert response == {"ok": False, "request_id": "req-core", "error_code": "SANITIZATION_FAILED"}
    assert "alice@example.com" not in str(response)


def test_audit_failure_returns_safe_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    operations, raw = _operations(tmp_path, monkeypatch)
    source = raw / "note.txt"
    source.write_text("x", encoding="utf-8")
    monkeypatch.setattr("privategateway_service.operations.append_service_audit", lambda *args, **kwargs: (_ for _ in ()).throw(AuditWriteError("raw failure")))

    response = operations.execute(GatewayRequest("req-audit", GatewayOperation.INSPECT_FILE, {"path": str(source)})).to_dict()

    assert response == {"ok": False, "request_id": "req-audit", "error_code": "AUDIT_WRITE_FAILED"}
