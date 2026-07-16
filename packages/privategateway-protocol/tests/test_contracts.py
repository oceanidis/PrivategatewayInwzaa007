from dataclasses import FrozenInstanceError

import pytest

from privategateway_protocol import (
    GatewayError,
    GatewayOperation,
    GatewayRequest,
    OutputClassification,
    SanitizedEnvelope,
)


def test_gateway_operation_values_are_stable():
    assert {member.name: member.value for member in GatewayOperation} == {
        "BROWSE_DIRECTORY": "browse_directory",
        "INSPECT_FILE": "inspect_file",
        "READ_SAFE_TABLE": "read_safe_table",
        "READ_SAFE_TEXT": "read_safe_text",
        "CREATE_SAFE_WORKING_COPY": "create_safe_working_copy",
        "SAFE_EXPORT": "safe_export",
        "HEALTH": "health",
    }


def test_output_classification_values_are_stable():
    assert {member.name: member.value for member in OutputClassification} == {
        "METADATA": "metadata",
        "SANITIZED": "sanitized",
        "SAFE_WORKING_COPY": "safe_working_copy",
        "SAFE_EXPORT": "safe_export",
    }


def test_gateway_request_rejects_blank_request_id():
    with pytest.raises(ValueError, match="^INVALID_REQUEST_ID$"):
        GatewayRequest(request_id=" ", operation=GatewayOperation.HEALTH)


def test_gateway_request_is_frozen():
    request = GatewayRequest(
        request_id="req-1",
        operation=GatewayOperation.HEALTH,
        arguments={"limit": 10},
    )
    assert request.arguments == {"limit": 10}
    with pytest.raises(FrozenInstanceError):
        request.request_id = "req-2"


def test_sanitized_envelope_serializes_only_safe_allowlist():
    envelope = SanitizedEnvelope(
        request_id="req-1",
        classification=OutputClassification.SANITIZED,
        payload={"rows": [{"name": "token-1"}]},
        policy_fingerprint="policy-hash",
        source_fingerprint="source-hash",
        content_hash="content-hash",
    )

    assert envelope.to_dict() == {
        "ok": True,
        "request_id": "req-1",
        "classification": "sanitized",
        "payload": {"rows": [{"name": "token-1"}]},
        "policy_fingerprint": "policy-hash",
        "source_fingerprint": "source-hash",
        "content_hash": "content-hash",
    }
    assert "mapping" not in envelope.to_dict()


def test_gateway_error_serializes_without_exception_detail():
    error = GatewayError(code="ACCESS_DENIED", request_id="req-1")

    assert error.to_dict() == {
        "ok": False,
        "request_id": "req-1",
        "error_code": "ACCESS_DENIED",
    }
    assert "detail" not in error.to_dict()

