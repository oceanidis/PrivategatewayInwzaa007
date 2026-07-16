from __future__ import annotations

import json
from typing import Any

from privategateway_protocol import GatewayError, GatewayOperation, GatewayRequest, OutputClassification, SanitizedEnvelope

MAX_MESSAGE_BYTES = 1_048_576


def encode_request(request: GatewayRequest) -> bytes:
    payload = {"request_id": request.request_id, "operation": request.operation.value, "arguments": dict(request.arguments)}
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_MESSAGE_BYTES:
        raise ValueError("REQUEST_TOO_LARGE")
    return encoded


def decode_request(payload: bytes) -> GatewayRequest:
    if len(payload) > MAX_MESSAGE_BYTES:
        raise ValueError("REQUEST_TOO_LARGE")
    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict) or set(value) != {"request_id", "operation", "arguments"} or not isinstance(value["arguments"], dict):
        raise ValueError("INVALID_REQUEST")
    return GatewayRequest(str(value["request_id"]), GatewayOperation(str(value["operation"])), value["arguments"])


def encode_response(response: SanitizedEnvelope | GatewayError) -> bytes:
    encoded = json.dumps(response.to_dict(), ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_MESSAGE_BYTES:
        raise ValueError("RESPONSE_TOO_LARGE")
    return encoded


def decode_response(payload: bytes) -> SanitizedEnvelope | GatewayError:
    if len(payload) > MAX_MESSAGE_BYTES:
        raise ValueError("RESPONSE_TOO_LARGE")
    value: dict[str, Any] = json.loads(payload.decode("utf-8"))
    if value.get("ok") is False and set(value) == {"ok", "request_id", "error_code"}:
        return GatewayError(code=str(value["error_code"]), request_id=str(value["request_id"]))
    required = {"ok", "request_id", "classification", "payload", "policy_fingerprint", "source_fingerprint", "content_hash"}
    if value.get("ok") is True and set(value) == required:
        return SanitizedEnvelope(str(value["request_id"]), OutputClassification(str(value["classification"])), value["payload"], str(value["policy_fingerprint"]), str(value["source_fingerprint"]), str(value["content_hash"]))
    raise ValueError("INVALID_RESPONSE")
