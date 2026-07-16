from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

import pytest

from privategateway.key_provider import init_project
from privategateway_client import GatewayClientError, LocalGatewayClient
from privategateway_service import GatewayOperations, LocalGatewayServer, ServiceConfig


@pytest.fixture
def running_gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    raw = tmp_path / "raw"
    raw.mkdir()
    policy = tmp_path / "policy.yaml"
    policy.write_text("security:\n  store_raw_copy: false\n  require_presidio: false\ncolumns:\n  email: tokenize\ndefault:\n  unknown_column: keep\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    init_project("ipc_test")
    operations = GatewayOperations.from_config(ServiceConfig((raw,), tmp_path / "safe", policy, "ipc_test"))
    address = rf"\\.\pipe\privategateway-{uuid4().hex}" if os.name == "nt" else str(tmp_path / "gateway.sock")
    family = "AF_PIPE" if os.name == "nt" else "AF_UNIX"
    server = LocalGatewayServer(operations, address=address, authkey=b"test-auth-key", family=family)
    server.start()
    try:
        yield LocalGatewayClient(address, b"test-auth-key", family=family), raw
    finally:
        server.close()


def test_client_receives_only_sanitized_envelope(running_gateway) -> None:
    client, raw = running_gateway
    source = raw / "note.txt"
    source.write_text("alice@example.com", encoding="utf-8")

    result = client.read_safe_text(str(source), max_chars=1000)

    assert result.classification.value == "sanitized"
    assert "alice@example.com" not in str(result.to_dict())


def test_invalid_authentication_is_rejected(running_gateway) -> None:
    client, _ = running_gateway

    with pytest.raises(GatewayClientError, match="^GATEWAY_AUTHENTICATION_FAILED$"):
        client.with_authkey(b"wrong-key").health()
