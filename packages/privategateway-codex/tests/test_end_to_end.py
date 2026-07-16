from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from privategateway.key_provider import init_project
from privategateway_client import LocalGatewayClient
from privategateway_codex.runtime import GatewayRuntime
from privategateway_codex.safe_read import SafeFileReader
from privategateway_service import GatewayOperations, ServiceConfig
from privategateway_service.server import LocalGatewayServer


class _RunningServer:
    def __init__(self, server: LocalGatewayServer) -> None:
        self._server = server
        self.terminated = False

    def poll(self):
        return None

    def terminate(self) -> None:
        self.terminated = True
        self._server.close()

    def wait(self, timeout: float) -> None:
        return None


def test_safe_read_auto_starts_gateway_and_never_returns_raw_sentinel(tmp_path: Path, monkeypatch) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    source = raw / "customers.csv"
    sentinel = "RAW_SENTINEL_DO_NOT_LEAK_7F2A@example.com"
    source.write_text(f"email,api_key\n{sentinel},sk-super-secret-value\n", encoding="utf-8")
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "\n".join(
            [
                "security:",
                "  store_raw_copy: false",
                "  require_presidio: false",
                "columns:",
                "  email: tokenize",
                "  api_key: drop",
                "default:",
                "  unknown_column: keep",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    project_id = f"codex_e2e_{uuid4().hex}"
    init_project(project_id)
    address = rf"\\.\pipe\privategateway-e2e-{uuid4().hex}"
    authkey = b"e2e-auth-key-material-32-bytes-ok"
    config = ServiceConfig((raw,), tmp_path / "safe", policy, project_id)
    client = LocalGatewayClient(address, authkey, family="AF_PIPE")
    started: list[_RunningServer] = []

    def start(_: Path) -> _RunningServer:
        server = LocalGatewayServer(GatewayOperations.from_config(config), address=address, authkey=authkey, family="AF_PIPE")
        server.start()
        process = _RunningServer(server)
        started.append(process)
        return process

    runtime = GatewayRuntime(
        tmp_path / "existing-service.toml",
        client_factory=lambda _: client,
        starter=start,
        startup_timeout_seconds=3,
        poll_interval_seconds=0.01,
    )

    response = SafeFileReader(runtime).read(str(source), limit=1)

    assert response["ok"] is True
    assert sentinel not in str(response)
    assert "sk-super-secret-value" not in str(response)
    assert "EMAIL_" in str(response)
    assert started and runtime.owns_service is True
    runtime.close()
    assert started[0].terminated is True
