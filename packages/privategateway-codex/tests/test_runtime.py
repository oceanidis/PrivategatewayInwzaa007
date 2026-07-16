from __future__ import annotations

from pathlib import Path

from privategateway_codex.runtime import GatewayRuntime


class _Response:
    def __init__(self, ok: bool) -> None:
        self._ok = ok

    def to_dict(self) -> dict[str, bool]:
        return {"ok": self._ok}


class _Client:
    def __init__(self, health: list[bool]) -> None:
        self.health_results = iter(health)
        self.health_calls = 0

    def health(self) -> _Response:
        self.health_calls += 1
        return _Response(next(self.health_results))


class _Process:
    def __init__(self) -> None:
        self.terminated = False

    def poll(self):
        return None

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout: float) -> None:
        return None


def test_healthy_existing_gateway_is_reused_without_start(tmp_path: Path) -> None:
    client = _Client([True])
    starts: list[object] = []
    runtime = GatewayRuntime(
        tmp_path / "service.toml",
        client_factory=lambda _: client,
        starter=lambda _: starts.append(object()),
    )

    assert runtime.ensure_client() is client
    assert starts == []
    assert runtime.owns_service is False


def test_unavailable_gateway_starts_once_then_returns_healthy_client(tmp_path: Path) -> None:
    client = _Client([False, True])
    process = _Process()
    starts: list[object] = []
    runtime = GatewayRuntime(
        tmp_path / "service.toml",
        client_factory=lambda _: client,
        starter=lambda _: starts.append(process) or process,
        startup_timeout_seconds=1,
        poll_interval_seconds=0,
    )

    assert runtime.ensure_client() is client
    assert starts == [process]
    assert runtime.owns_service is True
    runtime.close()
    assert process.terminated is True


def test_external_service_is_never_stopped(tmp_path: Path) -> None:
    client = _Client([True])
    runtime = GatewayRuntime(tmp_path / "service.toml", client_factory=lambda _: client)

    runtime.ensure_client()
    runtime.close()

    assert runtime.owns_service is False


def test_owned_gateway_restarts_when_service_config_changes(tmp_path: Path) -> None:
    config = tmp_path / "service.toml"
    config.write_text("version = 1", encoding="utf-8")
    client = _Client([False, True, False, True])
    first, second = _Process(), _Process()
    starts = iter([first, second])
    runtime = GatewayRuntime(
        config,
        client_factory=lambda _: client,
        starter=lambda _: next(starts),
        startup_timeout_seconds=1,
        poll_interval_seconds=0,
    )

    runtime.ensure_client()
    config.write_text("version = 2", encoding="utf-8")
    runtime.ensure_client()

    assert first.terminated is True
    assert runtime.owns_service is True
