from __future__ import annotations

from pathlib import Path

import pytest

import privategateway_codex.runtime as runtime_module
from privategateway_codex.runtime import GatewayRuntime, GatewayRuntimeError


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
    def __init__(self, exit_code: int | None = None) -> None:
        self.exit_code = exit_code
        self.terminated = False

    def poll(self):
        return self.exit_code

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


def test_dead_owned_gateway_is_restarted_on_the_next_request(tmp_path: Path) -> None:
    client = _Client([False, False, False, False, True])
    failed, recovered = _Process(exit_code=1), _Process()
    starts = iter([failed, recovered])
    runtime = GatewayRuntime(
        tmp_path / "service.toml",
        client_factory=lambda _: client,
        starter=lambda _: next(starts),
        startup_timeout_seconds=1,
        poll_interval_seconds=0,
    )

    with pytest.raises(GatewayRuntimeError, match="GATEWAY_UNAVAILABLE"):
        runtime.ensure_client()

    assert runtime.ensure_client() is client
    assert runtime.owns_service is True

def test_default_starter_uses_project_root_as_working_directory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def start(*args, **kwargs) -> _Process:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return _Process()

    monkeypatch.setattr(runtime_module.subprocess, "Popen", start)

    GatewayRuntime._default_starter(tmp_path / "service.toml")

    assert Path(captured["kwargs"]["cwd"]) == Path(runtime_module.__file__).resolve().parents[3]

def test_default_starter_uses_sibling_service_executable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    codex_executable = tmp_path / "privategateway-codex-mcp.exe"
    service_executable = tmp_path / "privategateway-service.exe"
    codex_executable.touch()
    service_executable.touch()
    captured: dict[str, object] = {}

    def start(args, **kwargs) -> _Process:
        captured["args"] = args
        return _Process()

    monkeypatch.setattr(runtime_module.sys, "argv", [str(codex_executable)])
    monkeypatch.setattr(runtime_module.subprocess, "Popen", start)

    GatewayRuntime._default_starter(tmp_path / "service.toml")

    assert captured["args"][:2] == [str(service_executable), "start"]