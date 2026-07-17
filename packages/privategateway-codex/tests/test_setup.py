from __future__ import annotations

import tomllib

from privategateway_codex.setup import initialize_gateway, main


def test_initialize_gateway_creates_reusable_local_state(tmp_path, monkeypatch) -> None:
    protected = tmp_path / "company-data"
    protected.mkdir()
    state = tmp_path / "gateway-state"
    monkeypatch.chdir(tmp_path)

    result = initialize_gateway(
        protected,
        project_id="loan_ai",
        state_root=state,
        service_starter=lambda _: None,
    )

    assert result.config_path == state / "service.toml"
    assert result.config_path.exists()
    assert (state / "default-policy.yaml").exists()
    assert (state / ".privacy_gateway" / "keys").exists()
    config = tomllib.loads(result.config_path.read_text(encoding="utf-8"))["service"]
    assert config["project_id"] == "loan_ai"
    assert config["protected_roots"] == [str(protected)]
    assert config["address"].startswith("127.0.0.1:")


def test_setup_cli_reports_missing_protected_root(tmp_path, capsys) -> None:
    exit_code = main(["--protect", str(tmp_path / "missing")])

    assert exit_code == 1
    assert capsys.readouterr().out.strip() == '{"ok": false, "error_code": "PROTECTED_ROOT_NOT_FOUND"}'

def test_initialize_gateway_starts_the_service_after_writing_config(tmp_path, monkeypatch) -> None:
    protected = tmp_path / "company-data"
    protected.mkdir()
    state = tmp_path / "gateway-state"
    started = []
    startup_entries = []

    result = initialize_gateway(
        protected,
        project_id="loan_ai",
        state_root=state,
        service_starter=lambda config_path: started.append(config_path),
        startup_installer=lambda config_path: startup_entries.append(config_path),
    )

    assert started == [result.config_path]
    assert startup_entries == [result.config_path]
from privategateway_codex.startup import install_user_startup


def test_startup_entry_launches_service_with_the_config_path(tmp_path) -> None:
    config = tmp_path / "service.toml"
    entry = install_user_startup(
        config,
        startup_dir=tmp_path / "Startup",
        command=[r"C:\\gateway\\privategateway-service.exe"],
    )

    assert entry is not None
    content = entry.read_text(encoding="utf-8")
    assert "privategateway-service.exe" in content
    assert "--config" in content
    assert str(config) in content

def test_initialize_gateway_stops_existing_service_before_replacing_config(tmp_path) -> None:
    protected = tmp_path / "company-data"
    protected.mkdir()
    state = tmp_path / "gateway-state"
    state.mkdir()
    existing = state / "service.toml"
    existing.write_text("[service]\n", encoding="utf-8")
    stopped = []

    initialize_gateway(
        protected,
        state_root=state,
        service_stopper=lambda config_path: stopped.append(config_path),
        service_starter=lambda _: None,
        startup_installer=lambda _: None,
    )

    assert stopped == [existing]