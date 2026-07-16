from __future__ import annotations

import tomllib

from privategateway_codex.setup import initialize_gateway, main


def test_initialize_gateway_creates_reusable_local_state(tmp_path, monkeypatch) -> None:
    protected = tmp_path / "company-data"
    protected.mkdir()
    state = tmp_path / "gateway-state"
    monkeypatch.chdir(tmp_path)

    result = initialize_gateway(protected, project_id="loan_ai", state_root=state)

    assert result.config_path == state / "service.toml"
    assert result.config_path.exists()
    assert (state / "default-policy.yaml").exists()
    assert (state / ".privacy_gateway" / "keys").exists()
    config = tomllib.loads(result.config_path.read_text(encoding="utf-8"))["service"]
    assert config["project_id"] == "loan_ai"
    assert config["protected_roots"] == [str(protected)]


def test_setup_cli_reports_missing_protected_root(tmp_path, capsys) -> None:
    exit_code = main(["--protect", str(tmp_path / "missing")])

    assert exit_code == 1
    assert capsys.readouterr().out.strip() == '{"ok": false, "error_code": "PROTECTED_ROOT_NOT_FOUND"}'