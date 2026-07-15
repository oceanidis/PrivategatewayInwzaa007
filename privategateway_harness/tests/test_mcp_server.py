from pathlib import Path

from privategateway_harness.mcp_server import HarnessMcpSettings


def test_mcp_settings_are_pinned_to_host_config(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("PRIVATEGATEWAY_HARNESS_PROJECT_ID", "loan_ai")
    monkeypatch.setenv("PRIVATEGATEWAY_HARNESS_SESSIONS_ROOT", str(tmp_path / "sessions"))
    monkeypatch.setenv("PRIVATEGATEWAY_HARNESS_RAW_ROOTS", str(tmp_path / "raw_a") + ";" + str(tmp_path / "raw_b"))
    monkeypatch.setenv("PRIVATEGATEWAY_HARNESS_POLICY_ROOT", str(tmp_path / "policies"))

    policy_root = tmp_path / 'policies'
    policy_root.mkdir()
    (policy_root / 'approved.yaml').write_text('columns: {}\n', encoding='utf-8')
    settings = HarnessMcpSettings.from_env()

    assert settings.project_id == "loan_ai"
    assert settings.raw_roots == (tmp_path / "raw_a", tmp_path / "raw_b")
    assert settings.policy_path("approved.yaml") == (tmp_path / "policies" / "approved.yaml")
