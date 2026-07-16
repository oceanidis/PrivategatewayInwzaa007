from __future__ import annotations

from privategateway_codex.mcp_server import build_server, read_safe_file


class _Reader:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int, int, int]] = []

    def read(self, path: str, *, offset: int, limit: int, max_chars: int):
        self.calls.append((path, offset, limit, max_chars))
        return {"ok": True, "kind": "table"}


def test_mcp_read_handler_delegates_only_to_safe_file_reader() -> None:
    reader = _Reader()

    response = read_safe_file("C:/protected/customers.csv", offset=4, limit=5, max_chars=6, reader=reader)

    assert response == {"ok": True, "kind": "table"}
    assert reader.calls == [("C:/protected/customers.csv", 4, 5, 6)]


def test_mcp_server_registers_read_safe_file_tool() -> None:
    server = build_server()

    assert "read_safe_file" in server._tool_manager._tools

def test_default_config_path_uses_user_local_gateway_state(monkeypatch, tmp_path) -> None:
    from privategateway_codex.mcp_server import default_config_path

    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    assert default_config_path() == tmp_path / "PrivateGateway" / "service.toml"
