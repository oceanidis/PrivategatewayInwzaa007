from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .runtime import GatewayRuntime
from .safe_read import SafeFileReader


def default_config_path() -> Path:
    configured = os.environ.get("PRIVATEGATEWAY_CONFIG")
    if configured:
        return Path(configured)
    return Path(os.environ.get("LOCALAPPDATA", Path.home())) / "PrivateGateway" / "service.toml"


def _read_safe_file(
    path: str,
    *,
    offset: int = 0,
    limit: int = 200,
    max_chars: int = 50_000,
    reader: SafeFileReader | Any | None = None,
) -> dict[str, Any]:
    """Read only Gateway-sanitized data from a supported protected path."""
    selected_reader = reader or SafeFileReader(GatewayRuntime(default_config_path()))
    return selected_reader.read(path, offset=offset, limit=limit, max_chars=max_chars)


read_safe_file = _read_safe_file


def build_server(*, reader: SafeFileReader | None = None):
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise RuntimeError("MCP support is required for the Codex adapter") from exc

    server = FastMCP("privategateway-codex")
    handler = _read_safe_file

    @server.tool()
    def read_safe_file(path: str, offset: int = 0, limit: int = 200, max_chars: int = 50_000) -> dict[str, Any]:
        """Return only PrivateGateway-sanitized contents for a supported protected file."""
        return handler(path, offset=offset, limit=limit, max_chars=max_chars, reader=reader)

    return server


def main() -> None:
    build_server().run(transport="stdio")


if __name__ == "__main__":
    main()
