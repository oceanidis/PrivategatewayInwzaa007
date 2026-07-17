from __future__ import annotations

import os
from pathlib import Path
from typing import Sequence

from .service_manager import _service_command


def install_user_startup(config_path: str | Path, *, startup_dir: str | Path | None = None, command: Sequence[str] | None = None) -> Path | None:
    """Create a per-user Windows startup entry for the local Gateway service."""
    if os.name != "nt" and startup_dir is None:
        return None
    directory = Path(startup_dir) if startup_dir is not None else _windows_startup_dir()
    directory.mkdir(parents=True, exist_ok=True)
    executable = list(command or _service_command())
    rendered = " ".join(_quote_cmd(part) for part in [*executable, "start", "--config", str(Path(config_path))])
    entry = directory / "PrivateGateway-Service.cmd"
    entry.write_text(f"@echo off\r\nstart \"\" /b {rendered}\r\n", encoding="utf-8")
    return entry


def _windows_startup_dir() -> Path:
    appdata = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    return appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"


def _quote_cmd(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'