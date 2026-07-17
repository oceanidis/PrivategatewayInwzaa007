from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

from privategateway_client import LocalGatewayClient
from privategateway_service.cli import _load_config


def stop_gateway(config_path: str | Path, *, timeout_seconds: float = 5) -> None:
    config = Path(config_path)
    if not config.exists():
        return
    try:
        subprocess.run(
            [*_service_command(), "stop", "--config", str(config)],
            cwd=str(Path(__file__).resolve().parents[3]),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return


def ensure_gateway_running(config_path: str | Path, *, timeout_seconds: float = 10) -> None:
    config = Path(config_path)
    client = _client(config)
    if _healthy(client):
        return

    flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    subprocess.Popen(
        [*_service_command(), "start", "--config", str(config)],
        cwd=str(Path(__file__).resolve().parents[3]),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=flags,
    )
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if _healthy(client):
            return
        time.sleep(0.1)
    raise RuntimeError("GATEWAY_START_FAILED")


def _client(config_path: Path) -> LocalGatewayClient:
    _, address, authkey, family = _load_config(config_path)
    return LocalGatewayClient(address, authkey, family=family)


def _healthy(client: LocalGatewayClient) -> bool:
    try:
        return client.health().to_dict().get("ok") is True
    except Exception:
        return False


def _service_command() -> list[str]:
    suffix = ".exe" if os.name == "nt" else ""
    sibling = Path(sys.argv[0]).resolve().with_name(f"privategateway-service{suffix}")
    if sibling.is_file():
        return [str(sibling)]
    return [sys.executable, "-m", "privategateway_service.cli"]