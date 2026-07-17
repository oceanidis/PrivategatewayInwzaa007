from __future__ import annotations

import os
import subprocess
import sys
import time
from hashlib import sha256
from pathlib import Path
from threading import RLock
from typing import Callable, Protocol

from privategateway_client import LocalGatewayClient
from privategateway_service.cli import _load_config


class _Process(Protocol):
    def poll(self) -> int | None: ...
    def terminate(self) -> None: ...
    def wait(self, timeout: float) -> object: ...


class GatewayRuntimeError(RuntimeError):
    pass


class GatewayRuntime:
    """Owns only a Gateway child process that it started itself."""

    def __init__(
        self,
        config_path: str | Path,
        *,
        client_factory: Callable[[Path], object] | None = None,
        starter: Callable[[Path], _Process] | None = None,
        startup_timeout_seconds: float = 10,
        poll_interval_seconds: float = 0.1,
    ) -> None:
        self._config_path = Path(config_path)
        self._client_factory = client_factory or self._default_client
        self._starter = starter or self._default_starter
        self._startup_timeout_seconds = startup_timeout_seconds
        self._poll_interval_seconds = poll_interval_seconds
        self._lock = RLock()
        self._owned_process: _Process | None = None
        self._owned_config_fingerprint: str | None = None

    @property
    def owns_service(self) -> bool:
        return self._owned_process is not None

    def ensure_client(self) -> object:
        with self._lock:
            fingerprint = self._config_fingerprint()
            if self._owned_process is not None and fingerprint != self._owned_config_fingerprint:
                self._stop_owned()
            client = self._client_factory(self._config_path)
            if self._healthy(client):
                return client
            if self._owned_process is not None and self._owned_process.poll() is not None:
                self._owned_process = None
                self._owned_config_fingerprint = None
            if self._owned_process is None:
                self._owned_process = self._starter(self._config_path)
                self._owned_config_fingerprint = fingerprint
            deadline = time.monotonic() + self._startup_timeout_seconds
            while time.monotonic() <= deadline:
                if self._healthy(client):
                    return client
                if self._owned_process.poll() is not None:
                    break
                time.sleep(self._poll_interval_seconds)
            raise GatewayRuntimeError("GATEWAY_UNAVAILABLE")

    def close(self) -> None:
        with self._lock:
            self._stop_owned()

    def _stop_owned(self) -> None:
        process, self._owned_process = self._owned_process, None
        self._owned_config_fingerprint = None
        if process is None or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass

    def _config_fingerprint(self) -> str | None:
        try:
            return sha256(self._config_path.read_bytes()).hexdigest()
        except OSError:
            return None

    @staticmethod
    def _healthy(client: object) -> bool:
        try:
            response = client.health()
            to_dict = getattr(response, "to_dict", None)
            payload = to_dict() if callable(to_dict) else response
            return isinstance(payload, dict) and payload.get("ok") is True
        except Exception:
            return False

    @staticmethod
    def _default_client(config_path: Path) -> LocalGatewayClient:
        _, address, authkey, family = _load_config(config_path)
        return LocalGatewayClient(address, authkey, family=family)

    @staticmethod
    def _default_starter(config_path: Path) -> _Process:
        return subprocess.Popen(
            [*GatewayRuntime._service_command(), "start", "--config", str(config_path)],
            cwd=str(Path(__file__).resolve().parents[3]),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    @staticmethod
    def _service_command() -> list[str]:
        suffix = ".exe" if os.name == "nt" else ""
        sibling = Path(sys.argv[0]).resolve().with_name(f"privategateway-service{suffix}")
        if sibling.is_file():
            return [str(sibling)]
        return [sys.executable, "-m", "privategateway_service.cli"]