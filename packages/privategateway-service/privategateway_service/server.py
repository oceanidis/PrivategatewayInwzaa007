from __future__ import annotations

import json
from multiprocessing.connection import AuthenticationError, Listener
from threading import Event, Thread
from typing import Any

from privategateway_protocol import GatewayError, GatewayOperation, GatewayRequest

from .operations import GatewayOperations

MAX_MESSAGE_BYTES = 1_048_576


def default_family() -> str:
    return "AF_PIPE" if __import__("os").name == "nt" else "AF_UNIX"


class LocalGatewayServer:
    def __init__(self, operations: GatewayOperations, *, address: str, authkey: bytes, family: str | None = None) -> None:
        self.operations = operations
        self.address = address
        self.authkey = bytes(authkey)
        self.family = family or default_family()
        self._listener: Listener | None = None
        self._stop = Event()
        self._thread: Thread | None = None

    def start(self) -> None:
        self._listener = Listener(self.address, family=self.family, authkey=self.authkey)
        self._thread = Thread(target=self.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        if self._listener is not None:
            self._listener.close()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def serve_forever(self) -> None:
        if self._listener is None:
            raise RuntimeError("server is not started")
        while not self._stop.is_set():
            try:
                connection = self._listener.accept()
            except AuthenticationError:
                continue
            except (OSError, EOFError):
                break
            with connection:
                try:
                    raw = connection.recv_bytes(MAX_MESSAGE_BYTES + 1)
                    if self._is_shutdown(raw):
                        self._stop.set()
                        response = GatewayError("SERVICE_STOPPING", "control")
                    else:
                        request = self._decode_request(raw)
                        response = self.operations.execute(request)
                except Exception:
                    response = GatewayError("INVALID_REQUEST", "unknown")
                connection.send_bytes(self._encode_response(response))

    @staticmethod
    def _is_shutdown(raw: bytes) -> bool:
        try:
            return json.loads(raw.decode("utf-8")) == {"control": "shutdown"}
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False

    @staticmethod
    def _decode_request(raw: bytes) -> GatewayRequest:
        if len(raw) > MAX_MESSAGE_BYTES:
            raise ValueError("too large")
        payload: dict[str, Any] = json.loads(raw.decode("utf-8"))
        if set(payload) != {"request_id", "operation", "arguments"} or not isinstance(payload["arguments"], dict):
            raise ValueError("invalid request")
        return GatewayRequest(str(payload["request_id"]), GatewayOperation(str(payload["operation"])), payload["arguments"])

    @staticmethod
    def _encode_response(response: object) -> bytes:
        payload = response.to_dict()
        encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_MESSAGE_BYTES:
            return json.dumps(GatewayError("RESPONSE_TOO_LARGE", payload.get("request_id", "unknown")).to_dict()).encode("utf-8")
        return encoded
