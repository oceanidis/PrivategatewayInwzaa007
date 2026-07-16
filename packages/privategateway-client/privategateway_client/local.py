from __future__ import annotations

from multiprocessing.connection import AuthenticationError, Client
from uuid import uuid4

from privategateway_protocol import GatewayOperation, GatewayRequest

from .serialization import decode_response, encode_request


class GatewayClientError(RuntimeError):
    pass


class LocalGatewayClient:
    def __init__(self, address: str, authkey: bytes, *, family: str) -> None:
        self.address, self.authkey, self.family = address, bytes(authkey), family

    def with_authkey(self, authkey: bytes) -> "LocalGatewayClient":
        return LocalGatewayClient(self.address, authkey, family=self.family)

    def browse_directory(self, path: str, *, include_hidden: bool = False):
        return self._call(GatewayOperation.BROWSE_DIRECTORY, {"path": path, "include_hidden": include_hidden})

    def inspect_file(self, path: str):
        return self._call(GatewayOperation.INSPECT_FILE, {"path": path})

    def read_safe_table(self, path: str, *, offset: int = 0, limit: int = 200):
        return self._call(GatewayOperation.READ_SAFE_TABLE, {"path": path, "offset": offset, "limit": limit})

    def read_safe_text(self, path: str, *, max_chars: int = 50_000):
        return self._call(GatewayOperation.READ_SAFE_TEXT, {"path": path, "max_chars": max_chars})

    def health(self):
        return self._call(GatewayOperation.HEALTH, {})

    def _call(self, operation: GatewayOperation, arguments: dict[str, object]):
        request = GatewayRequest(f"ipc_{uuid4().hex}", operation, arguments)
        try:
            with Client(self.address, family=self.family, authkey=self.authkey) as connection:
                connection.send_bytes(encode_request(request))
                return decode_response(connection.recv_bytes())
        except AuthenticationError as exc:
            raise GatewayClientError("GATEWAY_AUTHENTICATION_FAILED") from exc
        except (OSError, EOFError, ValueError) as exc:
            raise GatewayClientError("GATEWAY_UNAVAILABLE") from exc
