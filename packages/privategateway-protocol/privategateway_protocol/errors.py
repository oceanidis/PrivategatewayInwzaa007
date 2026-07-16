from dataclasses import dataclass


@dataclass(frozen=True)
class GatewayError:
    code: str
    request_id: str

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": False,
            "request_id": self.request_id,
            "error_code": self.code,
        }
