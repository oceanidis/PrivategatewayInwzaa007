from __future__ import annotations


class HarnessError(RuntimeError):
    """A stable, agent-safe harness failure."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        self.code = code
        self.detail = detail
        super().__init__(code)
