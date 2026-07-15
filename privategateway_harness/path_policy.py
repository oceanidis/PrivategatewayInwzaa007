from __future__ import annotations

from pathlib import Path

from .errors import HarnessError


class PathPolicy:
    def __init__(self, raw_roots: tuple[Path, ...]) -> None:
        self.raw_roots = tuple(root.resolve() for root in raw_roots)

    def validate_raw_input(self, path: Path) -> Path:
        candidate = path.resolve()
        if not self.raw_roots or not any(candidate.is_relative_to(root) for root in self.raw_roots):
            raise HarnessError('RAW_PATH_DENIED')
        if candidate.is_symlink() or candidate.is_dir():
            raise HarnessError('RAW_PATH_DENIED')
        return candidate
