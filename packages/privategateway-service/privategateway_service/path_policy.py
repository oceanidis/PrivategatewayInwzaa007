from __future__ import annotations

import os
import stat
from pathlib import Path

RAW_PATH_DENIED = "RAW_PATH_DENIED"
OUTPUT_PATH_DENIED = "OUTPUT_PATH_DENIED"


class ServicePathError(ValueError):
    def __init__(self, code: str) -> None:
        if code not in {RAW_PATH_DENIED, OUTPUT_PATH_DENIED}:
            raise ValueError("invalid service path error code")
        self.code = code
        super().__init__(code)


class PathPolicy:
    def __init__(self, protected_roots: tuple[Path, ...], safe_root: Path) -> None:
        roots = tuple(Path(root) for root in protected_roots)
        if not roots:
            raise ValueError("protected_roots must not be empty")
        self.protected_roots = tuple(self._existing_directory(root) for root in roots)
        self.safe_root = self._initialize_safe_root(Path(safe_root))

    def resolve_directory(self, path: Path | str) -> Path:
        candidate = self._raw_path(path, RAW_PATH_DENIED)
        self._inspect_existing_components(candidate, RAW_PATH_DENIED)
        resolved = self._resolve_existing(candidate, RAW_PATH_DENIED)
        if not resolved.is_dir() or not self._inside_any(resolved, self.protected_roots):
            raise ServicePathError(RAW_PATH_DENIED)
        return resolved

    def resolve_input(self, path: Path | str) -> Path:
        candidate = self._raw_path(path, RAW_PATH_DENIED)
        self._inspect_existing_components(candidate, RAW_PATH_DENIED)
        resolved = self._resolve_existing(candidate, RAW_PATH_DENIED)
        if not resolved.is_file() or not self._inside_any(resolved, self.protected_roots):
            raise ServicePathError(RAW_PATH_DENIED)
        return resolved

    def resolve_output(self, path: Path | str) -> Path:
        candidate = self._raw_path(path, OUTPUT_PATH_DENIED)
        parent = candidate.parent
        self._inspect_existing_components(parent, OUTPUT_PATH_DENIED)
        resolved_parent = self._resolve_existing(parent, OUTPUT_PATH_DENIED)
        if not self._inside(resolved_parent, self.safe_root):
            raise ServicePathError(OUTPUT_PATH_DENIED)
        try:
            resolved = candidate.resolve(strict=False)
        except (OSError, RuntimeError):
            raise ServicePathError(OUTPUT_PATH_DENIED) from None
        if not self._inside(resolved, self.safe_root):
            raise ServicePathError(OUTPUT_PATH_DENIED)
        if resolved.exists() and (resolved.is_dir() or self._is_link_or_reparse(resolved)):
            raise ServicePathError(OUTPUT_PATH_DENIED)
        return resolved

    @classmethod
    def _initialize_safe_root(cls, path: Path) -> Path:
        candidate = path if path.is_absolute() else Path.cwd() / path
        try:
            cls._inspect_existing_components(candidate.parent, OUTPUT_PATH_DENIED)
            candidate.mkdir(parents=True, exist_ok=True)
            cls._inspect_existing_components(candidate, OUTPUT_PATH_DENIED)
            if not candidate.is_dir() or cls._is_link_or_reparse(candidate):
                raise ValueError("configured safe root must be a directory")
            return candidate.resolve(strict=True)
        except ServicePathError:
            raise ValueError("configured safe root must be a safe directory") from None
        except (OSError, RuntimeError):
            raise ValueError("configured safe root must be an existing directory") from None

    @staticmethod
    def _existing_directory(path: Path) -> Path:
        try:
            if not path.is_dir() or PathPolicy._is_link_or_reparse(path):
                raise ValueError("configured root must be a directory")
            return path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ValueError("configured root must be an existing directory") from exc

    @staticmethod
    def _raw_path(path: Path | str, code: str) -> Path:
        try:
            raw = os.fspath(path)
        except TypeError:
            raise ServicePathError(code) from None
        if isinstance(raw, bytes) or raw.startswith(("\\\\", "//")):
            raise ServicePathError(code)
        for index, character in enumerate(raw):
            if character == ":" and not (index == 1 and raw[0].isalpha()):
                raise ServicePathError(code)
        candidate = Path(raw)
        return candidate if candidate.is_absolute() else Path.cwd() / candidate

    @classmethod
    def _inspect_existing_components(cls, path: Path, code: str) -> None:
        current = Path(path.anchor) if path.anchor else Path.cwd()
        parts = path.parts[1:] if path.anchor else path.parts
        for part in parts:
            current /= part
            try:
                info = current.lstat()
            except FileNotFoundError:
                break
            except OSError:
                raise ServicePathError(code) from None
            if cls._is_link_or_reparse_info(info):
                raise ServicePathError(code)

    @staticmethod
    def _resolve_existing(path: Path, code: str) -> Path:
        try:
            return path.resolve(strict=True)
        except (FileNotFoundError, OSError, RuntimeError):
            raise ServicePathError(code) from None

    @staticmethod
    def _is_link_or_reparse(path: Path) -> bool:
        try:
            return PathPolicy._is_link_or_reparse_info(path.lstat())
        except OSError:
            return True

    @staticmethod
    def _is_link_or_reparse_info(info: os.stat_result) -> bool:
        attributes = getattr(info, "st_file_attributes", 0)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse)

    @staticmethod
    def _inside(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False

    @classmethod
    def _inside_any(cls, path: Path, roots: tuple[Path, ...]) -> bool:
        return any(cls._inside(path, root) for root in roots)
