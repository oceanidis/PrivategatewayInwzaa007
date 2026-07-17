from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


def _required_path(value: Path | str, field_name: str) -> Path:
    if isinstance(value, str) and not value.strip():
        raise ValueError(f"{field_name} must be nonblank")
    try:
        path = Path(value)
    except TypeError as exc:
        raise ValueError(f"{field_name} must be a path") from exc
    if not str(path).strip():
        raise ValueError(f"{field_name} must be nonblank")
    return path


@dataclass(frozen=True)
class ServiceConfig:
    protected_roots: tuple[Path, ...]
    safe_root: Path
    policy_path: Path
    project_id: str
    secure_root: Path | None = None
    key_root: Path | None = None
    auto_policy: bool = True

    def __post_init__(self) -> None:
        roots = tuple(_required_path(root, "protected_roots") for root in self.protected_roots)
        if not roots:
            raise ValueError("protected_roots must not be empty")
        safe_root = _required_path(self.safe_root, "safe_root")
        policy_path = _required_path(self.policy_path, "policy_path")
        if not isinstance(self.project_id, str) or not self.project_id.strip():
            raise ValueError("project_id must be nonblank")
        object.__setattr__(self, "protected_roots", roots)
        object.__setattr__(self, "safe_root", safe_root)
        object.__setattr__(self, "policy_path", policy_path)
        object.__setattr__(self, "secure_root", self.secure_root or safe_root.parent / ".privacy_gateway" / "secure")
        object.__setattr__(self, "key_root", self.key_root or safe_root.parent / ".privacy_gateway" / "keys")
