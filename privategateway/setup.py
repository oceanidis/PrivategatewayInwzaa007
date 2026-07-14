from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path


_START = "<!-- privategateway:start -->"
_END = "<!-- privategateway:end -->"
_PACKAGE_ROOT = Path(__file__).resolve().parent


@dataclass(frozen=True)
class SetupStatus:
    installed: bool = False
    drifted: bool = False
    removed: bool = False


def run_setup(workspace: str | Path, *, check: bool = False, remove: bool = False) -> SetupStatus:
    root = Path(workspace).expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError("workspace was not found")
    agents = root / "AGENTS.md"
    mcp = root / ".codex" / "mcp.json"
    skill = root / ".agents" / "skills" / "privacy-safe-data-access"
    expected_agents = _managed_agents_block()
    expected_mcp = _mcp_entry()
    if remove:
        _remove_agents_block(agents)
        _remove_mcp_entry(mcp)
        if skill.exists():
            shutil.rmtree(skill)
        return SetupStatus(removed=True)
    drifted = _agents_drifted(agents, expected_agents) or _mcp_drifted(mcp, expected_mcp) or not _same_tree(skill, _PACKAGE_ROOT / "skills" / "privacy-safe-data-access")
    if check:
        return SetupStatus(drifted=drifted)
    _write_agents_block(agents, expected_agents)
    _write_mcp_entry(mcp, expected_mcp)
    skill.parent.mkdir(parents=True, exist_ok=True)
    if skill.exists():
        shutil.rmtree(skill)
    shutil.copytree(_PACKAGE_ROOT / "skills" / "privacy-safe-data-access", skill)
    return SetupStatus(installed=True)


def _managed_agents_block() -> str:
    return (_PACKAGE_ROOT / "templates" / "AGENTS.privategateway.md").read_text(encoding="utf-8").strip()


def _mcp_entry() -> dict:
    template = json.loads((_PACKAGE_ROOT / "templates" / "privategateway.mcp.json").read_text(encoding="utf-8"))
    template["command"] = str(Path(__file__).resolve().parents[1] / ".venv" / "Scripts" / "python.exe")
    return template


def _write_agents_block(path: Path, block: str) -> None:
    current = path.read_text(encoding="utf-8") if path.exists() else ""
    _remove_agents_block(path, current)
    current = path.read_text(encoding="utf-8") if path.exists() else ""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text((current.rstrip() + "\n\n" + block + "\n").lstrip(), encoding="utf-8")


def _remove_agents_block(path: Path, current: str | None = None) -> None:
    if current is None:
        if not path.exists(): return
        current = path.read_text(encoding="utf-8")
    start, end = current.find(_START), current.find(_END)
    if start >= 0 and end >= start:
        path.write_text((current[:start] + current[end + len(_END):]).strip() + "\n", encoding="utf-8")


def _load_mcp(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"mcpServers": {}}


def _write_mcp_entry(path: Path, entry: dict) -> None:
    data = _load_mcp(path)
    data.setdefault("mcpServers", {})["privategateway"] = entry
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _remove_mcp_entry(path: Path) -> None:
    if not path.exists(): return
    data = _load_mcp(path); data.get("mcpServers", {}).pop("privategateway", None)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _agents_drifted(path: Path, block: str) -> bool:
    return not path.exists() or block not in path.read_text(encoding="utf-8")


def _mcp_drifted(path: Path, entry: dict) -> bool:
    return _load_mcp(path).get("mcpServers", {}).get("privategateway") != entry


def _same_tree(destination: Path, source: Path) -> bool:
    return destination.exists() and all((destination / item.relative_to(source)).is_file() and (destination / item.relative_to(source)).read_bytes() == item.read_bytes() for item in source.rglob("*") if item.is_file())
