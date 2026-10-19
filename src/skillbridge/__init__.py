"""SkillBridge — Flagship Security, Multi-Tier Verification, Runtime Memory & MCP Orchestration Layer."""

from __future__ import annotations

import importlib.abc
import importlib.machinery
import importlib.util
from pathlib import Path
import sys

__version__ = "2.0.0"

_PKG_ROOT = Path(__file__).resolve().parent


class _DirectStatPathFinder(importlib.abc.MetaPathFinder):
    """Fallback finder that uses stat() rather than cached readdir() on virtualized 9p/gVisor mounts."""

    def find_spec(self, fullname: str, path=None, target=None):
        if not fullname.startswith("skillbridge."):
            return None
        rel_parts = fullname.split(".")[1:]
        cand_dir = _PKG_ROOT.joinpath(*rel_parts)
        cand_init = cand_dir / "__init__.py"
        if cand_init.is_file():
            return importlib.util.spec_from_file_location(
                fullname,
                str(cand_init),
                submodule_search_locations=[str(cand_dir)],
            )
        cand_py = _PKG_ROOT.joinpath(*rel_parts[:-1], f"{rel_parts[-1]}.py") if len(rel_parts) > 1 else _PKG_ROOT / f"{rel_parts[0]}.py"
        if cand_py.is_file():
            return importlib.util.spec_from_file_location(fullname, str(cand_py))
        return None


if not any(type(f).__name__ == "_DirectStatPathFinder" for f in sys.meta_path):
    sys.meta_path.insert(0, _DirectStatPathFinder())

from skillbridge.bridge import SkillBridge
from skillbridge.config import SkillBridgeConfig
from skillbridge.settings import RuntimeSettings

__all__ = ["RuntimeSettings", "SkillBridge", "SkillBridgeConfig", "__version__"]
