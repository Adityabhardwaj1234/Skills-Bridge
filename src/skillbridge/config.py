"""Configuration, environment detection, cross-platform path resolution, and runtime limits for SkillBridge."""

from __future__ import annotations

import os
import platform
import shutil
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class LoaderLimits:
    """Configurable limits for just-in-time skill and reference loading."""
    max_file_size_bytes: int = 4 * 1024 * 1024  # 4 MB per file
    max_total_bytes: int = 32 * 1024 * 1024     # 32 MB total per loaded skill bundle
    max_nesting_depth: int = 6                  # Maximum relative directory depth
    max_references: int = 100                   # Maximum supporting reference files loaded
    max_selected_skills: int = 3                # Maximum complementary skills per task
    max_context_tokens: int = 12000             # Maximum estimated token budget per task
    max_parallel_workers: int = 8               # Worker pool size for parallel batch loading
    allowed_extensions: tuple[str, ...] = (
        ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".py", ".sh", ".js", ".ts", ".html", ".css", ".sql"
    )


@dataclass
class NetworkConfig:
    """Network timeouts, retry settings, response size caps, and offline mode."""
    connect_timeout_sec: float = 8.0
    read_timeout_sec: float = 15.0
    max_response_bytes: int = 128 * 1024 * 1024  # 128 MB max download (large index catalogs)
    max_redirects: int = 5
    max_retries: int = 2
    offline_mode: bool = False


@dataclass
class SecurityPolicyConfig:
    """Configurable security and trust policy settings."""
    allow_trusted_caution: bool = True
    block_community_caution_without_approval: bool = True
    never_override_dangerous: bool = True
    allow_builtin_dangerous_override: bool = True
    require_approval_for_code_or_config: bool = True
    trusted_repos: List[str] = field(default_factory=lambda: [
        "openai/skills",
        "anthropics/skills",
        "huggingface/skills",
        "NVIDIA/skills",
        "NousResearch/hermes-agent",
    ])
    allowed_domains: List[str] = field(default_factory=lambda: [
        "hermes-agent.nousresearch.com",
        "skills.sh",
        "www.skills.sh",
        "clawhub.ai",
        "chat-agents.lobehub.com",
        "browse.sh",
        "api.github.com",
        "raw.githubusercontent.com",
        "github.com",
        "registry.modelcontextprotocol.io",
        "registry.smithery.ai",
        "server.smithery.ai",
        "smithery.ai",
    ])


@dataclass
class SkillBridgeConfig:
    """Central configuration for SkillBridge runtime, storage, and client adapters."""
    home_dir: Path = field(default_factory=lambda: Path(os.environ.get("SKILLBRIDGE_HOME", Path.home() / ".skillbridge")))
    project_root: Path = field(default_factory=Path.cwd)
    enable_telemetry: bool = True
    enable_content_cache: bool = False
    loader_limits: LoaderLimits = field(default_factory=LoaderLimits)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    security_policy: SecurityPolicyConfig = field(default_factory=SecurityPolicyConfig)
    extra_skill_dirs: List[Path] = field(default_factory=list)

    @property
    def db_path(self) -> Path:
        return self.home_dir / "skillbridge.db"

    @property
    def quarantine_dir(self) -> Path:
        return self.home_dir / "quarantine"

    @property
    def backups_dir(self) -> Path:
        return self.home_dir / "backups"

    @property
    def index_cache_dir(self) -> Path:
        return self.home_dir / "index-cache"

    @property
    def content_cache_dir(self) -> Path:
        return self.home_dir / "content-cache"

    @property
    def audit_log_path(self) -> Path:
        return self.home_dir / "audit.jsonl"

    @property
    def bundled_data_dir(self) -> Path:
        return Path(__file__).resolve().parent / "data" / "hermes_catalog"

    def ensure_dirs(self) -> None:
        """Create required state directories safely."""
        for d in (self.home_dir, self.quarantine_dir, self.backups_dir, self.index_cache_dir):
            d.mkdir(parents=True, exist_ok=True)
        if self.enable_content_cache:
            self.content_cache_dir.mkdir(parents=True, exist_ok=True)

    def get_local_skill_discovery_dirs(self) -> List[Dict[str, Any]]:
        """Return ordered local skill directories across Hermes, OpenCode, Claude Code, and Agent Skills."""
        user_home = Path.home()
        proj = self.project_root
        dirs: List[Dict[str, Any]] = [
            # Bundled Hermes Agent catalog inside SkillBridge
            {"path": self.bundled_data_dir / "bundled_skills", "source": "hermes-bundled", "trust": "builtin"},
            {"path": self.bundled_data_dir / "optional_skills", "source": "hermes-official", "trust": "builtin"},
            # User/Project Hermes directories
            {"path": Path(os.environ.get("HERMES_HOME", user_home / ".hermes")) / "skills", "source": "hermes-local", "trust": "trusted"},
            # OpenCode directories (verified from https://opencode.ai/docs/skills/)
            {"path": proj / ".opencode" / "skills", "source": "opencode-project", "trust": "trusted"},
            {"path": user_home / ".config" / "opencode" / "skills", "source": "opencode-user", "trust": "trusted"},
            {"path": proj / ".agents" / "skills", "source": "agents-project", "trust": "trusted"},
            {"path": user_home / ".agents" / "skills", "source": "agents-user", "trust": "trusted"},
            # Claude Code directories (verified from https://code.claude.com/docs/en/skills)
            {"path": proj / ".claude" / "skills", "source": "claude-project", "trust": "trusted"},
            {"path": user_home / ".claude" / "skills", "source": "claude-user", "trust": "trusted"},
        ]
        for extra in self.extra_skill_dirs:
            dirs.append({"path": Path(extra), "source": "local-custom", "trust": "community"})
        return dirs

    def detect_environment(self) -> Dict[str, Any]:
        """Detect OS, Python version, installed runtimes, executables, and native client configs."""
        user_home = Path.home()
        proj = self.project_root
        executables = {}
        for exe in ("python", "python3", "pip", "node", "npm", "npx", "bun", "uv", "uvx", "git", "gh", "opencode", "claude", "hermes"):
            executables[exe] = shutil.which(exe)

        opencode_user_cfg = user_home / ".config" / "opencode" / "opencode.json"
        opencode_user_cfg_c = user_home / ".config" / "opencode" / "opencode.jsonc"
        opencode_proj_cfg = proj / "opencode.json"
        opencode_proj_cfg_c = proj / "opencode.jsonc"

        claude_user_cfg = Path(os.environ.get("CLAUDE_CONFIG_DIR", user_home)) / ".claude.json"
        claude_user_settings = user_home / ".claude" / "settings.json"
        claude_proj_mcp = proj / ".mcp.json"
        claude_proj_settings = proj / ".claude" / "settings.json"

        return {
            "os_name": os.name,
            "sys_platform": sys.platform,
            "platform_release": platform.release(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
            "python_executable": sys.executable,
            "skillbridge_home": str(self.home_dir),
            "project_root": str(proj),
            "offline_mode": self.network.offline_mode,
            "executables": executables,
            "clients": {
                "opencode": {
                    "executable_found": executables.get("opencode") is not None,
                    "executable_path": executables.get("opencode"),
                    "user_config_path": str(opencode_user_cfg_c if opencode_user_cfg_c.exists() else opencode_user_cfg),
                    "project_config_path": str(opencode_proj_cfg_c if opencode_proj_cfg_c.exists() else opencode_proj_cfg),
                    "user_skills_dir": str(user_home / ".config" / "opencode" / "skills"),
                    "project_skills_dir": str(proj / ".opencode" / "skills"),
                    "user_agents_dir": str(user_home / ".config" / "opencode" / "agents"),
                    "project_agents_dir": str(proj / ".opencode" / "agents"),
                },
                "claude-code": {
                    "executable_found": executables.get("claude") is not None,
                    "executable_path": executables.get("claude"),
                    "user_mcp_config_path": str(claude_user_cfg),
                    "user_settings_path": str(claude_user_settings),
                    "project_mcp_config_path": str(claude_proj_mcp),
                    "project_settings_path": str(claude_proj_settings),
                    "user_skills_dir": str(user_home / ".claude" / "skills"),
                    "project_skills_dir": str(proj / ".claude" / "skills"),
                    "user_agents_dir": str(user_home / ".claude" / "agents"),
                    "project_agents_dir": str(proj / ".claude" / "agents"),
                },
                "hermes": {
                    "executable_found": executables.get("hermes") is not None,
                    "bundled_catalog_present": self.bundled_data_dir.is_dir(),
                    "bundled_skills_dir": str(self.bundled_data_dir / "bundled_skills"),
                    "optional_skills_dir": str(self.bundled_data_dir / "optional_skills"),
                    "optional_mcps_dir": str(self.bundled_data_dir / "optional_mcps"),
                },
            },
        }

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["home_dir"] = str(self.home_dir)
        data["project_root"] = str(self.project_root)
        data["extra_skill_dirs"] = [str(p) for p in self.extra_skill_dirs]
        return data
