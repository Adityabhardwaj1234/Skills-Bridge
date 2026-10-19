"""Native client adapters for OpenCode and Claude Code (skills, subagents, MCP servers, hooks, backups, and rollback)."""

from __future__ import annotations

import difflib
import json
import os
import re
import shutil
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from skillbridge.config import SkillBridgeConfig
from skillbridge.discovery.normalizer import (
    parse_skill_md,
    validate_bundle_rel_path,
    validate_skill_name,
)
from skillbridge.models import (
    ExtensionBundle,
    ExtensionRecord,
    ExtensionType,
    MCPTransportSpec,
)

CLAUDE_RESERVED_NAMES = {"synced", "anthropic-skills"}


def atomic_write_text(path: Path, content: str) -> None:
    """Write text to path atomically via a temporary sibling file and os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
        os.replace(tmp_name, path)
    except Exception:
        if os.path.exists(tmp_name):
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
        raise


def parse_jsonc(text: str) -> Tuple[Dict[str, Any], List[str]]:
    """Parse JSON or JSONC (JSON with // and /* */ comments and trailing commas), preserving header comment lines."""
    if not text.strip():
        return {}, []
    header_comments: List[str] = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("//"):
            header_comments.append(line)
        elif not s:
            continue
        else:
            break

    # Strip // and /* */ comments outside string literals
    token_re = re.compile(
        r'("(?:\\.|[^"\\])*")|(//[^\n]*)|(/\*[\s\S]*?\*/)',
        re.MULTILINE,
    )

    def _replacer(match: re.Match) -> str:
        if match.group(1) is not None:
            return match.group(1)
        return ""

    no_comments = token_re.sub(_replacer, text)
    # Remove trailing commas before } or ]
    no_trailing = re.sub(r",\s*([}\]])", r"\1", no_comments)
    parsed = json.loads(no_trailing)
    if not isinstance(parsed, dict):
        raise ValueError("Top-level configuration must be a JSON object")
    return parsed, header_comments


def dump_jsonc(data: Dict[str, Any], header_comments: Optional[List[str]] = None) -> str:
    """Serialize configuration dictionary back to formatted JSON/JSONC, preserving top-level header comments."""
    body = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if header_comments:
        return "\n".join(header_comments) + "\n" + body
    return body


def compute_unified_diff(old_text: str, new_text: str, path_label: str) -> str:
    return "".join(
        difflib.unified_diff(
            old_text.splitlines(keepends=True),
            new_text.splitlines(keepends=True),
            fromfile=f"a/{path_label}",
            tofile=f"b/{path_label}",
        )
    )


class ClientAdapter(ABC):
    """Abstract base adapter for native coding agent clients."""

    CLIENT_ID: str = "base"

    def __init__(self, config: SkillBridgeConfig, project_root: Optional[Path] = None, user_home: Optional[Path] = None):
        self.config = config
        self.project_root = Path(project_root or config.project_root)
        self.user_home = Path(user_home or Path.home())

    @abstractmethod
    def detect(self) -> Dict[str, Any]:
        """Detect whether the client executable or configuration directories exist."""

    @abstractmethod
    def plan_skill_install(self, bundle: ExtensionBundle, scope: str = "project") -> Tuple[List[Dict[str, Any]], str, List[str]]:
        """Return (planned_file_writes, diff_text, unpreserved_fields) for installing a skill."""

    @abstractmethod
    def plan_agent_install(self, bundle: ExtensionBundle, scope: str = "project") -> Tuple[List[Dict[str, Any]], str, List[str]]:
        """Return (planned_file_writes, diff_text, unpreserved_fields) for installing an agent/subagent."""

    @abstractmethod
    def plan_mcp_install(
        self,
        record: ExtensionRecord,
        scope: str = "project",
        *,
        lazy_disable_globally: bool = False,
    ) -> Tuple[List[Dict[str, Any]], str, List[str]]:
        """Return (planned_file_writes, diff_text, unpreserved_fields) for configuring an MCP server."""

    @abstractmethod
    def verify_installation(self, extension_name: str, extension_type: str, scope: str = "project") -> Dict[str, Any]:
        """Verify that an installed skill, agent, or MCP server is valid and discoverable in the client."""


class OpenCodeAdapter(ClientAdapter):
    """Native adapter for OpenCode (https://opencode.ai/docs/).

    Supported paths:
    - Project skills: `.opencode/skills/<name>/SKILL.md`
    - User skills: `~/.config/opencode/skills/<name>/SKILL.md`
    - Project agents: `.opencode/agents/<name>.md`
    - User agents: `~/.config/opencode/agents/<name>.md`
    - Project MCP config: `opencode.json` or `opencode.jsonc`
    - User MCP config: `~/.config/opencode/opencode.json` or `opencode.jsonc`
    """

    CLIENT_ID = "opencode"

    def _skills_dir(self, scope: str) -> Path:
        if scope == "user":
            return self.user_home / ".config" / "opencode" / "skills"
        return self.project_root / ".opencode" / "skills"

    def _agents_dir(self, scope: str) -> Path:
        if scope == "user":
            return self.user_home / ".config" / "opencode" / "agents"
        return self.project_root / ".opencode" / "agents"

    def _config_path(self, scope: str) -> Path:
        if scope == "user":
            base = self.user_home / ".config" / "opencode"
        else:
            base = self.project_root
        jsonc = base / "opencode.jsonc"
        if jsonc.exists():
            return jsonc
        return base / "opencode.json"

    def detect(self) -> Dict[str, Any]:
        exe = shutil.which("opencode")
        u_cfg = self._config_path("user")
        p_cfg = self._config_path("project")
        return {
            "client": self.CLIENT_ID,
            "executable_found": exe is not None,
            "executable_path": exe,
            "user_config_exists": u_cfg.exists(),
            "project_config_exists": p_cfg.exists(),
            "user_skills_dir": str(self._skills_dir("user")),
            "project_skills_dir": str(self._skills_dir("project")),
            "supported_formats": ["SKILL.md", "opencode.json", "opencode.jsonc", ".opencode/agents/*.md"],
        }

    def plan_skill_install(self, bundle: ExtensionBundle, scope: str = "project") -> Tuple[List[Dict[str, Any]], str, List[str]]:
        safe_name = validate_skill_name(bundle.name)
        target_dir = self._skills_dir(scope) / safe_name
        writes: List[Dict[str, Any]] = []
        diffs: List[str] = []
        unpreserved: List[str] = []

        for rel_path, content in sorted(bundle.files.items()):
            safe_rel = validate_bundle_rel_path(rel_path)
            dest = target_dir / safe_rel
            text = content.decode("utf-8-sig", errors="replace") if isinstance(content, bytes) else content
            if safe_rel == "SKILL.md":
                fm, body = parse_skill_md(text)
                for claude_key in ("disable-model-invocation", "allowed-tools"):
                    if claude_key in fm:
                        unpreserved.append(f"frontmatter.{claude_key} (Claude Code extension; OpenCode uses opencode.json permission.skill)")
                # Ensure name matches directory name per OpenCode strict validation rule
                if fm.get("name") != safe_name:
                    fm["name"] = safe_name
                    if not fm.get("description"):
                        fm["description"] = f"Skill {safe_name}"
                    text = "---\n" + yaml.safe_dump(fm, sort_keys=False).strip() + "\n---\n\n" + body
            old_text = dest.read_text(encoding="utf-8", errors="replace") if dest.exists() else ""
            writes.append({"path": str(dest), "content": text, "exists_before": dest.exists()})
            diffs.append(compute_unified_diff(old_text, text, f".opencode/skills/{safe_name}/{safe_rel}"))

        return writes, "\n".join(diffs), unpreserved

    def plan_agent_install(self, bundle: ExtensionBundle, scope: str = "project") -> Tuple[List[Dict[str, Any]], str, List[str]]:
        safe_name = validate_skill_name(bundle.name)
        dest = self._agents_dir(scope) / f"{safe_name}.md"
        raw_md = bundle.files.get("SKILL.md") or bundle.files.get(f"{safe_name}.md") or ""
        text = raw_md.decode("utf-8-sig", errors="replace") if isinstance(raw_md, bytes) else str(raw_md)
        fm, body = parse_skill_md(text)
        unpreserved: List[str] = []

        opencode_fm: Dict[str, Any] = {
            "description": str(fm.get("description") or f"Specialized subagent {safe_name}")[:500],
            "mode": str(fm.get("mode") or "subagent"),
        }
        if fm.get("model") and fm.get("model") != "inherit":
            opencode_fm["model"] = str(fm["model"])
        if "temperature" in fm:
            opencode_fm["temperature"] = fm["temperature"]
        if "steps" in fm:
            opencode_fm["steps"] = fm["steps"]

        # Convert Claude Code tools/disallowedTools to OpenCode permission block
        perm: Dict[str, Any] = dict(fm.get("permission")) if isinstance(fm.get("permission"), dict) else {}
        if "disallowedTools" in fm:
            disallowed = fm["disallowedTools"]
            dis_list = disallowed if isinstance(disallowed, list) else [s.strip() for s in str(disallowed).split(",")]
            for dt in dis_list:
                dt_low = str(dt).lower()
                if dt_low in ("write", "edit"):
                    perm["edit"] = "deny"
                elif dt_low == "bash":
                    perm["bash"] = "deny"
                else:
                    perm[dt_low] = "deny"
        if perm:
            opencode_fm["permission"] = perm

        for unsupported_key in ("isolation", "allowed-tools"):
            if unsupported_key in fm:
                unpreserved.append(f"agent.{unsupported_key} (not natively supported in OpenCode agent frontmatter)")

        converted_text = "---\n" + yaml.safe_dump(opencode_fm, sort_keys=False).strip() + "\n---\n\n" + body
        old_text = dest.read_text(encoding="utf-8", errors="replace") if dest.exists() else ""
        writes = [{"path": str(dest), "content": converted_text, "exists_before": dest.exists()}]
        diff = compute_unified_diff(old_text, converted_text, f".opencode/agents/{safe_name}.md")
        return writes, diff, unpreserved

    def plan_mcp_install(
        self,
        record: ExtensionRecord,
        scope: str = "project",
        *,
        lazy_disable_globally: bool = False,
    ) -> Tuple[List[Dict[str, Any]], str, List[str]]:
        cfg_path = self._config_path(scope)
        old_text = cfg_path.read_text(encoding="utf-8-sig") if cfg_path.exists() else ""
        cfg_data, comments = parse_jsonc(old_text) if old_text.strip() else ({"$schema": "https://opencode.ai/config.json"}, [])

        cfg_data.setdefault("$schema", "https://opencode.ai/config.json")
        mcp_block = cfg_data.setdefault("mcp", {})
        unpreserved: List[str] = []

        t = record.mcp_transport or MCPTransportSpec(transport_type="stdio", command="npx", args=["-y", record.name])
        if t.transport_type == "stdio":
            cmd_array = [str(t.command or "npx"), *[str(a) for a in t.args]]
            entry: Dict[str, Any] = {
                "type": "local",
                "command": cmd_array,
                "enabled": True,
            }
            if t.cwd:
                entry["cwd"] = t.cwd
            if t.env:
                # Convert ${VAR} to OpenCode {env:VAR} syntax so secrets are never written as literals
                env_map: Dict[str, str] = {}
                for k, v in t.env.items():
                    m = re.match(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$", str(v))
                    env_map[k] = f"{{env:{m.group(1)}}}" if m else str(v)
                entry["environment"] = env_map
        elif t.transport_type in ("http", "sse", "remote"):
            entry = {
                "type": "remote",
                "url": str(t.url or ""),
                "enabled": True,
            }
            if t.headers:
                entry["headers"] = dict(t.headers)
            if t.auth_type == "oauth":
                entry["oauth"] = dict(t.oauth_config) if t.oauth_config else {}
            elif t.auth_type == "api_key":
                entry["oauth"] = False
        else:
            raise ValueError(f"Unsupported MCP transport type '{t.transport_type}' for OpenCode")

        mcp_block[record.name] = entry
        if lazy_disable_globally:
            tools_block = cfg_data.setdefault("tools", {})
            tools_block[f"{record.name}_*"] = False

        new_text = dump_jsonc(cfg_data, comments)
        writes = [{"path": str(cfg_path), "content": new_text, "exists_before": cfg_path.exists()}]
        diff = compute_unified_diff(old_text, new_text, cfg_path.name)
        return writes, diff, unpreserved

    def verify_installation(self, extension_name: str, extension_type: str, scope: str = "project") -> Dict[str, Any]:
        if extension_type == ExtensionType.SKILL.value:
            skill_md = self._skills_dir(scope) / extension_name / "SKILL.md"
            if not skill_md.is_file():
                return {"discoverable": False, "reason": f"Missing {skill_md}"}
            fm, _ = parse_skill_md(skill_md.read_text(encoding="utf-8-sig"))
            if fm.get("name") != extension_name or not fm.get("description"):
                return {"discoverable": False, "reason": "SKILL.md frontmatter missing matching name or description"}
            return {"discoverable": True, "path": str(skill_md), "client": self.CLIENT_ID, "scope": scope}

        if extension_type == ExtensionType.AGENT.value:
            agent_md = self._agents_dir(scope) / f"{extension_name}.md"
            if not agent_md.is_file():
                return {"discoverable": False, "reason": f"Missing {agent_md}"}
            fm, _ = parse_skill_md(agent_md.read_text(encoding="utf-8-sig"))
            if not fm.get("description"):
                return {"discoverable": False, "reason": "OpenCode agent markdown requires 'description' in frontmatter"}
            return {"discoverable": True, "path": str(agent_md), "client": self.CLIENT_ID, "scope": scope}

        if extension_type == ExtensionType.MCP_SERVER.value:
            cfg_path = self._config_path(scope)
            if not cfg_path.is_file():
                return {"discoverable": False, "reason": f"Missing {cfg_path}"}
            data, _ = parse_jsonc(cfg_path.read_text(encoding="utf-8-sig"))
            mcp_entry = (data.get("mcp") or {}).get(extension_name)
            if not isinstance(mcp_entry, dict):
                return {"discoverable": False, "reason": f"MCP server '{extension_name}' not found under 'mcp' key"}
            if mcp_entry.get("type") not in ("local", "remote"):
                return {"discoverable": False, "reason": "Invalid OpenCode MCP type (must be 'local' or 'remote')"}
            return {"discoverable": True, "path": str(cfg_path), "client": self.CLIENT_ID, "scope": scope, "entry": mcp_entry}

        return {"discoverable": False, "reason": f"Unknown extension_type {extension_type}"}


class ClaudeCodeAdapter(ClientAdapter):
    """Native adapter for Claude Code (https://code.claude.com/docs/).

    Supported paths:
    - Project skills: `.claude/skills/<name>/SKILL.md`
    - User skills: `~/.claude/skills/<name>/SKILL.md`
    - Project subagents: `.claude/agents/<name>.md`
    - User subagents: `~/.claude/agents/<name>.md`
    - Project MCP config: `<project>/.mcp.json` (`mcpServers` key)
    - User MCP config: `~/.claude.json` (`mcpServers` key)
    - Hooks config: `.claude/settings.json` or `~/.claude/settings.json`
    """

    CLIENT_ID = "claude-code"

    def _skills_dir(self, scope: str) -> Path:
        if scope == "user":
            return self.user_home / ".claude" / "skills"
        return self.project_root / ".claude" / "skills"

    def _agents_dir(self, scope: str) -> Path:
        if scope == "user":
            return self.user_home / ".claude" / "agents"
        return self.project_root / ".claude" / "agents"

    def _mcp_config_path(self, scope: str) -> Path:
        if scope == "user":
            return self.user_home / ".claude.json"
        return self.project_root / ".mcp.json"

    def _settings_path(self, scope: str) -> Path:
        if scope == "user":
            return self.user_home / ".claude" / "settings.json"
        return self.project_root / ".claude" / "settings.json"

    def detect(self) -> Dict[str, Any]:
        exe = shutil.which("claude")
        return {
            "client": self.CLIENT_ID,
            "executable_found": exe is not None,
            "executable_path": exe,
            "user_mcp_config_exists": self._mcp_config_path("user").exists(),
            "project_mcp_config_exists": self._mcp_config_path("project").exists(),
            "user_skills_dir": str(self._skills_dir("user")),
            "project_skills_dir": str(self._skills_dir("project")),
            "supported_formats": ["SKILL.md", ".mcp.json", "~/.claude.json", ".claude/agents/*.md", ".claude/settings.json"],
        }

    def plan_skill_install(self, bundle: ExtensionBundle, scope: str = "project") -> Tuple[List[Dict[str, Any]], str, List[str]]:
        safe_name = validate_skill_name(bundle.name)
        if safe_name.lower() in CLAUDE_RESERVED_NAMES or safe_name.lower().startswith("anthropic-skills:"):
            raise ValueError(
                f"Skill name '{safe_name}' is reserved by Claude Code for claude.ai synced skills and will not load."
            )
        target_dir = self._skills_dir(scope) / safe_name
        writes: List[Dict[str, Any]] = []
        diffs: List[str] = []
        unpreserved: List[str] = []

        for rel_path, content in sorted(bundle.files.items()):
            safe_rel = validate_bundle_rel_path(rel_path)
            dest = target_dir / safe_rel
            text = content.decode("utf-8-sig", errors="replace") if isinstance(content, bytes) else content
            if safe_rel == "SKILL.md":
                fm, _ = parse_skill_md(text)
                meta = fm.get("metadata") if isinstance(fm.get("metadata"), dict) else {}
                if "opencode/slash" in meta or "opencode/autoinvoke" in meta:
                    unpreserved.append("metadata.opencode/* (OpenCode-specific metadata; Claude Code uses disable-model-invocation)")
            old_text = dest.read_text(encoding="utf-8", errors="replace") if dest.exists() else ""
            writes.append({"path": str(dest), "content": text, "exists_before": dest.exists()})
            diffs.append(compute_unified_diff(old_text, text, f".claude/skills/{safe_name}/{safe_rel}"))

        return writes, "\n".join(diffs), unpreserved

    def plan_agent_install(self, bundle: ExtensionBundle, scope: str = "project") -> Tuple[List[Dict[str, Any]], str, List[str]]:
        safe_name = validate_skill_name(bundle.name)
        dest = self._agents_dir(scope) / f"{safe_name}.md"
        raw_md = bundle.files.get("SKILL.md") or bundle.files.get(f"{safe_name}.md") or ""
        text = raw_md.decode("utf-8-sig", errors="replace") if isinstance(raw_md, bytes) else str(raw_md)
        fm, body = parse_skill_md(text)
        unpreserved: List[str] = []

        claude_fm: Dict[str, Any] = {
            "name": safe_name,
            "description": str(fm.get("description") or f"Claude Code subagent {safe_name}")[:500],
        }
        if fm.get("tools") and isinstance(fm["tools"], (list, str)):
            claude_fm["tools"] = fm["tools"]
        if fm.get("disallowedTools"):
            claude_fm["disallowedTools"] = fm["disallowedTools"]
        elif isinstance(fm.get("permission"), dict):
            # Convert OpenCode permission block to Claude Code disallowedTools
            disallowed: List[str] = []
            for k, v in fm["permission"].items():
                if v == "deny":
                    if k == "edit":
                        disallowed.extend(["Edit", "Write"])
                    elif k == "bash":
                        disallowed.append("Bash")
                    elif k == "webfetch":
                        disallowed.append("WebFetch")
            if disallowed:
                claude_fm["disallowedTools"] = disallowed

        if fm.get("model"):
            claude_fm["model"] = str(fm["model"])
        if fm.get("isolation"):
            claude_fm["isolation"] = str(fm["isolation"])

        for oc_key in ("steps", "temperature", "top_p", "color", "hidden"):
            if oc_key in fm:
                unpreserved.append(f"agent.{oc_key} (OpenCode agent option not supported in Claude Code subagent frontmatter)")

        converted_text = "---\n" + yaml.safe_dump(claude_fm, sort_keys=False).strip() + "\n---\n\n" + body
        old_text = dest.read_text(encoding="utf-8", errors="replace") if dest.exists() else ""
        writes = [{"path": str(dest), "content": converted_text, "exists_before": dest.exists()}]
        diff = compute_unified_diff(old_text, converted_text, f".claude/agents/{safe_name}.md")
        return writes, diff, unpreserved

    def plan_mcp_install(
        self,
        record: ExtensionRecord,
        scope: str = "project",
        *,
        lazy_disable_globally: bool = False,
    ) -> Tuple[List[Dict[str, Any]], str, List[str]]:
        if record.name.lower() == "anthropic-skills":
            raise ValueError("MCP server name 'anthropic-skills' is reserved by Claude Code.")
        cfg_path = self._mcp_config_path(scope)
        old_text = cfg_path.read_text(encoding="utf-8-sig") if cfg_path.exists() else ""
        cfg_data = json.loads(old_text) if old_text.strip() else {}
        if not isinstance(cfg_data, dict):
            cfg_data = {}

        mcp_servers = cfg_data.setdefault("mcpServers", {})
        unpreserved: List[str] = []
        t = record.mcp_transport or MCPTransportSpec(transport_type="stdio", command="npx", args=["-y", record.name])

        if t.transport_type == "stdio":
            entry: Dict[str, Any] = {
                "type": "stdio",
                "command": str(t.command or "npx"),
                "args": [str(a) for a in t.args],
            }
            if t.env:
                entry["env"] = {str(k): str(v) for k, v in t.env.items()}
        elif t.transport_type in ("http", "sse", "remote"):
            entry = {
                "type": "http" if t.transport_type == "remote" else t.transport_type,
                "url": str(t.url or ""),
            }
            if t.headers:
                entry["headers"] = dict(t.headers)
        else:
            raise ValueError(f"Unsupported MCP transport type '{t.transport_type}' for Claude Code")

        mcp_servers[record.name] = entry
        new_text = json.dumps(cfg_data, indent=2, ensure_ascii=False) + "\n"
        writes = [{"path": str(cfg_path), "content": new_text, "exists_before": cfg_path.exists()}]
        diff = compute_unified_diff(old_text, new_text, cfg_path.name)
        return writes, diff, unpreserved

    def build_claude_mcp_cli_command(self, record: ExtensionRecord, scope: str = "project") -> List[str]:
        """Return the official `claude mcp add` command array for reference or live execution."""
        t = record.mcp_transport or MCPTransportSpec(transport_type="stdio", command="npx", args=["-y", record.name])
        if t.transport_type in ("http", "sse", "remote"):
            return ["claude", "mcp", "add", "--scope", scope, "--transport", "http", record.name, str(t.url or "")]
        cmd = ["claude", "mcp", "add", "--scope", scope, record.name, "--", str(t.command or "npx"), *[str(a) for a in t.args]]
        return cmd

    def verify_installation(self, extension_name: str, extension_type: str, scope: str = "project") -> Dict[str, Any]:
        if extension_type == ExtensionType.SKILL.value:
            skill_md = self._skills_dir(scope) / extension_name / "SKILL.md"
            if not skill_md.is_file():
                return {"discoverable": False, "reason": f"Missing {skill_md}"}
            fm, _ = parse_skill_md(skill_md.read_text(encoding="utf-8-sig"))
            if not fm.get("description"):
                return {"discoverable": False, "reason": "SKILL.md missing description in frontmatter"}
            return {"discoverable": True, "path": str(skill_md), "client": self.CLIENT_ID, "scope": scope}

        if extension_type == ExtensionType.AGENT.value:
            agent_md = self._agents_dir(scope) / f"{extension_name}.md"
            if not agent_md.is_file():
                return {"discoverable": False, "reason": f"Missing {agent_md}"}
            fm, _ = parse_skill_md(agent_md.read_text(encoding="utf-8-sig"))
            if not fm.get("description"):
                return {"discoverable": False, "reason": "Claude subagent missing description"}
            return {"discoverable": True, "path": str(agent_md), "client": self.CLIENT_ID, "scope": scope}

        if extension_type == ExtensionType.MCP_SERVER.value:
            cfg_path = self._mcp_config_path(scope)
            if not cfg_path.is_file():
                return {"discoverable": False, "reason": f"Missing {cfg_path}"}
            data = json.loads(cfg_path.read_text(encoding="utf-8-sig"))
            mcp_entry = (data.get("mcpServers") or {}).get(extension_name)
            if not isinstance(mcp_entry, dict):
                return {"discoverable": False, "reason": f"MCP server '{extension_name}' not found in mcpServers"}
            return {"discoverable": True, "path": str(cfg_path), "client": self.CLIENT_ID, "scope": scope, "entry": mcp_entry}

        return {"discoverable": False, "reason": f"Unknown extension_type {extension_type}"}
