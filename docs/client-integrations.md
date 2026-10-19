# Native Client Integrations: OpenCode & Claude Code

SkillBridge provides dedicated, verified adapters (`src/skillbridge/adapters/clients.py`) and an atomic installation manager (`src/skillbridge/installers/planner.py`) for **OpenCode** and **Claude Code**, alongside Hermes Agent compatibility.

---

## 1. OpenCode Integration (`OpenCodeAdapter`)

### Official Documentation Verified
- [OpenCode Agent Skills](https://opencode.ai/docs/skills/)
- [OpenCode Custom Agents](https://opencode.ai/docs/agents/)
- [OpenCode MCP Servers](https://opencode.ai/docs/mcp-servers/)
- [OpenCode Configuration (`opencode.jsonc`)](https://opencode.ai/docs/config/)

### Verified Paths & Schemas
| Extension Type | Project Scope Path | User (Global) Scope Path | Format & Adapter Behavior |
| :--- | :--- | :--- | :--- |
| **Skills** | `.opencode/skills/<name>/SKILL.md` (also supports `.agents/skills/<name>/SKILL.md`) | `~/.config/opencode/skills/<name>/SKILL.md` (also supports `~/.agents/skills/<name>/SKILL.md`) | Validates slug `^[a-z0-9]+(-[a-z0-9]+)*$` (1–64 chars), ensures `name` matches directory name, and copies `SKILL.md` + verified references. |
| **Agents** | `.opencode/agents/<name>.md` | `~/.config/opencode/agents/<name>.md` | Converts agent/skill manifests into OpenCode markdown with YAML frontmatter (`description`, `mode: subagent`, `tools: <bool map>`, `permission: <ask/allow/deny map>`). Reports unsupported fields explicitly. |
| **MCP Servers** | `opencode.jsonc` or `opencode.json` | `~/.config/opencode/opencode.jsonc` | Merges into top-level `"mcp"` key using `"type": "local"` (`"command": [...]`, `"environment": {...}`, `"enabled": true`) or `"type": "remote"` (`"url": "..."`, `"headers": {...}`). Preserves existing `//` and `/* */` JSONC comments and unrelated keys. |

### CLI Commands for OpenCode
```powershell
# Preview installation plan (dry-run, zero files modified)
python -m skillbridge --offline install --target opencode --scope project --dry-run "hermes-bundled:skills/github/github-pr-workflow"

# Apply installation with backup and post-install verification
python -m skillbridge --offline install --target opencode --scope project --approve "hermes-bundled:skills/github/github-pr-workflow"
```

---

## 2. Claude Code Integration (`ClaudeCodeAdapter`)

### Official Documentation Verified
- [Claude Code Skills](https://code.claude.com/docs/en/skills)
- [Claude Code Subagents](https://code.claude.com/docs/en/sub-agents)
- [Claude Code MCP Configuration](https://code.claude.com/docs/en/mcp) & [MCP Quickstart](https://code.claude.com/docs/en/mcp-quickstart)
- [Claude Code Hooks Guide](https://code.claude.com/docs/en/hooks-guide) & [Hooks Reference](https://code.claude.com/docs/en/hooks)

### Verified Paths & Schemas
| Extension Type | Project Scope Path | User (Global) Scope Path | Format & Adapter Behavior |
| :--- | :--- | :--- | :--- |
| **Skills** | `.claude/skills/<name>/SKILL.md` | `~/.claude/skills/<name>/SKILL.md` | Enforces Claude Code reserved word rules (`name` cannot contain `"anthropic"` or `"claude"`), strips XML tags from `name`/`description`, and preserves `allowed-tools` frontmatter. |
| **Subagents** | `.claude/agents/<name>.md` | `~/.claude/agents/<name>.md` | Converts agent definitions to Claude Code subagent format (`name`, `description`, `tools: Read, Grep, Glob, Bash`, `model: inherit`). |
| **MCP Servers** | `.mcp.json` | `~/.claude.json` | Merges into `"mcpServers"` object with `"type": "stdio"` (`"command": "<bin>", "args": [...], "env": {...}`) or `"type": "http"` / `"sse"` (`"url": "..."`). Also outputs equivalent `claude mcp add` CLI commands. |

### Mandatory Preflight Enforcement via Claude Code Hooks
Claude Code supports deterministic lifecycle hooks in `.claude/settings.json` ([Claude Code Hooks](https://code.claude.com/docs/en/hooks)). To enforce SkillBridge preflight before every prompt in Claude Code, add a `UserPromptSubmit` hook:
```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python -m skillbridge preflight \"Task from Claude Code session\""
          }
        ]
      }
    ]
  }
}
```

---

## 3. Registering SkillBridge as an MCP Server

Installing SkillBridge itself as an MCP server is distinct from installing third-party MCP servers. SkillBridge provides a native JSON-RPC 2.0 `stdio` server (`python -m skillbridge mcp-serve`) that exposes 9 tools to any connected coding agent:
- `skillbridge_preflight`: Run mandatory task discovery, preview, security scan, and ranking.
- `skillbridge_search_skills`: Search local and remote skill catalogs.
- `skillbridge_preview_skill`: Non-executing preview of a candidate skill.
- `skillbridge_load_skill`: Load a verified skill just-in-time for a session.
- `skillbridge_unload_skill`: Explicitly release loaded skill references from runtime memory.
- `skillbridge_search_mcp`: Search MCP servers from the Official MCP Registry and catalog.
- `skillbridge_scan_path`: Run the 4-layer security scanner on a local path.
- `skillbridge_plan_install`: Create a dry-run native client installation plan.
- `skillbridge_record_outcome`: Record verified task pass/fail outcomes to improve future ranking.

### Register in OpenCode (`opencode.jsonc`)
```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "skillbridge": {
      "type": "local",
      "command": ["python", "-m", "skillbridge", "mcp-serve"],
      "enabled": true
    }
  }
}
```

### Register in Claude Code (`.mcp.json` or CLI)
```powershell
claude mcp add --transport stdio skillbridge -- python -m skillbridge mcp-serve
```

---

## 4. Transactional Safety, Backups & Rollback

Every `apply_install()` operation in `InstallationManager` (`src/skillbridge/installers/planner.py`):
1. Re-verifies the target extension's security verdict (`DANGEROUS` extensions are blocked even if `approve=True`).
2. Checks whether custom files would be overwritten (`overwrite_existing=False` by default prevents accidental overwrites of user-authored skills).
3. Saves exact snapshots of any existing files or config manifests into `~/.skillbridge/backups/<plan_id>/backup_manifest.json`.
4. Performs atomic file writes via temporary `.tmp.<pid>` files and `os.replace()`.
5. Validates the resulting configuration via `adapter.verify_installed()`.
6. Supports full transactional rollback (`bridge.rollback_install(plan_id)`) which restores modified files from backup and removes newly created skill directories.
