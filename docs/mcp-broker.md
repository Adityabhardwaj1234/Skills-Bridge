# SkillBridge MCP Broker Specification (`docs/mcp-broker.md`)

## 1. Broker Design Philosophy

Instead of registering hundreds of permanent model-visible tools for every discovered skill or third-party MCP server (which bloats the LLM tool schema and degrades tool selection), SkillBridge exposes **one stable JSON-RPC 2.0 `stdio` MCP Broker** (`python -m skillbridge mcp-serve`, implemented in `src/skillbridge/mcp_server/server.py`).

## 2. Exposed Broker Operations (19 Canonical Tools)

| Tool Name | Required Arguments | Purpose & Validation |
| :--- | :--- | :--- |
| `search_skills` | `query` (`limit`, `source_filter`) | Searches SQLite FTS5 catalog and configured skill providers; returns compact summaries. |
| `preview_skill` | `skill_id` (`target_client`) | Non-executing preview of `SKILL.md`, references, scripts, dependencies, and security verdict. |
| `compare_skills` | `skill_ids[]` (`query`, `target_client`) | Side-by-side suitability comparison and multi-skill capability overlap/conflict check. |
| `import_skill` | `skill_id` (`session_id`, `pin`, `approved`) | Runs the 13-state Tier 0–3 verification pipeline and stages the bundle into active runtime. |
| `import_directory` | `directory` (`session_id`, `pin`, `approved`) | Imports an entire local skill directory (every nested file) through Tier 0–3 by filesystem path. |
| `load_skill` | `skill_id` (`session_id`, `include_references`, `approved`) | Loads a verified skill's instructions and relative references into isolated session memory. |
| `load_skills_batch` | `skill_ids[]` (`session_id`, `approved`, `max_workers`) | Loads many verified skills concurrently with bounded workers and per-skill failure isolation. |
| `get_skill_status` | (`skill_id`) | Returns lifecycle state, bundle digest, assurance state, or recalled metadata after unload. |
| `invoke_skill` | `skill_id` (`session_id`) | Retrieves active skill instructions and updates its LRU access timestamp. |
| `run_skill_script` | `skill_id`, `relative_path` (`arguments`, `approved`) | Executes a permitted script inside an active bundle in a secret-stripped worker subprocess. |
| `unload_skill` | `skill_id` (`session_id`) | Releases runtime handles and deletes temporary bundle files while retaining recall metadata. |
| `search_mcp_servers` | `query` (`limit`) | Searches the Official MCP Registry, Smithery, and curated MCP catalog. |
| `preview_mcp_server` | `server_id` (`target_client`) | Previews MCP server transport, launch command, auth type, and missing dependencies. |
| `verify_mcp_server` | `server_id` | Audits MCP launch specification against malicious IOCs, shell injection, and least privilege. |
| `enable_mcp_server` | `server_id` (`approved`) | Verifies and enables an MCP server inside the broker (`DANGEROUS` servers are hard-blocked). |
| `disable_mcp_server` | `server_id` | Disables an active MCP server and cleans up broker routing state. |
| `call_mcp_tool` | `server_id`, `tool_name` (`arguments`) | Validates server activation and tool name safety before dispatching through `ParallelOrchestrator`. |
| `get_memory_status` | None | Returns process-tree RSS, 250 MiB threshold status, 25-skill active capacity, and eviction history. |
| `get_audit_report` | (`limit`) | Returns recent secret-redacted audit events, verification engine status, and scheduler stats. |

*(For backward compatibility, the broker also supports the v1 `skillbridge_*` tool aliases such as `skillbridge_preflight` and `skillbridge_plan_install`.)*

## 3. Confused-Deputy & Permission Guards

- An agent cannot pass an arbitrary shell command or unregistered endpoint to `call_mcp_tool` or `run_skill_script`.
- `call_mcp_tool` requires `server_id` to be registered in the catalog, verified by `verify_mcp_server`, and explicitly enabled via `enable_mcp_server`.
- `run_skill_script` requires `skill_id` to be actively imported with `AssuranceState.SAFE` and validates that `relative_path` resolves strictly inside the staged bundle directory.
