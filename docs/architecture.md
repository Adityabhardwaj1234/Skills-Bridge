# SkillBridge Architecture & Engineering Design

## 1. High-Level System Overview

SkillBridge is architected as a modular Python 3.10+ package (`src/skillbridge/`) with zero mandatory external services, a resilient SQLite + FTS5 catalog and telemetry store, a strict 10-state task preflight state machine, a non-executing candidate inspector and security scanner, a session-isolated runtime loader, native client configuration adapters, and a JSON-RPC 2.0 `stdio` MCP server.

```
USER_REQUEST / AGENT_TASK
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 1. Mandatory Preflight Gate (enforcement/state_machine.py & preflight.py)│
│    INITIALIZED -> PREFLIGHT -> SEARCHING -> PREVIEWING -> COMPARING     │
│    -> SELECTING -> [LOADING] -> EXECUTING -> VERIFYING -> RELEASED      │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         ▼                         ▼                         ▼
┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐
│ 2. Discovery Engine │  │ 3. Preview & AST    │  │ 4. 6-Factor Ranker  │
│ (discovery/ &       │  │ Security Pipeline   │  │ (ranking/scorer.py) │
│  providers/)        │  │ (preview/ &         │  │Relevance + TokenGate│
│ • Local Directories │  │  security/)         │  │+ Quality + Compat   │
│ • Hermes 100k+ Hub  │  │ • 60+ Regex Rules   │  │+ Security + History │
│ • Skills.sh/ClawHub │  │ • Python AST Audit  │  │+ Prov/Popularity    │
│ • LobeHub/Browse.sh │  │ • MCP IOC & Egress  │  │+ Redundancy Filter  │
│ • GitHub & WellKnown│  │ • QuarantineVault   │  └──────────┬──────────┘
│ • MCP Registry v0   │  └──────────┬──────────┘             │
└──────────┬──────────┘             │                        │
           └────────────────────────┼────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 5. Persistent Intelligence Catalog (cache/database.py - SQLite + FTS5)  │
│    extensions | extensions_fts | security_scans | preflight_records     │
│    outcomes (learning) | trust_overrides | install_plans | audit_logs   │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   │
         ┌─────────────────────────┴─────────────────────────┐
         ▼                                                   ▼
┌────────────────────────────────────┐     ┌──────────────────────────────┐
│ 6. Runtime Skill Loader            │     │ 7. Native Client Adapters    │
│ (runtime/loader.py)                │     │ (adapters/ & installers/)    │
│ • On-demand SKILL.md + refs        │     │ • OpenCode (JSONC preserving)│
│ • Path escape & byte limits        │     │ • Claude Code (.mcp.json &   │
│ • Content-hash invalidation        │     │   subagents frontmatter)     │
│ • Session dedup stubs              │     │ • Atomic backups & rollback  │
│ • Guaranteed finally-block unload  │     │ • Protocol MCP stdio server  │
└────────────────────────────────────┘     └──────────────────────────────┘
```

---

## 2. Module Responsibilities

| Module | File Path | Core Responsibilities |
| :--- | :--- | :--- |
| **Models** | `src/skillbridge/models.py` | Immutable/typed dataclasses (`ExtensionRecord`, `SecurityReport`, `SecurityFinding`, `CandidatePreview`, `ComparisonScore`, `PreflightRecord`, `LoadedSkillPayload`, `InstallationPlan`, `OutcomeRecord`, `AuditLogEntry`) and enums (`ExtensionType`, `SecurityVerdict`, `TrustLevel`, `TaskState`, `ClientTarget`, `TransportType`). |
| **Configuration** | `src/skillbridge/config.py` | Cross-platform path detection (Linux, macOS, Windows PowerShell/CMD), environment inspection (`detect_environment()`), configurable byte/reference/context caps, and client path resolution. |
| **Database & Cache** | `src/skillbridge/cache/database.py` | Resilient SQLite + FTS5 storage (`CatalogDatabase`), content-hash scan caching, outcome learning telemetry (`get_outcome_stats`), trust overrides, installation plan persistence, and secret-redacted audit logging. Includes automatic fallback for virtualized `9p`/gVisor filesystems. |
| **Discovery & Normalizer** | `src/skillbridge/discovery/normalizer.py`, `engine.py` | YAML frontmatter parser with safe fallback, skill ID validation, URL/repo alias normalization, SSRF target blocking, symmetric SHA-256 content hashing, parallel multi-provider querying (`ThreadPoolExecutor`), and deduplication across sources. |
| **Source Providers** | `src/skillbridge/providers/local.py`, `hermes_hub.py`, `remote.py` | Isolated `ExtensionProvider` implementations for local directories, Hermes 732-skill bundled/optional catalog + 70 MCPs, Hermes centralized 100k+ index API, `skills.sh`, `clawhub.ai` (with zip-slip/bomb protection), `lobehub`, `browse.sh`, GitHub API, `/.well-known/skills/`, and Official MCP Registry `/v0/servers`. |
| **Security Scanner** | `src/skillbridge/security/scanner.py`, `ast_audit.py`, `policy.py` | 60+ static regex signatures across 12 threat categories, MCP malicious package IOC blocklist, deep Python `ast.NodeVisitor` taint/call analysis, context-aware false-positive demotion, `SAFE`/`CAUTION`/`DANGEROUS`/`UNKNOWN` policy evaluator, and `QuarantineManager`. |
| **Preview Inspector** | `src/skillbridge/preview/inspector.py` | Non-executing inspection of `SKILL.md` frontmatter/body, supporting reference files, script inventories, dependency manifests, and estimated token cost (`chars // 4`). |
| **Candidate Ranker** | `src/skillbridge/ranking/scorer.py` | Deterministic 6-factor explainable scoring engine with query token coverage gating, historical outcome boost/penalty, and Jaccard redundancy filtering for multi-skill selection. |
| **Enforcement & Preflight** | `src/skillbridge/enforcement/state_machine.py`, `preflight.py` | Strict `TaskLifecycleStateMachine` enforcing legal state transitions and `PreflightOrchestrator.execute_protected_task` blocking unverified execution (`PreflightBypassError`). |
| **Runtime Loader** | `src/skillbridge/runtime/loader.py` | Just-in-time loader with relative reference containment, file/total byte limits, content-hash change detection, session deduplication stubs, explicit `unload_skill`/`unload_session`, and `@contextmanager temporary_skill_scope`. |
| **Client Adapters & Installer** | `src/skillbridge/adapters/clients.py`, `installers/planner.py` | `OpenCodeAdapter` (JSONC comment-preserving parser/merger, agent markdown conversion) and `ClaudeCodeAdapter` (`.mcp.json`/`~/.claude.json`, reserved skill name guard, subagent YAML converter), `DependencyInspector`, and `InstallationManager` with atomic writes and backups. |
| **MCP Server & Client** | `src/skillbridge/mcp_server/server.py` | Protocol-compliant JSON-RPC 2.0 `stdio` server (`SkillBridgeMCPServer`) exposing 9 tools and `MCPStdioClient` for real subprocess protocol verification. |
| **Evaluation & Reporting** | `src/skillbridge/evaluation/runner.py`, `reporting/generator.py` | 35-scenario evaluation runner computing Hit@1, Hit@3, lexical baseline comparison, NO_MATCH accuracy, security precision/false-positive rates, and generating `eval_report.json` + `dashboard.html`. |

---

## 3. State Separation & Memory Lifecycle

SkillBridge strictly separates extension state into three tiers:

1. **Persistent Catalog State (SQLite Database)**:
   - Stores lightweight `ExtensionRecord` metadata, content SHA-256 hashes, `SecurityReport` verdicts, `PreflightRecord` decision trails, and `OutcomeRecord` pass/fail counters.
   - Never stores raw user secrets, environment variables, or full transient skill instruction payloads by default.
2. **Optional Persistent Native Installation**:
   - Occurs **only** when explicitly requested via `plan_install()` + `apply_install()` with security policy approval.
   - Writes files into the target client's verified directory (`.opencode/skills/`, `.claude/skills/`, `opencode.jsonc`, `.mcp.json`) with a full `.bak` backup stored in `~/.skillbridge/backups/<plan_id>/`.
3. **Temporary Runtime Loading (`SkillRuntimeLoader`)**:
   - Holds `LoadedSkillPayload` objects in process memory under `_active_sessions[session_id][skill_id]`.
   - Enforces `max_file_size_bytes` (default 4 MB), `max_total_bytes` (default 32 MB), `max_references` (default 100), `max_nesting_depth` (default 6), and a bounded `max_parallel_workers` pool (default 8).
   - If the same skill is requested a second time within the same `session_id` with an unchanged `content_hash`, returns a lightweight deduplication stub (`already_loaded_in_session=True`) rather than duplicating tokens.
   - If the underlying file is modified on disk (`current_hash != cached_hash`), automatically invalidates the cached security scan and forces a fresh scan before loading; if the new scan returns `DANGEROUS`, loading is immediately blocked and the file is quarantined.
   - Releases all references via `unload_skill(session_id, skill_id)` or `unload_session(session_id)` inside `finally` blocks, clearing dictionaries and invoking `gc.collect()`.
