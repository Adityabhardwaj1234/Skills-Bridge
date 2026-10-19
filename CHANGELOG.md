# Changelog (`CHANGELOG.md`)

All notable changes to **SkillBridge** are documented in this file.

## [2.0.0] - 2026-10-19

### Added
- **Multi-Tier Verification Pipeline (`src/skillbridge/verification/`)**:
  - **Tier 0 (`BundleStager`)**: Whole-directory immutable quarantine staging, SHA-256 tree digesting, symlink/traversal/archive guards, script discovery, and static dependency manifest parsing.
  - **Tier 1 (`SkillSpectorAdapter` & `tier1_skillspector.py`)**: Subprocess CLI adapter and Apache-2.0 Python 3.11 engine supporting static patterns, Python AST & lexical-scope taint tracking (`TT1`–`TT6`), callable alias resolution (`BA1_ALIAS_SHELL_EXEC`), newline-split instruction reconstruction (`AE6`), Unicode confusables (`UC1`), MCP least-privilege (`LP1_WILDCARD_GRANT`), and inspection ledger completeness accounting.
  - **Tier 2 (`SKILAdapter` & `tier2_skil.py`)**: Subprocess CLI adapter and Apache-2.0 engine implementing declared-vs-observed capability verification and deterministic SHA-256 `AssuranceClosure` graphs (`SAFE`, `UNSAFE`, `UNKNOWN`).
  - **Tier 3 (`SkillEvaluatorAdapter` & `tier3_evaluator.py`)**: Subprocess CLI adapter and Apache-2.0 engine reusing Tier 1 SkillSpector evidence (zero duplicate scans) for structural quality rubric scoring, intra-skill section redundancy detection, and inter-skill catalog similarity checks.
  - **Optional External Adapter (`OptionalSkillFortifyAdapter`)**: Disabled-by-default external CLI wrapper for independently installed `skillfortify` binaries, maintaining strict Elastic License 2.0 separation (zero vendored code or benchmark files).
- **13-State Skill Bundle Import Lifecycle (`ImportState`)**: Full state machine from `DISCOVERED` through `FETCHED_INTO_QUARANTINE`, `TIERED_VERIFICATION`, `APPROVED_BY_POLICY`, `STAGED_TEMPORARILY`, `LOADED_INTO_ACTIVE_SESSION`, `USED` / `SCRIPT_EXECUTED_IF_ALLOWED`, `UNLOADED`, `TEMPORARY_FILES_REMOVED`, and `METADATA_AND_RESULTS_RETAINED`, with mid-import rollback and persistent recall (`recall_skill_metadata`).
- **Active Capacity (25 Skills) & 250 MiB Memory-Pressure Eviction (`src/skillbridge/runtime/memory.py`)**:
  - Enforces a configurable `active_skill_limit = 25` and `memory_threshold_mib = 250.0` with automatic LRU batch eviction (`5–10` skills, default `7`) down to the `210.0 MiB` lower watermark while protecting `pinned` and `in_use` skills.
  - Includes both `SystemMemoryProvider` (real OS RSS + child process tree) and `FakeMemoryProvider` for deterministic threshold testing.
- **Controlled Script Execution (`ScriptExecutionManager`)**: Executes permitted bundled scripts in a secret-stripped, socket-guarded subprocess worker (`run-script` CLI and `run_skill_script` MCP tool) with pre-execution TOCTOU digest checks and process-group timeout cleanup.
- **Parallel Asyncio Orchestrator & 19-Tool MCP Broker (`src/skillbridge/orchestration/scheduler.py` & `mcp_server/server.py`)**: Topological DAG task scheduling, per-provider/per-MCP semaphores, idempotency key deduplication, circuit breakers, and all 19 canonical v2 MCP broker operations.
- **Brand Identity & Flagship Console (`assets/brand/` & `reports/dashboard.html`)**: 5 original SVG brand assets, graphite/deep-navy UI theme, CycloneDX 1.6 SBOM generator (`reports/sbom.cdx.json`), 52-scenario evaluation benchmark (`reports/eval_report.json`), and scaling/memory performance report (`reports/performance_report.json`).

### Production hardening (post-build)
- **Parallel batch loading**: `SkillRuntimeLoader.load_skills_parallel` (bounded worker pool, default 8), CLI `load-batch`, MCP `load_skills_batch` / `skillbridge_load_skills_batch`, and batch loading in preflight (auto and deferred paths).
- **Raised payload limits**: 4 MB/file, 32 MB per loaded bundle, 100 references, depth 6, 128 MB HTTP response cap; staged bundle limits raised to 5,000 files / 256 MB total / 8 MB single file / depth 12.
- **Security policy override**: builtin DANGEROUS bundles may load only with explicit operator approval while `allow_builtin_dangerous_override` is enabled; community/untrusted DANGEROUS remains permanently blocked. Ranking and loader gates now honor the same rule.
- **Runnable helper imports**: when references are auto-discovered from `SKILL.md`, local Python/JS helper modules imported by loaded scripts (for example `scripts/_raster.py`) are recursively included within the same byte/reference/depth budgets.
- **Actionable load errors**: remote index-only records now return provider-specific errors that distinguish offline mode from stale/unreachable remote bundles.
- **ClawHub reliability**: search uses the `/search` API with owner/install-reference parsing; bundle downloads use `/download?slug=…&ownerHandle=…` with a legacy fallback; ZIP extraction enforces a total uncompressed size cap in addition to per-file caps.
- **Provider coverage**: added the Smithery MCP registry provider (hosted HTTP and stdio transports); browse.sh now participates in the parallel round-robin live search merge alongside skills.sh and ClawHub.
- **Catalog performance**: FTS5 maintenance now deletes/reinserts by `rowid` (schema v2 migration realigns existing databases), eliminating O(n²) catalog seeding.
- **Enforcement fixes**: deferred skill loading now runs before `assert_can_execute`, so `preflight --no-load` followed by protected execution works; `catalog_seed` audit events are only recorded on actual catalog changes or forced rescans.
- **Cross-platform runtime**: guarded POSIX-only `resource` import and a Win32 working-set measurement fallback; Windows memory telemetry works without `psutil`.
- **Product console**: new `skillbridge ui` command renders and optionally serves a self-contained live-state HTML console (`src/skillbridge/reporting/ui.py`).
- **Documentation and packaging**: added `README.md`, `MANIFEST.in`, version alignment at 2.0.0, and parity regression tests (`tests/unit/test_v2_parity_fixes.py`).

### Migration from v1.0.0 to v2.0.0
- Existing v1 SQLite databases (`~/.skillbridge/skillbridge.db`), CLI commands (`verify`, `scan`, `search-skills`, `preview-skill`, `preflight`, `load-skill`, `unload-skill`, `install`, `rollback`, `evaluate`, `report`, `mcp-serve`), and MCP `skillbridge_*` tool names remain backward compatible; the v2 schema migration realigns FTS5 rowids in place on first open.
- New v2 settings (`~/.skillbridge/settings.json`) are created automatically on first run.

## [1.0.0] - 2026-10-19

### Added
- Initial release of SkillBridge with Hermes 100k+ Skills Hub discovery, 732 bundled Hermes skills and 70 MCP servers, SQLite + FTS5 catalog, mandatory preflight state machine, static + AST security scanner, OpenCode & Claude Code adapters, and stdio MCP server.
