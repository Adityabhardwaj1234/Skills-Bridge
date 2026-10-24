# Changelog (`CHANGELOG.md`)

All notable changes to **SkillBridge** are documented in this file.

## [2.0.2] - 2026-10-24

Catalog durability and recovery patch.

### Fixed
- **Catalog durability**: the persistent SQLite catalog no longer uses `journal_mode=OFF` and `synchronous=OFF`. It now uses WAL with `synchronous=NORMAL` (or `DELETE`/`FULL` when WAL is unavailable), so a crash or interrupted schema/FTS migration cannot leave a half-written database image.
- **Startup integrity gate**: `CatalogDatabase` runs `PRAGMA quick_check` before schema writes and again after initialization. A damaged catalog raises `CatalogCorruptionError` with an actionable recovery command; it is no longer moved aside and replaced with an empty catalog that could later be silently reseeded. The damaged bytes remain untouched until an operator chooses recovery.
- **Row-preserving `repair-catalog`**: new CLI command backs up the catalog to `recovery-<timestamp>/`, copies only surviving base-table rows into a fresh schema, rebuilds all indexes and FTS5, verifies row counts, per-table content digests, and full `PRAGMA integrity_check`, then atomically swaps in the repaired file. `--dry-run` inspects without creating a backup or replacement; `--force` rebuilds an already-healthy catalog. The command never imports bundled/provider data, and does not promote stale index-only entries into invented records.
- **FTS/index damage handling**: corrupt FTS shadow tables and index entries are discarded and rebuilt from the authoritative table rows. A real damaged catalog containing 805 readable extension rows (with four corrupt indexes reporting 833 entries) was recovered with all 805 rows preserved; the original 9.6 MB file remains backed up byte-for-byte.
- **Clearer read-only reporting**: `--dry-run` and healthy-catalog output now show authoritative readable row counts, report FTS as `not evaluated`, and label data preservation as `yes (no writes)` instead of misleading zeros. Non-empty WAL sidecars are checkpointed before backup when no process holds them; otherwise repair stops rather than dropping the newest transactions. Files that are not SQLite databases are rejected without mutation, and a rebuilt catalog must checkpoint cleanly before the atomic swap.
- **Docs/version**: README, incident-recovery guide, CLI hint, and version updated to `2.0.2`. Documented that `verify`/`doctor` run discovery and can add local rows, so they are not read-only post-repair checks.

### Tests
- Added `tests/unit/test_catalog_recovery.py` (durable pragmas, forced rebuild, dry run/healthy reporting, stale-WAL checkpointing, non-SQLite rejection, no-seed row preservation, CLI command).
- Updated the corrupt-storage regression to assert non-mutation and explicit recovery rather than silent replacement.

## [2.0.1] - 2026-10-22

Security patch release based on an independent hostile red-team evaluation.

### Fixed
- **Scanner authorization failures**: AST findings now feed the verdict; added multi-line rules for Python socket→shell reverse shells, decoded `exec`, `powershell -EncodedCommand`/`FromBase64String`, keyboard-hook/keylogger APIs, `os.system`, dynamic `eval`/`exec`, and `subprocess(..., shell=True)`. Previously these could be rated SAFE and imported.
- **Filesystem containment**: Tier 0 now rejects NTFS junctions and hardlinks in addition to symlinks; every staged path is resolved and asserted inside the bundle root. In-memory bundle maps validate every key and reject Windows drive/UNC paths, traversal, device names, control characters, and case-colliding duplicates before writing.
- **SKILL.md traversal at import**: reference links are percent-decoded and validated component-by-component. `../` links now fail Tier 0 instead of being silently normalized; the 100-reference cap is enforced on import as well as load.
- **Cross-session unload**: `unload_skill` honors the requested `session_id`. One MCP client can no longer terminate another session's handle; staging is released only after the last session releases the skill.
- **Script runner resource bounds**: stdout/stderr are drained into fixed-size buffers instead of unbounded `communicate()` buffering; overflowing output is marked truncated. Timeouts terminate the full Windows process tree via `taskkill /T`.
- **SSRF guard**: decimal/octal/shorthand IPv4, IPv4-mapped IPv6, and NAT64 literals are normalized; every resolved A/AAAA is checked and non-public destinations are rejected. Environment proxies are ignored, and redirects are revalidated.
- **Corrupt storage recovery**: malformed SQLite catalogs are moved to `skillbridge.db.corrupt-<timestamp>` and rebuilt; `--home` paths that are regular files produce actionable errors. CLI startup errors no longer dump raw tracebacks (set `SKILLBRIDGE_DEBUG=1` to re-enable them).
- **Quarantine and audit lifecycle**: blocked imports now persist a `verification.json` plus file snapshot under `<home>/quarantine`; accepted/rejected imports write audit rows with digest and verdict. Catalog `security_verdict` is synchronized after successful import.
- **Archive ambiguity**: ClawHub ZIPs with duplicate or case-colliding member names are rejected.
- **UX/docs**: `--version`, `--source local` alias, 10k-character identifier echo reduced, `reports/` ignored, and README claims corrected for staging, quarantine, script isolation, and limits.

### Tests
- Added `tests/security/test_redteam_hardening.py` (16 regressions covering RCE verdicts, reverse-shell import blocking, junction/hardlink/root-link escapes, drive-absolute writes, cross-session unload, script output caps, SSRF aliases, corrupt DB recovery, quarantine, import audit, reference caps, and identifier echo bounds).

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
- **Live web-load hardening**: skills.sh records now use the API's canonical `source`/`skillId` fields; GitHub fetches resolve nested repo layouts (e.g. `skills/pdf` when an index reports only `pdf`); ClawHub index records with bare slugs resolve owners through live search; Smithery MCP verification now returns a real verdict; unknown IDs are never fuzzy-matched to unrelated MCP servers.
- **Memory and reliability**: the 100k+ record Hermes live index is released from memory after catalog seeding (RSS drops from ~277 MiB to ~86 MiB on Windows), and a load that is immediately evicted by the memory governor now raises an actionable error instead of returning an empty handle.
- **Documentation and packaging**: added `README.md`, `MANIFEST.in`, version alignment at 2.0.0, and parity regression tests (`tests/unit/test_v2_parity_fixes.py`).

### Migration from v1.0.0 to v2.0.0
- Existing v1 SQLite databases (`~/.skillbridge/skillbridge.db`), CLI commands (`verify`, `scan`, `search-skills`, `preview-skill`, `preflight`, `load-skill`, `unload-skill`, `install`, `rollback`, `evaluate`, `report`, `mcp-serve`), and MCP `skillbridge_*` tool names remain backward compatible; the v2 schema migration realigns FTS5 rowids in place on first open.
- New v2 settings (`~/.skillbridge/settings.json`) are created automatically on first run.

## [1.0.0] - 2026-10-19

### Added
- Initial release of SkillBridge with Hermes 100k+ Skills Hub discovery, 732 bundled Hermes skills and 70 MCP servers, SQLite + FTS5 catalog, mandatory preflight state machine, static + AST security scanner, OpenCode & Claude Code adapters, and stdio MCP server.
