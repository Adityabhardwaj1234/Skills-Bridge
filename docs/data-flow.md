# SkillBridge v2 End-to-End Data Flow (`docs/data-flow.md`)

## 1. End-to-End Request & Bundle Pipeline

```
[1. User / Coding Agent Task]
       │
       ▼
[2. SkillBridge MCP Broker (19 Typed Operations) / CLI / Python API]
       │
       ▼
[3. Mandatory Task Preflight (PreflightOrchestrator)]
       ├── Classify task category & extract intent tokens
       ├── Query SQLite FTS5 Catalog + Parallel Remote Providers (Hermes 100k+, skills.sh, GitHub, MCP Registry)
       └── Non-executing Candidate Preview & 6-Factor Comparison (or explicit NO_MATCH)
       │
       ▼
[4. Immutable Quarantine Staging (Tier 0 — BundleStager)]
       ├── Materialize complete directory tree into 0700 quarantine_staging/<bundle_digest>/
       ├── Reject symlink escapes, archive traversal (..), hidden binaries, and size/depth violations
       └── Inventory all files, scripts, local module imports, and dependency manifests
       │
       ▼
[5. Multi-Tier Security & Quality Verification (VerificationCoordinator)]
       ├── Tier 1 (SkillSpectorAdapter): Static patterns, Python AST & lexical taint (TT1–TT6), MCP least-privilege (LP1)
       ├── Tier 2 (SKILAdapter): Declared-vs-observed capabilities & SHA-256 Assurance Closure (SAFE / UNSAFE / UNKNOWN)
       ├── Tier 3 (SkillEvaluatorAdapter): Reuses Tier 1 evidence; quality rubric, intra-skill & inter-skill deduplication
       └── Optional (OptionalSkillFortifyAdapter): Disabled by default (Elastic-2.0 isolation)
       │
       ▼
[6. Fail-Closed Policy Gate]
       ├── UNSAFE  ──> Block, quarantine, retain audit trail
       ├── UNKNOWN ──> Fail-closed block (unless non-executable & explicit read-only override)
       └── SAFE    ──> Promote to session-scoped active_staging/<session_id>/<skill_id>/
       │
       ▼
[7. Temporary Runtime Registry & Memory Monitor (SkillRuntimeLoader)]
       ├── Enforce 25-skill active limit (LRU eviction of eligible unpinned, non-in-use skills)
       ├── Monitor Process-Tree RSS against 250 MiB threshold (batch evict 5–10 skills down to 210 MiB watermark)
       ├── Serve instructions & relative references (or session deduplication stub)
       └── Execute permitted scripts in isolated subprocess worker (ScriptExecutionManager)
       │
       ▼
[8. Unload, Cleanup & Persistent Recall]
       ├── Release in-memory payload references & delete temporary staging directories
       ├── Retain lightweight provenance, source URI, bundle digest, and outcome telemetry in SQLite
       └── Subsequent recall verifies stored digest against upstream revision before reuse
```

## 2. Separation of Discovery, Preview, Import, Activation, and Native Deployment

- **Discovery (`search_skills`, `search_mcp_servers`)**: Queries indexed metadata and remote APIs without downloading full script bundles or executing code.
- **Preview (`preview_skill`, `compare_skills`)**: Inspects `SKILL.md` frontmatter, file trees, script entry points, and prior scan verdicts in read-only mode.
- **Import (`import_skill`)**: Stages the complete directory bundle into quarantine, runs Tiers 0–3 verification, promotes approved bundles into temporary active staging, and registers them in the 25-slot runtime registry.
- **Script Execution (`run_skill_script`)**: Validates current bundle digest against the approved verification digest, checks allowlisted capabilities and approval flags, and spawns a restricted worker subprocess with secrets stripped and network disabled by default.
- **Native Client Deployment (`plan_install`, `apply_install`, `rollback_install`)**: Permanently writes approved skills, agents, or MCP server configs into OpenCode or Claude Code directories with backups and rollback.
