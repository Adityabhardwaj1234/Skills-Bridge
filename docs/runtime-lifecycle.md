# SkillBridge v2 Runtime Lifecycle & State Machine (`docs/runtime-lifecycle.md`)

## 1. The 13-State Skill Bundle Import Lifecycle

Implemented in `src/skillbridge/verification/models.py` (`ImportState`) and enforced by `SkillRuntimeLoader.import_skill_bundle()` (`src/skillbridge/runtime/loader.py`):

```
DISCOVERED
   │
   ▼
PREVIEWED
   │
   ▼
SELECTED
   │
   ▼
FETCHED_INTO_QUARANTINE
   │
   ▼
ARTIFACT_VALIDATED (Tier 0)
   │
   ▼
TIERED_VERIFICATION (Tiers 1–3)
   │
   ├──────────────────────────► REJECTED (AssuranceState.UNSAFE)
   ├──────────────────────────► UNKNOWN  (AssuranceState.UNKNOWN, fail-closed)
   │
   ▼
APPROVED_BY_POLICY (AssuranceState.SAFE)
   │
   ▼
STAGED_TEMPORARILY
   │
   ▼
LOADED_INTO_ACTIVE_SESSION
   │
   ▼
USED / SCRIPT_EXECUTED_IF_ALLOWED
   │
   ▼
UNLOADED
   │
   ▼
TEMPORARY_FILES_REMOVED
   │
   ▼
METADATA_AND_RESULTS_RETAINED
```

## 2. Resource Ownership & State Separation

SkillBridge maintains strict separation across eight extension states:
1. **Discovered Skills**: Metadata rows in SQLite `extensions` / `extensions_fts`. Zero temporary disk or runtime payload memory used.
2. **Cached Artifacts**: Optional content-addressed metadata/scan records keyed by SHA-256 `content_hash`.
3. **Permanently Installed Skills**: Files explicitly deployed into `.opencode/skills/` or `.claude/skills/` via `apply_install()`.
4. **Quarantine-Staged Bundles**: Immutable snapshots in `quarantine_staging/<bundle_digest>/` undergoing Tier 0–3 inspection.
5. **Active Skills (`_active_bundles` & `_active_sessions`)**: Verified skills currently occupying one of the **25 active skill slots** (configurable via `RuntimeSettings.active_skill_limit`).
6. **In-Use Skills (`in_use=True`)**: Active skills currently executing a task or script worker; strictly protected from LRU or memory-pressure eviction until execution completes.
7. **Pinned Skills (`pinned=True`)**: Active skills explicitly protected by the user (`--pin`); excluded from automatic LRU eviction.
8. **Rejected / Quarantined Skills**: Extensions blocked by Tier 0–3 verification and isolated in `~/.skillbridge/quarantine/`.

## 3. Mid-Import Failure Rollback

If an exception occurs after `APPROVED_BY_POLICY` (for example, during `promote_to_active_staging` or session handle construction), `import_skill_bundle` executes a `try...except` rollback block that deletes the partially created `active_staging/<session>/<skill>` directory, removes any partial `_active_bundles` or `_active_sessions` entry, and leaves no dangling active handle.
