# Incident Recovery, Rollback & Migration Guide (`docs/incident-recovery.md`)

## 1. Quarantine & Blocked Bundle Recovery

When an extension fails Tier 0–3 security verification (`AssuranceState.UNSAFE` or `SecurityVerdict.DANGEROUS`):
1. The active import or installation is aborted immediately before any native client files are modified.
2. A forensic bundle snapshot and `verification.json` report are written to
   `<home>/quarantine/<name>-<hash>/` (`~/.skillbridge` by default).
3. Temporary `quarantine_staging/` or `active_staging/` directories for that attempt are deleted; accepted
   bundle staging is also removed on unload and abandoned staging older than 24 hours is garbage-collected.

If the catalog database itself is malformed, SkillBridge stops with an actionable integrity error instead
of silently replacing it. Close every SkillBridge/MCP process, then run
`skillbridge --home <home> repair-catalog`. The command preserves the original bytes under
`<home>/recovery-<timestamp>/`, rebuilds indexes and FTS5 from the rows that remain readable, verifies
row counts/content digests and `PRAGMA integrity_check`, and atomically replaces the damaged file. It
never seeds bundled or provider data; rows that are only present as stale index entries are not invented.
Use `--dry-run` first to inspect the corruption without creating a backup or rebuilding the catalog.

On a damaged catalog, ordinary `SELECT COUNT(*)` may use a corrupt covering index and report more rows
than the base table actually contains. The repair uses `NOT INDEXED` full-table scans and digest checks.
Do not use `verify` or `doctor` as frozen post-repair checks: both run normal discovery and may add local
catalog rows. A non-empty `skillbridge.db-wal` is checkpointed before the backup; if a process still holds
it, close that process instead of deleting the WAL. Read-only inspection may leave zero-length WAL or
shared-memory sidecars; they contain no unmerged catalog rows.

Global options (`--home`, `--offline`, `--json`) must appear before `repair-catalog`. The repair applies
the current schema migration (typically v1 to v2); only the `schema_migrations` metadata row changes in
addition to rebuilt indexes/FTS. The CLI prints a shortened backup digest; hash the full backup file with
`Get-FileHash` or `sha256sum` when recording forensic evidence.

## 2. Rolling Back Native Client Deployments

Every `skillbridge install --apply` operation creates a backup manifest in `~/.skillbridge/backups/<plan_id>/backup_manifest.json`. To revert a native OpenCode or Claude Code deployment:

```powershell
python -m skillbridge rollback <plan_id>
```

This atomically restores `opencode.jsonc`, `.mcp.json`, or `~/.claude.json` from the pre-install snapshot and removes newly installed skill/agent files.

## 3. Upgrading from SkillBridge v1 to v2

SkillBridge v2 preserves compatibility with v1 SQLite databases (`skillbridge.db`) and CLI scripts:
1. Existing catalog records (`extensions`, `extensions_fts`, `security_scans`, `outcomes`, `audit_log`) are retained without destructive schema drops; the schema-v2 migration re-aligns FTS5 `rowid` maintenance for older catalogs.
2. Default v2 settings (`active_skill_limit=25`, `memory_threshold_mib=250.0`, `security_fail_closed=True`) are initialized in `~/.skillbridge/settings.json` only if not already customized.
3. Previously cached skills with executable scripts are **not** automatically activated; they must pass through the v2 Tier 0–3 verification pipeline on import.
