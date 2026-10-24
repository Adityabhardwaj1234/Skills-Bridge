"""SQLite persistent metadata catalog, FTS5 search index, outcome learning database, and audit trail."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.request import pathname2url

from skillbridge.models import (
    DependencySpec,
    ExtensionRecord,
    InstallPlan,
    MCPTransportSpec,
    PreflightDecision,
    SecurityAssessment,
    TaskOutcome,
    utc_now_iso,
)

SCHEMA_VERSION = 2


class CatalogCorruptionError(RuntimeError):
    """Raised when SQLite reports structural damage in the persistent catalog."""

    def __init__(self, db_path: Path, errors: list[str]):
        self.db_path = Path(db_path)
        self.errors = list(errors)
        preview = " | ".join(self.errors[:3]) or "unknown integrity failure"
        super().__init__(
            f"Catalog database '{self.db_path}' failed SQLite integrity checks: {preview}. "
            "No catalog data was deleted or reseeded. Close other SkillBridge processes, then run "
            f"'python -m skillbridge --home \"{self.db_path.parent}\" repair-catalog' to create a "
            "timestamped backup and rebuild the catalog from its surviving rows."
        )


def quick_check_errors(conn: sqlite3.Connection) -> List[str]:
    """Return SQLite quick_check errors without raising on a malformed database image."""
    errors: List[str] = []
    try:
        cursor = conn.execute("PRAGMA quick_check")
        while True:
            try:
                row = cursor.fetchone()
            except sqlite3.DatabaseError as exc:
                errors.append(str(exc))
                break
            if row is None:
                break
            text = str(row[0])
            if text and text.strip().lower() not in {"ok", "0"}:
                errors.extend(line for line in text.splitlines() if line.strip())
    except sqlite3.DatabaseError as exc:
        errors.append(str(exc))
    return errors


def _looks_like_corruption(exc: BaseException) -> bool:
    text = str(exc).lower()
    return any(
        marker in text
        for marker in ("malformed", "not a database", "disk image", "encrypted", "corrupt")
    )


def _configure_durable_connection(conn: sqlite3.Connection) -> None:
    """Use crash-safe SQLite settings; journal_mode=OFF must never be used for the catalog."""
    mode = "delete"
    try:
        row = conn.execute("PRAGMA journal_mode=WAL").fetchone()
        if row is not None:
            mode = str(row[0]).lower()
    except sqlite3.DatabaseError:
        mode = "off"
    if mode not in {"wal", "delete", "truncate", "persist"}:
        row = conn.execute("PRAGMA journal_mode=DELETE").fetchone()
        if row is not None:
            mode = str(row[0]).lower()
    if mode not in {"wal", "delete", "truncate", "persist"}:
        raise sqlite3.OperationalError(
            f"SQLite refused a crash-safe journal mode (got '{mode}'); "
            "journal_mode=OFF is not permitted for the catalog"
        )
    # NORMAL in WAL mode cannot corrupt the database after a crash. The legacy DELETE
    # fallback is upgraded to FULL so a partial page write is rolled back on next open.
    conn.execute("PRAGMA synchronous=NORMAL" if mode == "wal" else "PRAGMA synchronous=FULL")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA busy_timeout=15000")


def _open_sqlite_resilient(db_path: Path) -> sqlite3.Connection:
    """Open a catalog after a non-mutating integrity check.

    A damaged database is left exactly where it is. Silently moving it aside and creating an
    empty catalog risks losing records and encouraging an unintended provider reseed. The
    explicit ``repair-catalog`` command performs a backed-up, row-preserving rebuild instead.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists() and db_path.is_dir():
        raise RuntimeError(f"Catalog path '{db_path}' is a directory, not a SQLite database file.")
    if os.name != "nt":
        try:
            os.chmod(db_path.parent, 0o755)
        except OSError:
            pass
    if db_path.exists() and db_path.stat().st_size == 0:
        try:
            db_path.unlink()
        except OSError:
            pass

    conn = sqlite3.connect(str(db_path), timeout=15.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=15000")
        conn.execute("PRAGMA temp_store=MEMORY")
        # Force a page read so a non-SQLite file is detected before any schema write.
        conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
        errors = quick_check_errors(conn)
        if errors:
            raise CatalogCorruptionError(db_path, errors)
        _configure_durable_connection(conn)
        conn.execute("PRAGMA foreign_keys=ON")
        return conn
    except CatalogCorruptionError:
        conn.close()
        raise
    except sqlite3.DatabaseError as exc:
        conn.close()
        if _looks_like_corruption(exc):
            raise CatalogCorruptionError(db_path, [str(exc)]) from exc
        raise RuntimeError(f"Could not open catalog database at '{db_path}': {exc}") from exc


class CatalogDatabase:
    """Thread-safe SQLite database for extension catalog, FTS5 search, security attestations, and outcome learning."""

    def __init__(self, db_path: Path, enable_telemetry: bool = True):
        self.db_path = Path(db_path)
        self.enable_telemetry = enable_telemetry
        self._lock = threading.RLock()
        self._outcome_cache: Dict[str, Dict[str, Any]] = {}
        self._has_outcomes: bool = False
        self._conn = _open_sqlite_resilient(self.db_path)

        try:
            self._init_schema()
            errors = quick_check_errors(self._conn)
            if errors:
                raise CatalogCorruptionError(self.db_path, errors)
        except CatalogCorruptionError:
            self._conn.close()
            raise
        except sqlite3.DatabaseError as exc:
            self._conn.close()
            if _looks_like_corruption(exc):
                raise CatalogCorruptionError(self.db_path, [str(exc)]) from exc
            raise

    def _connect(self) -> sqlite3.Connection:
        return self._conn

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS extensions (
                    extension_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    extension_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    source_provider TEXT NOT NULL,
                    canonical_uri TEXT NOT NULL DEFAULT '',
                    repo TEXT NOT NULL DEFAULT '',
                    source_path TEXT NOT NULL DEFAULT '',
                    version_or_revision TEXT NOT NULL DEFAULT 'latest',
                    content_hash TEXT NOT NULL DEFAULT '',
                    trust_level TEXT NOT NULL DEFAULT 'community',
                    security_verdict TEXT NOT NULL DEFAULT 'UNKNOWN',
                    tags_json TEXT NOT NULL DEFAULT '[]',
                    categories_json TEXT NOT NULL DEFAULT '[]',
                    capabilities_json TEXT NOT NULL DEFAULT '[]',
                    platforms_json TEXT NOT NULL DEFAULT '[]',
                    clients_json TEXT NOT NULL DEFAULT '[]',
                    dependencies_json TEXT NOT NULL DEFAULT '[]',
                    mcp_transport_json TEXT,
                    install_targets_json TEXT NOT NULL DEFAULT '[]',
                    popularity_json TEXT NOT NULL DEFAULT '{}',
                    extra_json TEXT NOT NULL DEFAULT '{}',
                    cached_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_extensions_name ON extensions(name);
                CREATE INDEX IF NOT EXISTS idx_extensions_type ON extensions(extension_type);
                CREATE INDEX IF NOT EXISTS idx_extensions_provider ON extensions(source_provider);

                CREATE VIRTUAL TABLE IF NOT EXISTS extensions_fts USING fts5(
                    extension_id UNINDEXED,
                    name,
                    display_name,
                    description,
                    tags,
                    categories,
                    capabilities
                );

                CREATE TABLE IF NOT EXISTS security_scans (
                    extension_id TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    scanner_version TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    trust_level TEXT NOT NULL,
                    allowed INTEGER,
                    policy_reason TEXT NOT NULL,
                    findings_json TEXT NOT NULL,
                    ast_findings_json TEXT NOT NULL DEFAULT '[]',
                    quarantine_path TEXT,
                    scanned_at TEXT NOT NULL,
                    PRIMARY KEY (extension_id, content_hash, scanner_version)
                );

                CREATE TABLE IF NOT EXISTS preflight_history (
                    decision_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    task_category TEXT NOT NULL,
                    state TEXT NOT NULL,
                    sources_searched_json TEXT NOT NULL,
                    candidate_ids_json TEXT NOT NULL,
                    selected_ids_json TEXT NOT NULL,
                    no_match INTEGER NOT NULL DEFAULT 0,
                    selection_reason TEXT NOT NULL,
                    runtime_loaded INTEGER NOT NULL DEFAULT 0,
                    elapsed_ms REAL NOT NULL DEFAULT 0.0,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS outcome_telemetry (
                    outcome_id TEXT PRIMARY KEY,
                    decision_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    extension_id TEXT NOT NULL,
                    task_category TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    tests_passed INTEGER NOT NULL,
                    regression_detected INTEGER NOT NULL DEFAULT 0,
                    human_override TEXT,
                    latency_ms REAL NOT NULL DEFAULT 0.0,
                    notes TEXT NOT NULL DEFAULT '',
                    recorded_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_outcome_ext ON outcome_telemetry(extension_id);

                CREATE TABLE IF NOT EXISTS trust_overrides (
                    extension_id TEXT PRIMARY KEY,
                    trust_decision TEXT NOT NULL,
                    reason TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS install_plans (
                    plan_id TEXT PRIMARY KEY,
                    extension_id TEXT NOT NULL,
                    target_client TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    dry_run INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    backup_dir TEXT NOT NULL DEFAULT '',
                    plan_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    applied_at TEXT
                );

                CREATE TABLE IF NOT EXISTS cache_stats (
                    metric_key TEXT PRIMARY KEY,
                    metric_value INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    extension_id TEXT NOT NULL DEFAULT '',
                    verdict TEXT NOT NULL DEFAULT '',
                    elapsed_ms REAL NOT NULL DEFAULT 0.0,
                    details_json TEXT NOT NULL DEFAULT '{}'
                );
                """
            )
            with self._conn:
                applied = {
                    int(r[0])
                    for r in self._conn.execute("SELECT version FROM schema_migrations").fetchall()
                }
                if 2 not in applied:
                    # One-time migration: align FTS rowids with extensions.rowid so per-record
                    # index maintenance deletes by rowid (O(log n)) instead of scanning the
                    # UNINDEXED extension_id column of the FTS5 table (O(n) per upsert).
                    self._conn.execute("DELETE FROM extensions_fts")
                    self._conn.execute(
                        """
                        INSERT INTO extensions_fts (
                            rowid, extension_id, name, display_name, description, tags, categories, capabilities
                        )
                        SELECT
                            e.rowid, e.extension_id, replace(e.name, '-', ' '), e.display_name, e.description,
                            COALESCE((SELECT group_concat(value, ' ') FROM json_each(e.tags_json)), ''),
                            COALESCE((SELECT group_concat(value, ' ') FROM json_each(e.categories_json)), ''),
                            COALESCE((SELECT group_concat(value, ' ') FROM json_each(e.capabilities_json)), '')
                        FROM extensions e
                        """
                    )
                self._conn.execute(
                    "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (SCHEMA_VERSION, utc_now_iso()),
                )
            cnt = int(self._conn.execute("SELECT COUNT(*) FROM outcome_telemetry").fetchone()[0])
            ov_cnt = int(self._conn.execute("SELECT COUNT(*) FROM trust_overrides").fetchone()[0])
            self._has_outcomes = (cnt + ov_cnt) > 0

    def increment_stat(self, key: str, delta: int = 1) -> None:
        now = utc_now_iso()
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO cache_stats (metric_key, metric_value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(metric_key) DO UPDATE SET
                    metric_value = metric_value + excluded.metric_value,
                    updated_at = excluded.updated_at
                """,
                (key, delta, now),
            )

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            rows = self._conn.execute("SELECT metric_key, metric_value FROM cache_stats").fetchall()
            return {r["metric_key"]: int(r["metric_value"]) for r in rows}

    def log_audit(
        self,
        operation: str,
        *,
        severity: str = "INFO",
        session_id: str = "system",
        provider: str = "skillbridge",
        extension_id: str = "",
        verdict: str = "",
        elapsed_ms: float = 0.0,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record a structured observability event without logging sensitive payloads or secrets."""
        safe_details = {}
        if details:
            for k, v in details.items():
                if any(s in k.lower() for s in ("secret", "token", "password", "key", "auth", "body", "prompt")):
                    continue
                safe_details[k] = v
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO audit_log
                (timestamp, severity, session_id, operation, provider, extension_id, verdict, elapsed_ms, details_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    utc_now_iso(),
                    severity,
                    session_id,
                    operation,
                    provider,
                    extension_id,
                    verdict,
                    round(elapsed_ms, 3),
                    json.dumps(safe_details, default=str),
                ),
            )

    def get_recent_audit_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["details"] = json.loads(d.pop("details_json", "{}"))
                out.append(d)
            return out

    def upsert_extension(self, record: ExtensionRecord) -> None:
        """Insert or update an extension record and synchronize its FTS5 entry."""
        with self._lock, self._conn:
            self._upsert_one(self._conn, record)

    def upsert_extensions_batch(self, records: List[ExtensionRecord]) -> None:
        """Batch upsert extension records inside a single transaction for speed."""
        if not records:
            return
        with self._lock, self._conn:
            for rec in records:
                self._upsert_one(self._conn, rec)

    def _upsert_one(self, conn: sqlite3.Connection, record: ExtensionRecord) -> None:
        now = utc_now_iso()
        deps_data = [
            {
                "kind": d.kind,
                "name": d.name,
                "version_constraint": d.version_constraint,
                "required": d.required,
                "secret": d.secret,
                "description": d.description,
            }
            if isinstance(d, DependencySpec)
            else d
            for d in record.dependencies
        ]
        mcp_data = None
        if record.mcp_transport:
            mcp_data = (
                record.mcp_transport.__dict__
                if isinstance(record.mcp_transport, MCPTransportSpec)
                else record.mcp_transport
            )

        conn.execute(
            """
            INSERT INTO extensions (
                extension_id, name, display_name, extension_type, description,
                source_provider, canonical_uri, repo, source_path, version_or_revision,
                content_hash, trust_level, security_verdict, tags_json, categories_json,
                capabilities_json, platforms_json, clients_json, dependencies_json,
                mcp_transport_json, install_targets_json, popularity_json, extra_json,
                cached_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(extension_id) DO UPDATE SET
                name = excluded.name,
                display_name = excluded.display_name,
                extension_type = excluded.extension_type,
                description = excluded.description,
                source_provider = excluded.source_provider,
                canonical_uri = excluded.canonical_uri,
                repo = excluded.repo,
                source_path = excluded.source_path,
                version_or_revision = excluded.version_or_revision,
                content_hash = CASE WHEN excluded.content_hash != '' THEN excluded.content_hash ELSE extensions.content_hash END,
                trust_level = excluded.trust_level,
                security_verdict = CASE WHEN excluded.security_verdict != 'UNKNOWN' THEN excluded.security_verdict ELSE extensions.security_verdict END,
                tags_json = excluded.tags_json,
                categories_json = excluded.categories_json,
                capabilities_json = excluded.capabilities_json,
                platforms_json = excluded.platforms_json,
                clients_json = excluded.clients_json,
                dependencies_json = excluded.dependencies_json,
                mcp_transport_json = COALESCE(excluded.mcp_transport_json, extensions.mcp_transport_json),
                install_targets_json = excluded.install_targets_json,
                popularity_json = excluded.popularity_json,
                extra_json = excluded.extra_json,
                updated_at = excluded.updated_at
            """,
            (
                record.extension_id,
                record.name,
                record.display_name or record.name,
                record.extension_type,
                record.description,
                record.source_provider,
                record.canonical_uri,
                record.repo,
                record.source_path,
                record.version_or_revision,
                record.content_hash,
                record.trust_level,
                record.security_verdict,
                json.dumps(record.tags),
                json.dumps(record.task_categories),
                json.dumps(record.capabilities),
                json.dumps(record.platforms),
                json.dumps(record.compatible_clients),
                json.dumps(deps_data),
                json.dumps(mcp_data) if mcp_data else None,
                json.dumps(record.install_targets),
                json.dumps(record.popularity_signals),
                json.dumps(record.extra_metadata),
                record.cached_at or now,
                now,
            ),
        )
        # Maintain the FTS5 index by rowid (fast). Deleting by the UNINDEXED extension_id
        # column forced a full FTS table scan per upsert, making 100k-index seeding O(n^2).
        fts_row = conn.execute(
            "SELECT rowid FROM extensions WHERE extension_id = ?", (record.extension_id,)
        ).fetchone()
        if fts_row is not None:
            fts_rowid = int(fts_row[0])
            conn.execute("DELETE FROM extensions_fts WHERE rowid = ?", (fts_rowid,))
            conn.execute(
                """
                INSERT INTO extensions_fts (rowid, extension_id, name, display_name, description, tags, categories, capabilities)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    fts_rowid,
                    record.extension_id,
                    record.name.replace("-", " "),
                    record.display_name,
                    record.description,
                    " ".join(record.tags),
                    " ".join(record.task_categories),
                    " ".join(record.capabilities),
                ),
            )

    def _row_to_extension(self, row: sqlite3.Row, conn: sqlite3.Connection) -> ExtensionRecord:
        deps_raw = json.loads(row["dependencies_json"] or "[]")
        deps = [DependencySpec(**d) if isinstance(d, dict) else d for d in deps_raw]
        mcp_raw = json.loads(row["mcp_transport_json"]) if row["mcp_transport_json"] else None
        mcp = MCPTransportSpec(**mcp_raw) if isinstance(mcp_raw, dict) else None
        outcome_stats = self._compute_outcome_stats(conn, row["extension_id"])
        return ExtensionRecord(
            extension_id=row["extension_id"],
            name=row["name"],
            display_name=row["display_name"],
            extension_type=row["extension_type"],
            description=row["description"],
            source_provider=row["source_provider"],
            canonical_uri=row["canonical_uri"],
            repo=row["repo"],
            source_path=row["source_path"],
            version_or_revision=row["version_or_revision"],
            content_hash=row["content_hash"],
            trust_level=row["trust_level"],
            security_verdict=row["security_verdict"],
            tags=json.loads(row["tags_json"] or "[]"),
            task_categories=json.loads(row["categories_json"] or "[]"),
            capabilities=json.loads(row["capabilities_json"] or "[]"),
            platforms=json.loads(row["platforms_json"] or "[]"),
            compatible_clients=json.loads(row["clients_json"] or "[]"),
            dependencies=deps,
            mcp_transport=mcp,
            install_targets=json.loads(row["install_targets_json"] or "[]"),
            popularity_signals=json.loads(row["popularity_json"] or "{}"),
            outcome_stats=outcome_stats,
            extra_metadata=json.loads(row["extra_json"] or "{}"),
            cached_at=row["cached_at"],
            updated_at=row["updated_at"],
        )

    def get_extension(self, extension_id: str) -> Optional[ExtensionRecord]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM extensions WHERE extension_id = ? OR LOWER(name) = LOWER(?) ORDER BY CASE WHEN extension_id = ? THEN 0 ELSE 1 END LIMIT 1",
                (extension_id, extension_id, extension_id),
            ).fetchone()
            if not row:
                self.increment_stat("catalog_miss")
                return None
            self.increment_stat("catalog_hit")
            return self._row_to_extension(row, self._conn)

    def search_extensions(
        self,
        query: str,
        *,
        extension_type: Optional[str] = None,
        source_provider: Optional[str] = None,
        limit: int = 25,
    ) -> List[ExtensionRecord]:
        """Search extensions using SQLite FTS5 with trust-weighted ordering and fallback substring matching."""
        with self._lock:
            results: List[ExtensionRecord] = []
            seen: set[str] = set()

            terms = [t for t in "".join(c if c.isalnum() else " " for c in query.lower()).split() if len(t) >= 2]
            if terms:
                fts_query = " OR ".join(f'"{t}"*' for t in terms[:10])
                sql = """
                    SELECT e.*,
                           (bm25(extensions_fts, 0.0, 6.0, 3.5, 2.0, 3.0, 2.0, 1.5)
                            - CASE e.trust_level WHEN 'builtin' THEN 3.0 WHEN 'trusted' THEN 2.0 ELSE 0.0 END) AS fts_rank
                    FROM extensions_fts f
                    JOIN extensions e ON e.extension_id = f.extension_id
                    WHERE extensions_fts MATCH ?
                """
                params: List[Any] = [fts_query]
                if extension_type:
                    sql += " AND e.extension_type = ?"
                    params.append(extension_type)
                if source_provider and source_provider != "all":
                    sql += " AND e.source_provider = ?"
                    params.append(source_provider)
                sql += " ORDER BY fts_rank ASC, e.extension_id ASC LIMIT ?"
                params.append(limit * 2)
                try:
                    for row in self._conn.execute(sql, params).fetchall():
                        rec = self._row_to_extension(row, self._conn)
                        seen.add(rec.extension_id)
                        results.append(rec)
                except sqlite3.OperationalError:
                    pass

            if len(results) < limit:
                sql_like = "SELECT * FROM extensions WHERE 1=1"
                params_like: List[Any] = []
                if extension_type:
                    sql_like += " AND extension_type = ?"
                    params_like.append(extension_type)
                if source_provider and source_provider != "all":
                    sql_like += " AND source_provider = ?"
                    params_like.append(source_provider)
                if query.strip():
                    q_like = f"%{query.strip().lower()}%"
                    sql_like += " AND (LOWER(name) LIKE ? OR LOWER(description) LIKE ? OR LOWER(tags_json) LIKE ? OR LOWER(extension_id) LIKE ?)"
                    params_like.extend([q_like, q_like, q_like, q_like])
                sql_like += " ORDER BY extension_id ASC LIMIT ?"
                params_like.append(limit * 2)
                for row in self._conn.execute(sql_like, params_like).fetchall():
                    if row["extension_id"] not in seen:
                        seen.add(row["extension_id"])
                        results.append(self._row_to_extension(row, self._conn))
                        if len(results) >= limit * 2:
                            break

            self.increment_stat("fts_search_count")
            return results[:limit]

    def count_extensions(self, extension_type: Optional[str] = None) -> int:
        with self._lock:
            if extension_type:
                return int(self._conn.execute("SELECT COUNT(*) FROM extensions WHERE extension_type = ?", (extension_type,)).fetchone()[0])
            return int(self._conn.execute("SELECT COUNT(*) FROM extensions").fetchone()[0])

    def save_security_scan(self, assessment: SecurityAssessment) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO security_scans (
                    extension_id, content_hash, scanner_version, verdict, trust_level,
                    allowed, policy_reason, findings_json, ast_findings_json, quarantine_path, scanned_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    assessment.extension_id,
                    assessment.content_hash,
                    assessment.scanner_version,
                    assessment.verdict,
                    assessment.trust_level,
                    1 if assessment.allowed is True else (0 if assessment.allowed is False else None),
                    assessment.policy_reason,
                    json.dumps([f.to_dict() for f in assessment.findings]),
                    json.dumps(assessment.ast_findings),
                    assessment.quarantine_path,
                    assessment.scanned_at,
                ),
            )
            self._conn.execute(
                "UPDATE extensions SET content_hash = ?, security_verdict = ?, updated_at = ? WHERE extension_id = ?",
                (assessment.content_hash, assessment.verdict, utc_now_iso(), assessment.extension_id),
            )

    def get_cached_security_scan(
        self, extension_id: str, content_hash: str, scanner_version: str = "skillbridge-guard-v1"
    ) -> Optional[SecurityAssessment]:
        if not content_hash:
            return None
        with self._lock:
            row = self._conn.execute(
                """
                SELECT * FROM security_scans
                WHERE extension_id = ? AND content_hash = ? AND scanner_version = ?
                """,
                (extension_id, content_hash, scanner_version),
            ).fetchone()
            if not row:
                self.increment_stat("scan_cache_miss")
                return None
            self.increment_stat("scan_cache_hit")
            from skillbridge.models import SecurityFinding

            findings = [SecurityFinding(**f) for f in json.loads(row["findings_json"] or "[]")]
            allowed_val = row["allowed"]
            return SecurityAssessment(
                extension_id=row["extension_id"],
                name=row["extension_id"].split("/")[-1],
                source="cached",
                trust_level=row["trust_level"],
                verdict=row["verdict"],
                findings=findings,
                ast_findings=json.loads(row["ast_findings_json"] or "[]"),
                content_hash=row["content_hash"],
                scanned_at=row["scanned_at"],
                scanner_version=row["scanner_version"],
                allowed=True if allowed_val == 1 else (False if allowed_val == 0 else None),
                policy_reason=row["policy_reason"],
                quarantine_path=row["quarantine_path"],
            )

    def record_preflight(self, decision: PreflightDecision) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO preflight_history (
                    decision_id, session_id, task_category, state, sources_searched_json,
                    candidate_ids_json, selected_ids_json, no_match, selection_reason,
                    runtime_loaded, elapsed_ms, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision.decision_id,
                    decision.session_id,
                    decision.task_category,
                    decision.state,
                    json.dumps(decision.sources_searched),
                    json.dumps(decision.candidate_ids),
                    json.dumps(decision.selected_ids),
                    1 if decision.no_match else 0,
                    decision.selection_reason,
                    1 if decision.runtime_loaded else 0,
                    decision.elapsed_ms,
                    decision.created_at,
                ),
            )

    def record_outcome(self, outcome: TaskOutcome) -> bool:
        """Record a verified task outcome if telemetry is enabled (never stores raw prompts or secrets)."""
        if not self.enable_telemetry:
            return False
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO outcome_telemetry (
                    outcome_id, decision_id, session_id, extension_id, task_category,
                    success, tests_passed, regression_detected, human_override,
                    latency_ms, notes, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    outcome.outcome_id,
                    outcome.decision_id,
                    outcome.session_id,
                    outcome.extension_id,
                    outcome.task_category,
                    1 if outcome.success else 0,
                    1 if outcome.tests_passed else 0,
                    1 if outcome.regression_detected else 0,
                    outcome.human_override,
                    outcome.latency_ms,
                    outcome.notes[:200],
                    outcome.recorded_at,
                ),
            )
            self._has_outcomes = True
            self._outcome_cache.pop(outcome.extension_id, None)
        return True

    def _compute_outcome_stats(self, conn: sqlite3.Connection, extension_id: str) -> Dict[str, Any]:
        if not self._has_outcomes:
            return {
                "total_runs": 0,
                "successes": 0,
                "regressions": 0,
                "success_rate": None,
                "avg_latency_ms": 0.0,
                "last_used_at": None,
                "trust_override": None,
            }
        if extension_id in self._outcome_cache:
            return self._outcome_cache[extension_id]
        row = conn.execute(
            """
            SELECT
                COUNT(*) AS total_runs,
                SUM(CASE WHEN success = 1 AND tests_passed = 1 AND regression_detected = 0 THEN 1 ELSE 0 END) AS successes,
                SUM(CASE WHEN regression_detected = 1 THEN 1 ELSE 0 END) AS regressions,
                AVG(latency_ms) AS avg_latency_ms,
                MAX(recorded_at) AS last_used_at
            FROM outcome_telemetry
            WHERE extension_id = ?
            """,
            (extension_id,),
        ).fetchone()
        override_row = conn.execute(
            "SELECT trust_decision, reason FROM trust_overrides WHERE extension_id = ?",
            (extension_id,),
        ).fetchone()
        total = int(row["total_runs"] or 0)
        successes = int(row["successes"] or 0)
        regressions = int(row["regressions"] or 0)
        stats = {
            "total_runs": total,
            "successes": successes,
            "regressions": regressions,
            "success_rate": round(successes / total, 4) if total > 0 else None,
            "avg_latency_ms": round(float(row["avg_latency_ms"] or 0.0), 2),
            "last_used_at": row["last_used_at"],
            "trust_override": override_row["trust_decision"] if override_row else None,
        }
        self._outcome_cache[extension_id] = stats
        return stats

    def set_trust_override(self, extension_id: str, trust_decision: str, reason: str = "") -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO trust_overrides (extension_id, trust_decision, reason, updated_at)
                VALUES (?, ?, ?, ?)
                """,
                (extension_id, trust_decision, reason, utc_now_iso()),
            )
            self._has_outcomes = True
            self._outcome_cache.pop(extension_id, None)

    def clear_telemetry(self) -> int:
        """Clear stored usage and outcome records on user request."""
        with self._lock, self._conn:
            cur = self._conn.execute("DELETE FROM outcome_telemetry")
            self._conn.execute("DELETE FROM preflight_history")
            self._outcome_cache.clear()
            ov_cnt = int(self._conn.execute("SELECT COUNT(*) FROM trust_overrides").fetchone()[0])
            self._has_outcomes = ov_cnt > 0
            return cur.rowcount

    def save_install_plan(self, plan: InstallPlan) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO install_plans (
                    plan_id, extension_id, target_client, scope, dry_run, status, backup_dir, plan_json, created_at, applied_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    plan.plan_id,
                    plan.extension_id,
                    plan.target_client,
                    plan.scope,
                    1 if plan.dry_run else 0,
                    plan.status,
                    plan.backup_dir,
                    json.dumps(plan.to_dict(), default=str),
                    plan.created_at,
                    plan.applied_at,
                ),
            )

    def get_install_plan(self, plan_id: str) -> Optional[InstallPlan]:
        with self._lock:
            row = self._conn.execute("SELECT plan_json FROM install_plans WHERE plan_id = ?", (plan_id,)).fetchone()
            if not row:
                return None
            data = json.loads(row["plan_json"])
            sec_data = data.pop("security_assessment", None)
            sec = None
            if isinstance(sec_data, dict):
                from skillbridge.models import SecurityFinding

                findings = [SecurityFinding(**f) for f in sec_data.pop("findings", [])]
                sec = SecurityAssessment(**sec_data, findings=findings)
            return InstallPlan(**data, security_assessment=sec)
