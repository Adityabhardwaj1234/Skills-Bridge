"""Backed-up, row-preserving recovery for corrupt SkillBridge SQLite catalogs.

The repair path never imports provider data. It copies only the surviving rows from the existing
catalog into a fresh schema, rebuilds indexes and the FTS5 search index, verifies the result, and
atomically replaces the damaged file after preserving a timestamped backup.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import quote

from skillbridge.cache.database import CatalogDatabase


CATALOG_TABLES: tuple[str, ...] = (
    "extensions",
    "audit_log",
    "cache_stats",
    "install_plans",
    "outcome_telemetry",
    "preflight_history",
    "security_scans",
    "trust_overrides",
)


class CatalogRepairError(RuntimeError):
    """Recovery could not be completed safely; the original catalog is preserved."""


@dataclass
class CatalogRepairReport:
    database: str
    status: str
    dry_run: bool = False
    backup_dir: Optional[str] = None
    readable_rows: Dict[str, int] = field(default_factory=dict)
    restored_rows: Dict[str, int] = field(default_factory=dict)
    fts_rows: Optional[int] = None
    source_errors: List[str] = field(default_factory=list)
    after_errors: List[str] = field(default_factory=list)
    data_preserved: bool = False
    message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _quote_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _readonly_connection(db_path: Path) -> sqlite3.Connection:
    wal_path = Path(str(db_path) + "-wal")
    wal_present = wal_path.exists() and wal_path.stat().st_size > 0
    immutable = "" if wal_present else "&immutable=1"
    uri = f"file:{quote(str(db_path).replace(chr(92), '/'))}?mode=ro{immutable}"
    conn = sqlite3.connect(uri, uri=True, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


def _pragma_errors(conn: sqlite3.Connection, pragma: str) -> List[str]:
    errors: List[str] = []
    try:
        cursor = conn.execute(f"PRAGMA {pragma}")
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


def _is_not_sqlite(errors: Sequence[str]) -> bool:
    text = " ".join(errors).lower()
    return "file is not a database" in text or "not a database" in text


def _sidecar_paths(db_path: Path) -> List[Path]:
    return [
        path
        for path in (Path(str(db_path) + "-wal"), Path(str(db_path) + "-shm"))
        if path.exists() and path.stat().st_size > 0
    ]


def _checkpoint_stale_wal(db_path: Path) -> None:
    """Merge a leftover WAL into the main file before taking a forensic copy.

    A non-empty WAL is data, not scratch space. Blindly copying only ``skillbridge.db`` would
    silently discard the newest transactions, while deleting the WAL would lose them entirely.
    If no writer holds the database, SQLite can checkpoint it into the main file; if that fails,
    the repair must stop and ask the operator to close processes or preserve all files together.
    """
    sidecars = _sidecar_paths(db_path)
    if not sidecars:
        return
    try:
        conn = sqlite3.connect(str(db_path), timeout=15.0)
        try:
            conn.execute("PRAGMA busy_timeout=15000")
            result = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        finally:
            conn.close()
    except sqlite3.DatabaseError as exc:
        raise CatalogRepairError(
            "Catalog has a non-empty SQLite WAL sidecar that could not be checkpointed: "
            f"{exc}. Close every SkillBridge/MCP process using this home, then retry. "
            "The original .db, .db-wal, and .db-shm files were not modified."
        ) from exc
    remaining_wal = [path for path in _sidecar_paths(db_path) if path.name.endswith("-wal")]
    if (result and int(result[0]) != 0) or remaining_wal:
        raise CatalogRepairError(
            "Catalog WAL checkpoint is busy or still has unmerged frames. Close every "
            "SkillBridge/MCP process using this home, then retry. Do not delete the .db-wal "
            "file: it may contain the newest catalog transactions."
        )


def _hash_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _backup_catalog(db_path: Path) -> tuple[Path, Path, str]:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup_dir = db_path.parent / f"recovery-{stamp}"
    suffix = 1
    while backup_dir.exists():
        backup_dir = db_path.parent / f"recovery-{stamp}-{suffix}"
        suffix += 1
    backup_dir.mkdir(parents=True, exist_ok=False)
    backup_file = backup_dir / db_path.name
    shutil.copy2(db_path, backup_file)
    source_hash = _hash_file(db_path)
    backup_hash = _hash_file(backup_file)
    if source_hash != backup_hash:
        raise CatalogRepairError(
            f"Backup verification failed for '{backup_file}'. The original catalog was not modified."
        )
    return backup_dir, backup_file, source_hash


def _table_columns(conn: sqlite3.Connection, table: str) -> List[str]:
    rows = conn.execute(f"PRAGMA table_info({_quote_identifier(table)})").fetchall()
    return [str(row["name"]) for row in rows]


def _table_digest(conn: sqlite3.Connection, table: str, columns: Sequence[str]) -> str:
    """Hash all values in rowid order so row preservation can be proven without relying on indexes."""
    if not columns:
        return ""
    cols = ", ".join(_quote_identifier(column) for column in columns)
    hasher = hashlib.sha256()
    cursor = conn.execute(f"SELECT {cols} FROM {_quote_identifier(table)} NOT INDEXED ORDER BY rowid")
    while True:
        row = cursor.fetchone()
        if row is None:
            break
        for value in row:
            if value is None:
                hasher.update(b"N\x00")
            elif isinstance(value, bytes):
                hasher.update(b"B\x00")
                hasher.update(value)
                hasher.update(b"\x00")
            else:
                hasher.update(b"T\x00")
                hasher.update(str(value).encode("utf-8", "surrogatepass"))
                hasher.update(b"\x00")
    return hasher.hexdigest()


def _readable_counts(conn: sqlite3.Connection) -> Dict[str, int]:
    """Count authoritative table rows, bypassing corrupt indexes and FTS shadow tables."""
    counts: Dict[str, int] = {}
    for table in CATALOG_TABLES:
        try:
            if not _table_columns(conn, table):
                counts[table] = 0
                continue
            counts[table] = int(
                conn.execute(
                    f"SELECT COUNT(*) FROM {_quote_identifier(table)} NOT INDEXED"
                ).fetchone()[0]
            )
        except sqlite3.DatabaseError:
            counts[table] = -1
    return counts


def _copy_table(
    source: sqlite3.Connection,
    target: sqlite3.Connection,
    table: str,
) -> int:
    source_columns = _table_columns(source, table)
    if not source_columns:
        return 0
    target_columns = _table_columns(target, table)
    if not target_columns:
        raise CatalogRepairError(
            f"Recovered schema is missing table '{table}'; refusing to drop surviving rows."
        )
    missing = [column for column in source_columns if column not in target_columns]
    if missing:
        raise CatalogRepairError(
            f"Table '{table}' contains columns not supported by the current schema: {missing}."
        )
    columns = target_columns
    column_sql = ", ".join(_quote_identifier(column) for column in columns)
    placeholders = ", ".join("?" for _ in columns)
    insert_sql = (
        f"INSERT INTO {_quote_identifier(table)} ({column_sql}) VALUES ({placeholders})"
    )
    select_sql = (
        f"SELECT {column_sql} FROM {_quote_identifier(table)} NOT INDEXED ORDER BY rowid"
    )
    count = 0
    cursor = source.execute(select_sql)
    while True:
        rows = cursor.fetchmany(1000)
        if not rows:
            break
        target.executemany(insert_sql, [tuple(row) for row in rows])
        count += len(rows)
    return count


def _populate_fts(target: sqlite3.Connection) -> int:
    target.execute("DELETE FROM extensions_fts")
    target.execute(
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
    return int(target.execute("SELECT COUNT(*) FROM extensions_fts").fetchone()[0])


def _remove_new_database_files(path: Path) -> None:
    for candidate in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm")):
        try:
            if candidate.exists():
                candidate.unlink()
        except OSError:
            pass


def repair_catalog(
    db_path: Path,
    *,
    dry_run: bool = False,
    force: bool = False,
) -> CatalogRepairReport:
    """Rebuild a corrupt catalog from surviving rows without importing provider data."""
    db_path = Path(db_path).expanduser().resolve()
    if not db_path.exists():
        raise CatalogRepairError(f"Catalog database does not exist: {db_path}")
    if not db_path.is_file():
        raise CatalogRepairError(f"Catalog path is not a regular file: {db_path}")

    source = _readonly_connection(db_path)
    try:
        source_errors = _pragma_errors(source, "integrity_check")
        if _is_not_sqlite(source_errors):
            raise CatalogRepairError(
                f"File at '{db_path}' is not a readable SQLite database. It was not modified or "
                "deleted. Preserve it for forensics; if it is a different file format, move it "
                "aside manually before starting a new catalog."
            )
        if not source_errors and not force:
            readable = _readable_counts(source)
            return CatalogRepairReport(
                database=str(db_path),
                status="healthy",
                dry_run=dry_run,
                readable_rows=readable,
                source_errors=[],
                data_preserved=True,
                message=(
                    "SQLite integrity_check passed; no repair was needed. "
                    "No catalog data was modified."
                ),
            )
        if dry_run:
            readable = _readable_counts(source)
            return CatalogRepairReport(
                database=str(db_path),
                status="would_repair",
                dry_run=True,
                readable_rows=readable,
                source_errors=source_errors,
                data_preserved=True,
                message=(
                    "A repair would create a timestamped backup and rebuild indexes/FTS from "
                    "surviving base-table rows. No data was modified by this dry run."
                ),
            )
    finally:
        source.close()

    _checkpoint_stale_wal(db_path)
    backup_dir, backup_file, source_hash = _backup_catalog(db_path)
    source = _readonly_connection(backup_file)
    try:
        columns: Dict[str, List[str]] = {}
        digests: Dict[str, str] = {}
        row_counts: Dict[str, int] = {}
        for table in CATALOG_TABLES:
            table_columns = _table_columns(source, table)
            if not table_columns:
                row_counts[table] = 0
                continue
            columns[table] = table_columns
            row_counts[table] = int(
                source.execute(
                    f"SELECT COUNT(*) FROM {_quote_identifier(table)} NOT INDEXED"
                ).fetchone()[0]
            )
            digests[table] = _table_digest(source, table, table_columns)
    except sqlite3.DatabaseError as exc:
        raise CatalogRepairError(
            f"Could not read surviving catalog rows from the preserved backup: {exc}. "
            f"The original database remains unchanged at '{db_path}' and the backup is at "
            f"'{backup_file}'."
        ) from exc
    finally:
        source.close()

    stamp = time.strftime("%Y%m%d-%H%M%S")
    recovered_path = db_path.with_name(f".{db_path.name}.recovered-{stamp}")
    _remove_new_database_files(recovered_path)

    target: Optional[CatalogDatabase] = None
    try:
        target = CatalogDatabase(recovered_path)
        target_conn = target._conn
        target_conn.execute("PRAGMA foreign_keys=OFF")
        restored: Dict[str, int] = {}
        # Re-open the preserved backup read-only for the actual copy so a long recovery does not
        # hold an old reader open while the replacement file is being prepared.
        source = _readonly_connection(backup_file)
        try:
            with target_conn:
                for table in CATALOG_TABLES:
                    restored[table] = _copy_table(source, target_conn, table)
                fts_rows = _populate_fts(target_conn)
                target_conn.execute(
                    "DELETE FROM sqlite_sequence WHERE name='audit_log'"
                )
                target_conn.execute(
                    "INSERT INTO sqlite_sequence(name, seq) "
                    "SELECT 'audit_log', COALESCE(MAX(id), 0) FROM audit_log"
                )
        except sqlite3.DatabaseError as exc:
            raise CatalogRepairError(
                f"Could not copy surviving catalog rows: {exc}. "
                f"The original database is preserved unchanged at '{backup_file}'."
            ) from exc
        finally:
            source.close()
        target_conn.execute("PRAGMA foreign_keys=ON")
        checkpoint = target_conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if checkpoint and int(checkpoint[0]) != 0:
            raise CatalogRepairError(
                "Could not checkpoint the rebuilt catalog before swapping it in; "
                f"the original database is preserved unchanged at '{backup_file}'."
            )
        target.close()
        target = None
        if any(
            path.name.endswith("-wal") for path in _sidecar_paths(recovered_path)
        ):
            raise CatalogRepairError(
                "The rebuilt catalog still has uncheckpointed WAL frames; refusing to swap it in. "
                f"The original database is preserved unchanged at '{backup_file}'."
            )

        validation = _readonly_connection(recovered_path)
        try:
            after_errors = _pragma_errors(validation, "integrity_check")
        finally:
            validation.close()
        if after_errors:
            raise CatalogRepairError(
                "The rebuilt catalog still fails integrity_check: "
                + " | ".join(after_errors[:5])
                + f". The original database is preserved unchanged at '{backup_file}'."
            )

        target_check = _readonly_connection(recovered_path)
        try:
            restored_actual = {
                table: int(
                    target_check.execute(
                        f"SELECT COUNT(*) FROM {_quote_identifier(table)} NOT INDEXED"
                    ).fetchone()[0]
                )
                for table in CATALOG_TABLES
            }
            digests_match = all(
                _table_digest(target_check, table, columns[table]) == digests.get(table)
                for table in columns
            )
            fts_actual = int(target_check.execute("SELECT COUNT(*) FROM extensions_fts").fetchone()[0])
        finally:
            target_check.close()
        if restored_actual != row_counts:
            raise CatalogRepairError(
                f"Row-count verification failed after rebuild (expected {row_counts}, got {restored_actual}). "
                f"The original database is preserved unchanged at '{backup_file}'."
            )
        if not digests_match:
            raise CatalogRepairError(
                "Row-content verification failed after rebuild. "
                f"The original database is preserved unchanged at '{backup_file}'."
            )
        if fts_actual != row_counts.get("extensions", 0):
            raise CatalogRepairError(
                f"FTS verification failed after rebuild (extensions={row_counts.get('extensions', 0)}, "
                f"fts={fts_actual}). The original database is preserved unchanged at '{backup_file}'."
            )

        os.replace(recovered_path, db_path)
        final_check = _readonly_connection(db_path)
        try:
            final_errors = _pragma_errors(final_check, "integrity_check")
            final_extensions = int(
                final_check.execute("SELECT COUNT(*) FROM extensions NOT INDEXED").fetchone()[0]
            )
        finally:
            final_check.close()
        if final_errors:
            shutil.copy2(backup_file, db_path)
            raise CatalogRepairError(
                "The swapped catalog failed final integrity verification and the original was restored: "
                + " | ".join(final_errors[:5])
            )
        if final_extensions != row_counts.get("extensions", 0):
            shutil.copy2(backup_file, db_path)
            raise CatalogRepairError(
                "The swapped catalog lost extension rows and the original was restored."
            )

        return CatalogRepairReport(
            database=str(db_path),
            status="repaired",
            backup_dir=str(backup_dir),
            readable_rows=row_counts,
            restored_rows=restored_actual,
            fts_rows=fts_actual,
            source_errors=source_errors,
            after_errors=after_errors,
            data_preserved=True,
            message=(
                f"Recovered {restored_actual.get('extensions', 0)} extension rows without seeding. "
                f"Original preserved at '{backup_file}' (sha256 {source_hash[:16]})."
            ),
        )
    except Exception:
        if target is not None:
            try:
                target.close()
            except Exception:
                pass
        _remove_new_database_files(recovered_path)
        raise
