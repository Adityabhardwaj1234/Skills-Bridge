"""Durability and row-preserving recovery tests for the persistent SQLite catalog."""

from __future__ import annotations

import contextlib
import hashlib
import io
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

from skillbridge.cache.database import CatalogDatabase
from skillbridge.cache.recovery import CatalogRepairError, repair_catalog
from skillbridge.cli import main as cli_main
from skillbridge.models import ExtensionRecord


def _record(extension_id: str, name: str) -> ExtensionRecord:
    return ExtensionRecord(
        extension_id=extension_id,
        name=name,
        display_name=name.title(),
        extension_type="skill",
        description=f"Recovery fixture for {name}",
        source_provider="local",
        trust_level="trusted",
        tags=["recovery", "catalog"],
    )


class TestCatalogDurability(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(prefix="sb_catalog_durability_"))
        self.db_path = self.home / "skillbridge.db"

    def tearDown(self) -> None:
        shutil.rmtree(self.home, ignore_errors=True)

    def _seed(self) -> None:
        db = CatalogDatabase(self.db_path)
        try:
            db.upsert_extension(_record("local-custom/alpha", "alpha"))
            db.upsert_extension(_record("local-custom/beta", "beta"))
        finally:
            db.close()

    def test_connection_uses_crash_safe_pragmas(self) -> None:
        db = CatalogDatabase(self.db_path)
        try:
            journal = db._conn.execute("PRAGMA journal_mode").fetchone()[0].lower()
            synchronous = int(db._conn.execute("PRAGMA synchronous").fetchone()[0])
            self.assertEqual(journal, "wal")
            self.assertNotEqual(synchronous, 0, "synchronous=OFF is not crash-safe")
        finally:
            db.close()

    def test_repair_preserves_rows_and_never_seeds(self) -> None:
        self._seed()
        original_hash = hashlib.sha256(self.db_path.read_bytes()).hexdigest()
        report = repair_catalog(self.db_path, force=True)

        self.assertEqual(report.status, "repaired")
        self.assertTrue(report.data_preserved)
        self.assertEqual(report.restored_rows.get("extensions"), 2)
        self.assertEqual(report.fts_rows, 2)
        self.assertTrue(Path(report.backup_dir).is_dir())
        backup = Path(report.backup_dir) / "skillbridge.db"
        self.assertEqual(hashlib.sha256(backup.read_bytes()).hexdigest(), original_hash)

        check = sqlite3.connect(self.db_path)
        try:
            self.assertEqual(
                [r[0] for r in check.execute("PRAGMA integrity_check")],
                ["ok"],
            )
            self.assertEqual(
                check.execute("SELECT COUNT(*) FROM extensions NOT INDEXED").fetchone()[0], 2
            )
            self.assertEqual(
                check.execute("SELECT COUNT(*) FROM extensions_fts").fetchone()[0], 2
            )
            ids = {
                row[0]
                for row in check.execute("SELECT extension_id FROM extensions NOT INDEXED")
            }
            self.assertEqual(ids, {"local-custom/alpha", "local-custom/beta"})
            sequence_rows = list(
                check.execute("SELECT name, COUNT(*) FROM sqlite_sequence GROUP BY name")
            )
            self.assertTrue(all(count == 1 for _, count in sequence_rows))
        finally:
            check.close()

        reopened = CatalogDatabase(self.db_path)
        try:
            self.assertEqual(reopened.count_extensions(), 2)
            hits = [record.extension_id for record in reopened.search_extensions("fixture", limit=5)]
            self.assertEqual(set(hits), {"local-custom/alpha", "local-custom/beta"})
        finally:
            reopened.close()

    def test_non_sqlite_catalog_is_rejected_without_mutation(self) -> None:
        original = b"not a sqlite database\n" * 100
        self.db_path.write_bytes(original)
        with self.assertRaises(CatalogRepairError):
            repair_catalog(self.db_path, force=True)
        self.assertEqual(self.db_path.read_bytes(), original)
        self.assertFalse(list(self.home.glob("recovery-*")))

    def test_healthy_report_is_read_only(self) -> None:
        self._seed()
        before = hashlib.sha256(self.db_path.read_bytes()).hexdigest()
        report = repair_catalog(self.db_path)
        self.assertEqual(report.status, "healthy")
        self.assertIsNone(report.backup_dir)
        self.assertTrue(report.data_preserved)
        self.assertEqual(report.readable_rows.get("extensions"), 2)
        self.assertIsNone(report.fts_rows)
        self.assertEqual(hashlib.sha256(self.db_path.read_bytes()).hexdigest(), before)

    def test_repair_checkpoints_stale_wal_without_losing_rows(self) -> None:
        self._seed()
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA wal_autocheckpoint=0")
            conn.execute(
                "UPDATE extensions SET display_name='After' "
                "WHERE extension_id='local-custom/alpha'"
            )
            conn.commit()
            stale_home = self.home / "stale"
            stale_home.mkdir()
            for path in self.home.iterdir():
                if path.name.startswith("skillbridge.db"):
                    shutil.copy2(path, stale_home / path.name)
        finally:
            conn.close()

        report = repair_catalog(stale_home / "skillbridge.db", force=True)
        self.assertEqual(report.status, "repaired")
        check = sqlite3.connect(stale_home / "skillbridge.db")
        try:
            self.assertEqual(
                [r[0] for r in check.execute("PRAGMA integrity_check")],
                ["ok"],
            )
            display_name = check.execute(
                "SELECT display_name FROM extensions WHERE extension_id='local-custom/alpha'"
            ).fetchone()[0]
            self.assertEqual(display_name, "After")
            self.assertEqual(
                check.execute("SELECT COUNT(*) FROM extensions NOT INDEXED").fetchone()[0], 2
            )
        finally:
            check.close()

    def test_dry_run_reports_without_writing(self) -> None:
        self._seed()
        before = hashlib.sha256(self.db_path.read_bytes()).hexdigest()
        report = repair_catalog(self.db_path, dry_run=True, force=True)
        self.assertEqual(report.status, "would_repair")
        self.assertIsNone(report.backup_dir)
        self.assertTrue(report.data_preserved)
        self.assertEqual(report.readable_rows.get("extensions"), 2)
        self.assertIsNone(report.fts_rows)
        self.assertEqual(hashlib.sha256(self.db_path.read_bytes()).hexdigest(), before)
        self.assertFalse(list(self.home.glob("recovery-*")))

    def test_cli_repair_command_works(self) -> None:
        self._seed()
        out = io.StringIO()
        err = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli_main(["--home", str(self.home), "repair-catalog", "--force"])
        self.assertEqual(code, 0, err.getvalue())
        self.assertIn("Status        : repaired", out.getvalue())
        self.assertTrue(list(self.home.glob("recovery-*")))


if __name__ == "__main__":
    unittest.main()
