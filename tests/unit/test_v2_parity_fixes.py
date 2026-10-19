"""Regression tests for V2 parity upgrades: limits, parallel loading, helper imports, policy overrides,
FTS rowid maintenance, actionable errors, deferred load ordering, audit noise, ClawHub parsing, and
whole-directory local imports."""

from __future__ import annotations

import asyncio
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from skillbridge.bridge import SkillBridge
from skillbridge.cache.database import SCHEMA_VERSION, CatalogDatabase
from skillbridge.config import LoaderLimits, SecurityPolicyConfig, SkillBridgeConfig
from skillbridge.models import ExtensionRecord, SecurityAssessment, TrustLevel
from skillbridge.providers.hermes_hub import HermesHubProvider
from skillbridge.runtime.loader import SkillLoadError
from skillbridge.security.policy import TrustPolicyEngine
from skillbridge.settings import RuntimeSettings


def _write_skill(root: Path, name: str, body: str, files: dict[str, str] | None = None) -> Path:
    skill_dir = root / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: {name} isolated regression-test skill\n---\n{body}\n",
        encoding="utf-8",
    )
    for rel_path, content in (files or {}).items():
        target = skill_dir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return skill_dir


class TestLimitsAndPolicy(unittest.TestCase):
    def test_loader_and_bundle_limits_are_raised(self) -> None:
        limits = LoaderLimits()
        self.assertEqual(limits.max_file_size_bytes, 4 * 1024 * 1024)
        self.assertEqual(limits.max_total_bytes, 32 * 1024 * 1024)
        self.assertEqual(limits.max_nesting_depth, 6)
        self.assertEqual(limits.max_references, 100)
        self.assertEqual(limits.max_parallel_workers, 8)

        settings = RuntimeSettings()
        self.assertEqual(settings.max_parallel_skill_workers, 8)
        self.assertEqual(settings.bundle_max_files, 5000)
        self.assertEqual(settings.bundle_max_total_bytes, 256 * 1024 * 1024)
        self.assertEqual(settings.bundle_max_single_file_bytes, 8 * 1024 * 1024)
        self.assertEqual(settings.bundle_max_depth, 12)

    def test_builtin_dangerous_override_requires_explicit_approval(self) -> None:
        engine = TrustPolicyEngine(SecurityPolicyConfig())
        builtin = SecurityAssessment(
            extension_id="builtin/risky",
            name="risky",
            source="builtin",
            trust_level=TrustLevel.BUILTIN.value,
            verdict="DANGEROUS",
        )
        allowed, _, _ = engine.evaluate(builtin, approved=False)
        self.assertFalse(allowed)
        self.assertFalse(builtin.allowed)

        allowed, requires_approval, reason = engine.evaluate(builtin, approved=True)
        self.assertTrue(allowed)
        self.assertFalse(requires_approval)
        self.assertIn("ALLOWED_WITH_APPROVAL", reason)
        self.assertTrue(builtin.allowed)

        community = SecurityAssessment(
            extension_id="community/risky",
            name="risky",
            source="community",
            trust_level=TrustLevel.COMMUNITY.value,
            verdict="DANGEROUS",
        )
        allowed, _, _ = engine.evaluate(community, approved=True)
        self.assertFalse(allowed)

        disabled = TrustPolicyEngine(SecurityPolicyConfig(allow_builtin_dangerous_override=False))
        blocked = SecurityAssessment(
            extension_id="builtin/risky2",
            name="risky2",
            source="builtin",
            trust_level=TrustLevel.BUILTIN.value,
            verdict="DANGEROUS",
        )
        allowed, _, _ = disabled.evaluate(blocked, approved=True)
        self.assertFalse(allowed)


class TestParallelLoadingAndHelpers(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="sb_par_"))
        self.skills_root = self.tmp_dir / "skills"
        self.skills_root.mkdir(parents=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _bridge(self) -> SkillBridge:
        cfg = SkillBridgeConfig(
            home_dir=self.tmp_dir / ".sb",
            project_root=self.tmp_dir,
            extra_skill_dirs=[self.skills_root],
        )
        cfg.network.offline_mode = True
        return SkillBridge(config=cfg)

    def test_batch_load_auto_includes_local_helpers_and_isolates_failures(self) -> None:
        _write_skill(
            self.skills_root,
            "helper-skill",
            "Use [scripts/render.py](scripts/render.py) to render output.",
            files={
                "scripts/render.py": "from _raster import rasterize\n\ndef render():\n    return rasterize()\n",
                "scripts/_raster.py": "def rasterize():\n    return 'pixels'\n",
            },
        )
        _write_skill(
            self.skills_root,
            "js-helper-skill",
            "Use [scripts/app.js](scripts/app.js) for the browser flow.",
            files={
                "scripts/app.js": "import { draw } from './helper.js';\ndraw();\n",
                "scripts/helper.js": "export function draw() { return 1; }\n",
            },
        )
        _write_skill(self.skills_root, "plain-skill", "A plain, safe skill with no references.")
        bridge = self._bridge()

        async def _run():
            return await bridge.load_skills_parallel(
                ["helper-skill", "js-helper-skill", "plain-skill", "does-not-exist"],
                session_id="batch",
                max_workers=4,
                approved=True,
            )

        res = asyncio.run(_run())
        self.assertEqual(res["requested_count"], 4)
        self.assertEqual(res["loaded_count"], 3)
        self.assertEqual(res["failed_count"], 1)
        self.assertEqual(res["workers"], 4)
        self.assertEqual(res["failed"][0]["extension_id"], "does-not-exist")
        self.assertIn("could not be found", res["failed"][0]["error"])

        handles = {h.extension_id.split("/")[-1]: h for h in bridge.loader.get_active_handles("batch")}
        helper = handles["helper-skill"]
        self.assertIn("scripts/render.py", helper.loaded_references)
        self.assertIn("scripts/_raster.py", helper.loaded_references)
        js_helper = handles["js-helper-skill"]
        self.assertIn("scripts/app.js", js_helper.loaded_references)
        self.assertIn("scripts/helper.js", js_helper.loaded_references)

        batch_audits = [e for e in bridge.db.get_recent_audit_logs(limit=20) if e.get("operation") == "load_skills_parallel"]
        self.assertEqual(len(batch_audits), 1)
        self.assertEqual(batch_audits[0]["details"]["loaded_count"], 3)

    def test_index_only_record_reports_actionable_offline_error(self) -> None:
        bridge = self._bridge()
        record = ExtensionRecord(
            extension_id="skills-sh/acme/remote-only",
            name="remote-only",
            display_name="Remote Only",
            extension_type="skill",
            description="Remote indexed skill without a local bundle",
            source_provider="skills.sh",
            canonical_uri="https://skills.sh/acme/remote-only",
        )
        bridge.db.upsert_extension(record)

        async def _run():
            with self.assertRaises(SkillLoadError) as ctx:
                await bridge.load_skill("skills-sh/acme/remote-only", session_id="s")
            return str(ctx.exception)

        message = asyncio.run(_run())
        self.assertIn("index record", message)
        self.assertIn("offline", message.lower())
        self.assertIn("skills.sh", message)

    def test_deferred_load_runs_before_execution_gate(self) -> None:
        _write_skill(
            self.skills_root,
            "gate-skill",
            "# Gate Skill\nUse deterministic checklist validation for execution gate regression tests.",
        )
        bridge = self._bridge()

        async def _run():
            decision = await bridge.preflight(
                "deterministic checklist validation execution gate regression",
                session_id="gate-session",
                auto_load=False,
            )
            self.assertFalse(decision.no_match, decision.selection_reason)
            self.assertEqual(len(bridge.loader.get_active_handles("gate-session")), 0)
            executed, final = await bridge.execute_protected_task(
                decision.decision_id,
                lambda handles: f"used={len(handles)}",
            )
            return executed, final, decision

        executed, final, decision = asyncio.run(_run())
        self.assertIn("used=", executed)
        self.assertTrue(decision.runtime_loaded)
        self.assertTrue(decision.loaded_handles)
        self.assertEqual(len(bridge.loader.get_active_handles("gate-session")), 0)


class TestDatabaseMaintenance(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="sb_db_"))
        self.db_path = self.tmp_dir / "catalog.db"

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @staticmethod
    def _record(extension_id: str, description: str) -> ExtensionRecord:
        return ExtensionRecord(
            extension_id=extension_id,
            name=extension_id.split("/")[-1],
            display_name=extension_id.split("/")[-1].title(),
            extension_type="skill",
            description=description,
            source_provider="local",
        )

    def test_fts_rowids_align_and_upserts_do_not_duplicate(self) -> None:
        db = CatalogDatabase(self.db_path)
        try:
            db.upsert_extension(self._record("local/alpha", "alpha initial description"))
            db.upsert_extension(self._record("local/beta", "beta initial description"))
            rows = db._conn.execute(
                "SELECT f.rowid, e.rowid FROM extensions_fts f JOIN extensions e ON e.extension_id = f.extension_id"
            ).fetchall()
            self.assertEqual(len(rows), 2)
            for fts_rowid, ext_rowid in rows:
                self.assertEqual(int(fts_rowid), int(ext_rowid))

            db.upsert_extension(self._record("local/alpha", "alpha revised description"))
            count = db._conn.execute("SELECT COUNT(*) FROM extensions_fts").fetchone()[0]
            self.assertEqual(int(count), 2)
            hits = db.search_extensions("revised", limit=10)
            self.assertTrue(any(r.extension_id == "local/alpha" for r in hits))
            schema_versions = {int(r[0]) for r in db._conn.execute("SELECT version FROM schema_migrations")}
            self.assertIn(SCHEMA_VERSION, schema_versions)
        finally:
            db.close()

        # Simulate an old v1 database whose FTS rowids drifted, then reopen: the v2 migration re-aligns.
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM schema_migrations WHERE version = ?", (SCHEMA_VERSION,))
            conn.execute("UPDATE extensions_fts SET rowid = rowid + 1000")
            conn.commit()
        reopened = CatalogDatabase(self.db_path)
        try:
            rows = reopened._conn.execute(
                "SELECT f.rowid, e.rowid FROM extensions_fts f JOIN extensions e ON e.extension_id = f.extension_id"
            ).fetchall()
            self.assertEqual(len(rows), 2)
            for fts_rowid, ext_rowid in rows:
                self.assertEqual(int(fts_rowid), int(ext_rowid))
        finally:
            reopened.close()


class TestSeedingAuditAndClawHub(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="sb_audit_"))
        self.skills_root = self.tmp_dir / "skills"
        self.skills_root.mkdir(parents=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_catalog_seed_audit_only_logs_on_change_or_force(self) -> None:
        _write_skill(self.skills_root, "seed-skill", "Seeded local skill for audit-noise regression.")
        cfg = SkillBridgeConfig(
            home_dir=self.tmp_dir / ".sb",
            project_root=self.tmp_dir,
            extra_skill_dirs=[self.skills_root],
        )
        cfg.network.offline_mode = True
        bridge = SkillBridge(config=cfg)
        # Keep the test hermetic/fast: no bundled hub walk or MCP catalog scan.
        bridge.discovery.hermes_hub_provider._load_bundled_and_cached_index = lambda: []  # type: ignore[method-assign]
        bridge.discovery.mcp_provider._load_local_mcp_catalog = lambda: []  # type: ignore[method-assign]

        def seed_count() -> int:
            return len([e for e in bridge.db.get_recent_audit_logs(limit=50) if e.get("operation") == "catalog_seed"])

        bridge.discovery.ensure_catalog_seeded()
        self.assertEqual(seed_count(), 1)
        bridge.discovery.ensure_catalog_seeded()
        self.assertEqual(seed_count(), 1)
        bridge.discovery.ensure_catalog_seeded(force_rescan=True)
        self.assertEqual(seed_count(), 2)

    def test_clawhub_search_parses_owner_and_install_reference(self) -> None:
        provider = HermesHubProvider()

        class FakeHttp:
            def get_json(self, url, params=None):
                self.url = url
                self.params = params
                return {
                    "results": [
                        {
                            "skill": {"slug": "pdf-helper", "displayName": "PDF Helper", "summary": "PDF tables"},
                            "install": {"reference": "acme/pdf-helper"},
                            "native": {"owner": {"handle": "acme"}},
                            "links": {"canonical": "/skills/acme/pdf-helper"},
                            "latestVersion": "1.2.3",
                        }
                    ]
                }

        fake = FakeHttp()
        provider.http = fake  # type: ignore[assignment]
        recs = provider.search_clawhub("pdf", limit=5)
        self.assertEqual(len(recs), 1)
        rec = recs[0]
        self.assertEqual(rec.extension_id, "clawhub/acme/pdf-helper")
        self.assertEqual(rec.extra_metadata["owner"], "acme")
        self.assertEqual(rec.extra_metadata["install_reference"], "acme/pdf-helper")
        self.assertEqual(rec.canonical_uri, "https://clawhub.ai/skills/acme/pdf-helper")
        self.assertTrue(fake.url.endswith("/search"))


class TestWholeDirectoryImport(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="sb_import_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_import_local_directory_stages_every_nested_file(self) -> None:
        source = _write_skill(
            self.tmp_dir,
            "whole-dir-skill",
            "Use [scripts/task.py](scripts/task.py) and [references/guide.md](references/guide.md).",
            files={
                "scripts/task.py": "def run():\n    return 42\n",
                "references/guide.md": "# Guide\nAll nested references are staged.",
                "assets/data.json": '{"rows": 3}',
                "templates/report.md": "# Report template\n",
            },
        )
        cfg = SkillBridgeConfig(home_dir=self.tmp_dir / ".sb", project_root=self.tmp_dir)
        cfg.network.offline_mode = True
        bridge = SkillBridge(config=cfg)

        async def _run():
            return await bridge.import_local_directory(str(source), session_id="import-session")

        result = asyncio.run(_run())
        self.assertTrue(result["imported_path"].endswith("whole-dir-skill"))
        self.assertGreaterEqual(result["manifest"]["total_files"], 5)
        staged = Path(result["staged_dir"])
        for rel in ("SKILL.md", "scripts/task.py", "references/guide.md", "assets/data.json", "templates/report.md"):
            self.assertTrue((staged / rel).is_file(), f"missing staged file: {rel}")
        self.assertTrue(result["verification"]["allowed_to_load"])


if __name__ == "__main__":
    unittest.main()
