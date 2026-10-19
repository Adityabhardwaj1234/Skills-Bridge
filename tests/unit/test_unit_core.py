"""Unit tests for SkillBridge normalization, discovery, ranking, preview, SQLite persistence, runtime loader/unloader, adapters, and CLI."""

from __future__ import annotations

import asyncio
import contextlib
import io
import shutil
import tempfile
import unittest
from pathlib import Path

import httpx

from skillbridge.adapters.clients import dump_jsonc, parse_jsonc
from skillbridge.bridge import SkillBridge
from skillbridge.cache.database import CatalogDatabase
from skillbridge.cli import main as cli_main
from skillbridge.config import SkillBridgeConfig
from skillbridge.discovery.normalizer import (
    compute_bundle_content_hash,
    compute_directory_content_hash,
    extract_referenced_support_paths,
    is_safe_http_url,
    normalize_repo_alias,
    normalize_url,
    parse_skill_md,
    validate_bundle_rel_path,
    validate_skill_frontmatter,
    validate_skill_name,
)
from skillbridge.installers.planner import DependencyInspector
from skillbridge.models import DependencySpec, ExtensionRecord, ExtensionType, TaskOutcome
from skillbridge.providers.base import GuardedHttpClient


class TestSkillBridgeUnitCore(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="sb_unit_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_parse_and_validate_skill_frontmatter(self) -> None:
        valid_md = "---\nname: git-release\ndescription: Create consistent releases\n---\n# Body\nSteps here."
        fm, body = parse_skill_md(valid_md)
        self.assertEqual(fm["name"], "git-release")
        self.assertEqual(fm["description"], "Create consistent releases")
        self.assertIn("# Body", body)
        self.assertEqual(validate_skill_frontmatter(fm, expected_dir_name="git-release"), [])

        bad_yaml = "---\nname: [unclosed\n---\nBody"
        fm_bad, _ = parse_skill_md(bad_yaml)
        self.assertIn("_invalid_frontmatter", fm_bad)
        self.assertEqual(len(validate_skill_frontmatter(fm_bad)), 1)

        fm_mismatch = {"name": "Invalid--Name", "description": "Valid desc"}
        issues = validate_skill_frontmatter(fm_mismatch, expected_dir_name="other-dir")
        self.assertTrue(any("regex" in i for i in issues))
        self.assertTrue(any("does not match directory" in i for i in issues))

    def test_path_validation_and_reference_extraction(self) -> None:
        self.assertEqual(validate_skill_name("my-skill-1"), "my-skill-1")
        self.assertEqual(validate_bundle_rel_path("references/guide.md"), "references/guide.md")

        for unsafe in ("../secret.txt", "/etc/passwd", "C:\\Windows\\System32", "file.py:ads_stream"):
            with self.assertRaises(ValueError):
                validate_bundle_rel_path(unsafe)

        md_with_refs = "See [references/api.md](references/api.md) and `scripts/helper.py` and [ sibling ]( ./NOTES.md )."
        refs = extract_referenced_support_paths(md_with_refs)
        self.assertEqual(refs, {"references/api.md", "scripts/helper.py", "NOTES.md"})

        self.assertIsNone(extract_referenced_support_paths("See `references/../../etc/passwd`"))

    def test_url_and_repo_normalization(self) -> None:
        self.assertEqual(normalize_repo_alias("anthropic"), "anthropics/skills")
        self.assertEqual(
            normalize_repo_alias("https://github.com/openai/skills/tree/main/skills/codex"),
            "openai/skills/skills/codex",
        )
        self.assertEqual(normalize_url("HTTPS://Example.COM/a//b/c/"), "https://example.com/a/b/c")

        self.assertTrue(is_safe_http_url("https://skills.sh/api/search")[0])
        self.assertFalse(is_safe_http_url("http://127.0.0.1:8080/admin")[0])
        self.assertFalse(is_safe_http_url("http://169.254.169.254/latest/meta-data/")[0])
        self.assertFalse(is_safe_http_url("ftp://files.example.com/skill.md")[0])

    def test_symmetric_content_hashing_and_cache_invalidation(self) -> None:
        skill_dir = self.tmp_dir / "sample-skill"
        (skill_dir / "references").mkdir(parents=True)
        md_text = "---\nname: sample-skill\ndescription: Sample test skill\n---\n# Sample\nSee [references/ref.md](references/ref.md)\n"
        ref_text = "Reference content v1\n"
        (skill_dir / "SKILL.md").write_text(md_text, encoding="utf-8", newline="")
        (skill_dir / "references" / "ref.md").write_text(ref_text, encoding="utf-8", newline="")

        disk_hash_1 = compute_directory_content_hash(skill_dir)
        bundle_hash_1 = compute_bundle_content_hash({"SKILL.md": md_text, "references/ref.md": ref_text})
        self.assertEqual(disk_hash_1, bundle_hash_1)

        (skill_dir / "references" / "ref.md").write_text("Reference content v2\n", encoding="utf-8", newline="")
        disk_hash_2 = compute_directory_content_hash(skill_dir)
        self.assertNotEqual(disk_hash_2, disk_hash_1)

    def test_sqlite_persistence_fts_and_outcome_learning(self) -> None:
        db = CatalogDatabase(self.tmp_dir / "test.db", enable_telemetry=True)
        rec1 = ExtensionRecord(
            extension_id="local/alpha-debug",
            name="alpha-debug",
            display_name="Alpha Debugger",
            extension_type=ExtensionType.SKILL.value,
            description="Debug Python tracebacks and memory leaks",
            source_provider="local",
            trust_level="trusted",
            tags=["python", "debugging"],
        )
        rec2 = ExtensionRecord(
            extension_id="local/beta-debug",
            name="beta-debug",
            display_name="Beta Debugger",
            extension_type=ExtensionType.SKILL.value,
            description="Debug Python tracebacks and memory leaks",
            source_provider="local",
            trust_level="trusted",
            tags=["python", "debugging"],
        )
        db.upsert_extensions_batch([rec1, rec2])
        hits = db.search_extensions("Python tracebacks")
        self.assertEqual(len(hits), 2)

        for i in range(3):
            db.record_outcome(
                TaskOutcome(
                    outcome_id=f"o_beta_{i}",
                    decision_id="d1",
                    session_id="s1",
                    extension_id="local/beta-debug",
                    task_category="python_debugging",
                    success=True,
                    tests_passed=True,
                    regression_detected=False,
                )
            )
            db.record_outcome(
                TaskOutcome(
                    outcome_id=f"o_alpha_{i}",
                    decision_id="d2",
                    session_id="s1",
                    extension_id="local/alpha-debug",
                    task_category="python_debugging",
                    success=False,
                    tests_passed=False,
                    regression_detected=True,
                )
            )

        r_alpha = db.get_extension("local/alpha-debug")
        r_beta = db.get_extension("local/beta-debug")
        self.assertIsNotNone(r_alpha)
        self.assertIsNotNone(r_beta)
        assert r_alpha is not None and r_beta is not None
        self.assertEqual(r_beta.outcome_stats["successes"], 3)
        self.assertEqual(r_alpha.outcome_stats["regressions"], 3)

        cleared = db.clear_telemetry()
        self.assertEqual(cleared, 6)
        r_beta_after = db.get_extension("local/beta-debug")
        assert r_beta_after is not None
        self.assertEqual(r_beta_after.outcome_stats["total_runs"], 0)

    def test_http_timeouts_retries_and_size_bounds(self) -> None:
        attempts = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            attempts["count"] += 1
            if request.url.path == "/flaky" and attempts["count"] == 1:
                return httpx.Response(503, text="Temporary Unavailable")
            if request.url.path == "/flaky":
                return httpx.Response(200, json={"status": "recovered"})
            if request.url.path == "/huge":
                return httpx.Response(200, content=b"X" * 5000)
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        client = GuardedHttpClient(transport=transport)
        data = client.get_json("https://skills.sh/flaky")
        self.assertEqual(data, {"status": "recovered"})
        self.assertEqual(attempts["count"], 2)

        with self.assertRaises(ValueError):
            client.get_bytes("https://skills.sh/huge", max_bytes=1024)

    def test_runtime_loading_unloading_and_dedup(self) -> None:
        s_dir = self.tmp_dir / "skills" / "custom-helper"
        (s_dir / "references").mkdir(parents=True)
        (s_dir / "SKILL.md").write_text(
            "---\nname: custom-helper\ndescription: Custom helper skill for unit tests\n---\n"
            "# Instructions\nUse [references/detail.md](references/detail.md).\n",
            encoding="utf-8",
        )
        (s_dir / "references" / "detail.md").write_text("Detailed reference content.", encoding="utf-8")

        cfg = SkillBridgeConfig(
            home_dir=self.tmp_dir / ".sb",
            project_root=self.tmp_dir,
            extra_skill_dirs=[self.tmp_dir / "skills"],
        )
        cfg.network.offline_mode = True
        bridge = SkillBridge(config=cfg)

        async def _run() -> None:
            h1 = await bridge.load_skill("custom-helper", session_id="sess_1", allow_dedup_stub=True)
            self.assertTrue(h1.active)
            self.assertFalse(h1.dedup_stub)
            self.assertIn("references/detail.md", h1.loaded_references)
            self.assertEqual(len(bridge.loader.get_active_handles("sess_1")), 1)

            h2 = await bridge.load_skill("custom-helper", session_id="sess_1", allow_dedup_stub=True)
            self.assertTrue(h2.dedup_stub)
            self.assertIn("unchanged", h2.skill_md_body)

            unload_res = await bridge.unload_skill("custom-helper", session_id="sess_1")
            self.assertTrue(unload_res["unloaded"])
            self.assertFalse(h2.active)
            self.assertEqual(h2.skill_md_body, "")
            self.assertEqual(len(bridge.loader.get_active_handles("sess_1")), 0)

            with self.assertRaises(RuntimeError):
                async with bridge.loader.async_temporary_skill_scope(["custom-helper"], session_id="sess_err") as handles:
                    self.assertEqual(len(handles), 1)
                    self.assertEqual(len(bridge.loader.get_active_handles("sess_err")), 1)
                    raise RuntimeError("simulated failure")
            self.assertEqual(len(bridge.loader.get_active_handles("sess_err")), 0)

        asyncio.run(_run())

    def test_jsonc_and_dependency_inspector(self) -> None:
        raw_jsonc = """// OpenCode configuration comment
{
  "$schema": "https://opencode.ai/config.json",
  // Inline comment
  "plugin": ["opencode-skill"],
}
"""
        parsed, comments = parse_jsonc(raw_jsonc)
        self.assertEqual(parsed["plugin"], ["opencode-skill"])
        self.assertEqual(len(comments), 1)
        dumped = dump_jsonc(parsed, comments)
        self.assertIn("// OpenCode configuration comment", dumped)

        inspector = DependencyInspector()
        checks, missing = inspector.inspect_dependencies(
            [
                DependencySpec(kind="executable", name="python3"),
                DependencySpec(kind="executable", name="nonexistent_binary_xyz_999"),
                DependencySpec(kind="python_package", name="httpx"),
            ]
        )
        self.assertIn("executable:nonexistent_binary_xyz_999", missing)
        self.assertTrue(any(c["name"] == "httpx" and c["satisfied"] is True for c in checks))

    def test_cli_commands_and_exit_codes(self) -> None:
        sb_home = str(self.tmp_dir / ".sb")
        proj = str(self.tmp_dir / "proj")

        buf1 = io.StringIO()
        with contextlib.redirect_stdout(buf1):
            rc1 = cli_main(["--home", sb_home, "--project-root", proj, "--offline", "--json", "scan"])
        self.assertEqual(rc1, 0)
        self.assertIn('"skills":', buf1.getvalue())

        buf2 = io.StringIO()
        with contextlib.redirect_stdout(buf2):
            rc2 = cli_main(["--home", sb_home, "--project-root", proj, "--offline", "--json", "search-skills", "pdf"])
        self.assertEqual(rc2, 0)
        self.assertIn("pdf", buf2.getvalue().lower())

        err_buf = io.StringIO()
        with contextlib.redirect_stderr(err_buf):
            rc3 = cli_main(["--home", sb_home, "--project-root", proj, "--offline", "preview-skill", "nonexistent_skill_zzz"])
        self.assertEqual(rc3, 2)


if __name__ == "__main__":
    unittest.main()
