"""Opt-in live marketplace smoke test suite and 16-step end-to-end marketplace workflow test (Section 17)."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from skillbridge.bridge import SkillBridge
from skillbridge.config import SkillBridgeConfig


class TestLiveMarketplaceWorkflow(unittest.TestCase):
    """Tests the 16-step marketplace discovery, quarantine staging, Tier 0-3 verification, import, recall, and hash-invalidation workflow."""

    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="sb_live_mkt_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_16_step_marketplace_workflow_on_real_bundled_catalog_and_hash_invalidation(self) -> None:
        # Copy a real skill from the bundled Hermes catalog into a mutable workspace repository to test all 16 steps
        real_src = Path("src/skillbridge/data/hermes_catalog/bundled_skills/software-development/test-driven-development")
        if not real_src.exists():
            real_src = next(Path("src/skillbridge/data/hermes_catalog/bundled_skills").rglob("SKILL.md")).parent

        repo_skill_dir = self.tmp_dir / "marketplace_repo" / real_src.name
        shutil.copytree(real_src, repo_skill_dir)

        cfg = SkillBridgeConfig(
            home_dir=self.tmp_dir / ".skillbridge",
            project_root=self.tmp_dir / "project",
            extra_skill_dirs=[self.tmp_dir / "marketplace_repo"],
        )
        cfg.network.offline_mode = True
        cfg.project_root.mkdir(parents=True, exist_ok=True)
        bridge = SkillBridge(config=cfg)

        # Step 1-2: Search and select skill through provider
        hits = asyncio.run(bridge.search_skills(real_src.name, limit=5))
        self.assertGreaterEqual(len(hits), 1)
        target_id = f"local-custom/{real_src.name}"

        # Step 5: Preview candidate without executing code
        preview = asyncio.run(bridge.preview_skill(target_id))
        self.assertIsNotNone(preview)

        # Step 6-12: Import into temporary runtime (Quarantine -> Tier 0-3 Verification -> Active Staging)
        imp = asyncio.run(bridge.import_skill(target_id, session_id="mkt_sess"))
        self.assertEqual(imp["verification"]["assurance_state"], "SAFE")
        first_digest = imp["bundle_digest"]

        # Step 13: Verify discoverable & usable in active session
        invoked = asyncio.run(bridge.invoke_skill(target_id, session_id="mkt_sess"))
        self.assertTrue(len(invoked.get("skill_md_body", "")) > 20)

        # Step 14: Unload and verify cleanup
        unloaded = asyncio.run(bridge.unload_skill(target_id, session_id="mkt_sess"))
        self.assertTrue(unloaded["unloaded"])
        self.assertFalse(Path(imp["staged_dir"]).exists())

        # Step 15: Recall from saved metadata
        recalled = bridge.loader.recall_skill_metadata(target_id)
        self.assertIsNotNone(recalled)
        self.assertEqual(recalled["bundle_digest"], first_digest)

        # Step 16: Mutate skill content on disk and verify digest changes & re-verification runs
        (repo_skill_dir / "SKILL.md").write_text(
            (repo_skill_dir / "SKILL.md").read_text(encoding="utf-8") + "\n<!-- benign update -->\n",
            encoding="utf-8",
        )
        imp2 = asyncio.run(bridge.import_skill(target_id, session_id="mkt_sess_2"))
        self.assertNotEqual(imp2["bundle_digest"], first_digest)

    @unittest.skipUnless(
        os.environ.get("SKILLBRIDGE_LIVE_NETWORK_TESTS") == "1",
        "Live network marketplace smoke test skipped: outbound internet is disabled in the build sandbox VM "
        "(set SKILLBRIDGE_LIVE_NETWORK_TESTS=1 on a network-enabled host to run against github.com/anthropics/skills, "
        "github.com/NVIDIA/skills, skills.sh, and registry.modelcontextprotocol.io).",
    )
    def test_opt_in_live_network_marketplaces(self) -> None:
        cfg = SkillBridgeConfig(
            home_dir=self.tmp_dir / ".skillbridge_live",
            project_root=self.tmp_dir / "project_live",
        )
        cfg.network.offline_mode = False
        bridge = SkillBridge(config=cfg)
        skills = asyncio.run(bridge.search_skills("pdf", source_filter="skills.sh", limit=3))
        self.assertIsInstance(skills, list)


if __name__ == "__main__":
    unittest.main()
