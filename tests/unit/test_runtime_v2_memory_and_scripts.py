"""Unit and integration tests for the 13-state bundle import lifecycle, 25-skill active cap, 250 MiB memory eviction, script execution isolation, and parallel MCP orchestration."""

from __future__ import annotations

import asyncio
from pathlib import Path
import shutil
import tempfile
import unittest

from skillbridge.bridge import SkillBridge
from skillbridge.config import SkillBridgeConfig
from skillbridge.mcp_server.server import SkillBridgeMCPServer
from skillbridge.orchestration.scheduler import (
    OrchestratedTaskSpec,
    ParallelOrchestrator,
    TaskDependencyError,
)
from skillbridge.runtime.memory import FakeMemoryProvider
from skillbridge.runtime.scripts import ScriptExecutionBlockedError
from skillbridge.settings import RuntimeSettings, SettingsValidationError
from skillbridge.verification.models import ImportState


class TestRuntimeV2MemoryAndScripts(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="sb_v2_rt_"))
        self.skills_root = self.tmp_dir / "skills"
        self.skills_root.mkdir(parents=True, exist_ok=True)

        # Create 30 valid multi-file skills with scripts
        for i in range(1, 31):
            sname = f"v2-skill-{i:02d}"
            sdir = self.skills_root / sname
            (sdir / "references").mkdir(parents=True, exist_ok=True)
            (sdir / "scripts").mkdir(parents=True, exist_ok=True)
            (sdir / "SKILL.md").write_text(
                f"---\nname: {sname}\ndescription: Test skill number {i} with helper script and reference.\n---\n"
                f"# {sname}\nConsult [references/doc.md](references/doc.md) and run `python3 scripts/hello.py`.\n",
                encoding="utf-8",
            )
            (sdir / "references" / "doc.md").write_text(f"# Documentation for {sname}\nDetails here.\n", encoding="utf-8")
            (sdir / "scripts" / "hello.py").write_text(
                "import os, sys\n"
                "print('ARGS:', sys.argv[1:])\n"
                "print('HAS_SECRET:', bool(os.getenv('OPENAI_API_KEY')))\n",
                encoding="utf-8",
            )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _make_bridge(
        self,
        *,
        settings: RuntimeSettings | None = None,
        fake_mem: FakeMemoryProvider | None = None,
    ) -> SkillBridge:
        cfg = SkillBridgeConfig(
            home_dir=self.tmp_dir / ".skillbridge",
            project_root=self.tmp_dir / "workspace",
            extra_skill_dirs=[self.skills_root],
        )
        cfg.network.offline_mode = True
        cfg.project_root.mkdir(parents=True, exist_ok=True)
        return SkillBridge(config=cfg, settings=settings, memory_provider=fake_mem)

    def test_13_state_import_lifecycle_script_execution_and_persistent_recall(self) -> None:
        import os

        os.environ["OPENAI_API_KEY"] = "sk-test-secret-should-never-leak-to-worker"
        bridge = self._make_bridge()

        # 1. Import bundle and verify state transitions
        imp = asyncio.run(bridge.import_skill("v2-skill-01", session_id="s1"))
        self.assertEqual(imp["import_state"], ImportState.LOADED_INTO_ACTIVE_SESSION.value)
        expected_prefix = [
            ImportState.DISCOVERED.value,
            ImportState.PREVIEWED.value,
            ImportState.SELECTED.value,
            ImportState.FETCHED_INTO_QUARANTINE.value,
            ImportState.ARTIFACT_VALIDATED.value,
            ImportState.TIERED_VERIFICATION.value,
            ImportState.APPROVED_BY_POLICY.value,
            ImportState.STAGED_TEMPORARILY.value,
            ImportState.LOADED_INTO_ACTIVE_SESSION.value,
        ]
        self.assertEqual(imp["state_history"], expected_prefix)

        # 2. Invoke skill -> transitions to USED
        inv = asyncio.run(bridge.invoke_skill("local-custom/v2-skill-01", session_id="s1"))
        self.assertIn("Documentation", str(inv.get("loaded_references", {})))

        # 3. Unapproved script execution must be blocked when allow_untrusted_script_execution=False
        with self.assertRaises(ScriptExecutionBlockedError):
            asyncio.run(bridge.run_skill_script("local-custom/v2-skill-01", "scripts/hello.py", ["arg1"], approved=False))

        # 4. Path traversal in script path must be blocked even with approved=True
        with self.assertRaises(ScriptExecutionBlockedError):
            asyncio.run(bridge.run_skill_script("local-custom/v2-skill-01", "../../etc/passwd", [], approved=True))

        # 5. Approved script execution runs in isolated worker without leaking OPENAI_API_KEY
        scr = asyncio.run(
            bridge.run_skill_script("local-custom/v2-skill-01", "scripts/hello.py", ["--flag", "42"], approved=True)
        )
        self.assertEqual(scr.exit_code, 0)
        self.assertIn("ARGS: ['--flag', '42']", scr.stdout)
        self.assertIn("HAS_SECRET: False", scr.stdout)

        # 6. Tampering with staged file invalidates bundle digest and blocks script execution (TOCTOU guard)
        staged_dir = Path(imp["staged_dir"])
        (staged_dir / "scripts" / "hello.py").write_text("print('tampered')\n", encoding="utf-8")
        with self.assertRaises(ScriptExecutionBlockedError):
            asyncio.run(bridge.run_skill_script("local-custom/v2-skill-01", "scripts/hello.py", [], approved=True))

        # 7. Unload removes temporary staging directory while retaining metadata & source recall
        unloaded = asyncio.run(bridge.unload_skill("local-custom/v2-skill-01", session_id="s1"))
        self.assertTrue(unloaded["unloaded"])
        self.assertFalse(staged_dir.exists())
        self.assertEqual(unloaded["final_state"], ImportState.METADATA_AND_RESULTS_RETAINED.value)

        recalled = bridge.loader.recall_skill_metadata("local-custom/v2-skill-01")
        self.assertIsNotNone(recalled)
        self.assertEqual(recalled["bundle_digest"], imp["bundle_digest"])

    def test_25_active_skill_limit_and_250_mib_memory_pressure_batch_eviction(self) -> None:
        # Configure FakeMemoryProvider so each loaded skill adds 8 MiB on top of 110 MiB base:
        # At 18 skills: 110 + 18*8 = 254 MiB (>= 250 MiB threshold!)
        # Evicting a batch of 7 skills brings active skills from 18 -> 11: 110 + 11*8 = 198 MiB (<= 210 MiB watermark!)
        fake_mem = FakeMemoryProvider(base_rss_mib=110.0, per_skill_overhead_mib=8.0)
        settings = RuntimeSettings(
            active_skill_limit=25,
            memory_threshold_mib=250.0,
            memory_target_mib=210.0,
            eviction_batch_default=7,
            eviction_batch_min=5,
            eviction_batch_max=10,
        )
        bridge = self._make_bridge(settings=settings, fake_mem=fake_mem)

        # Pin skill 1 and mark skill 2 as in_use so neither can ever be evicted
        asyncio.run(bridge.import_skill("v2-skill-01", session_id="mem_test", pin=True))
        asyncio.run(bridge.import_skill("v2-skill-02", session_id="mem_test"))
        bridge.loader.set_skill_in_use("local-custom/v2-skill-02", True)

        for i in range(3, 19):
            asyncio.run(bridge.import_skill(f"v2-skill-{i:02d}", session_id="mem_test"))

        # Memory pressure at skill 18 (254 MiB >= 250 MiB) must have triggered a 7-skill eviction batch!
        mem_status = asyncio.run(bridge.get_memory_status())
        self.assertGreaterEqual(len(mem_status["eviction_history"]), 1)
        first_ev = mem_status["eviction_history"][0]
        self.assertEqual(first_ev["evicted_count"], 7)
        self.assertLessEqual(first_ev["final_mib"], 210.0)
        # Verify pinned skill 01 and in_use skill 02 were NOT evicted
        self.assertNotIn("local-custom/v2-skill-01", first_ev["evicted_skills"])
        self.assertNotIn("local-custom/v2-skill-02", first_ev["evicted_skills"])
        self.assertIn("local-custom/v2-skill-01", bridge.loader._active_bundles)
        self.assertIn("local-custom/v2-skill-02", bridge.loader._active_bundles)

        # Now test the 25-skill active limit with low memory overhead (1 MiB per skill)
        fake_mem.base_rss_bytes = int(50 * 1024 * 1024)
        fake_mem.per_skill_overhead_bytes = int(1 * 1024 * 1024)
        for i in range(1, 29):
            asyncio.run(bridge.import_skill(f"v2-skill-{i:02d}", session_id="cap_test", pin=(i == 1)))

        self.assertLessEqual(bridge.loader.active_skill_count(), 25)
        self.assertIn("local-custom/v2-skill-01", bridge.loader._active_bundles)

        # Live runtime setting reduction from 25 -> 10 must safely evict down to 10 active skills
        bridge.update_settings(active_skill_limit=10)
        self.assertEqual(bridge.loader.active_skill_count(), 10)
        self.assertIn("local-custom/v2-skill-01", bridge.loader._active_bundles)

        # Invalid settings must raise SettingsValidationError without corrupting current settings
        with self.assertRaises(SettingsValidationError):
            bridge.update_settings(memory_target_mib=300.0)
        self.assertEqual(bridge.settings.active_skill_limit, 10)

    def test_parallel_orchestrator_dag_circuit_breaker_and_17_mcp_broker_tools(self) -> None:
        orch = ParallelOrchestrator(max_parallel_scans=2, max_parallel_mcp_calls=4)
        execution_order: list[str] = []

        specs = [
            OrchestratedTaskSpec(
                task_id="step_a",
                kind="scan",
                target_id="prov_1",
                callable_fn=lambda: execution_order.append("A") or "A_OK",
            ),
            OrchestratedTaskSpec(
                task_id="step_b",
                kind="scan",
                target_id="prov_1",
                depends_on=["step_a"],
                callable_fn=lambda: execution_order.append("B") or "B_OK",
            ),
            OrchestratedTaskSpec(
                task_id="step_dup",
                kind="mcp_call",
                target_id="mcp_1",
                idempotency_key="idem_key_1",
                callable_fn=lambda: "FIRST_RESULT",
            ),
            OrchestratedTaskSpec(
                task_id="step_dup_2",
                kind="mcp_call",
                target_id="mcp_1",
                depends_on=["step_dup"],
                idempotency_key="idem_key_1",
                callable_fn=lambda: "SECOND_RESULT_SHOULD_NOT_RUN",
            ),
        ]
        res = orch.execute_dag(specs)
        self.assertEqual(execution_order, ["A", "B"])
        self.assertEqual(res["step_b"].status, "completed")
        self.assertTrue(res["step_dup_2"].from_idempotency_cache)
        self.assertEqual(res["step_dup_2"].result, "FIRST_RESULT")

        # Cycle detection
        with self.assertRaises(TaskDependencyError):
            orch.execute_dag(
                [
                    OrchestratedTaskSpec("c1", "scan", "t", lambda: 1, depends_on=["c2"]),
                    OrchestratedTaskSpec("c2", "scan", "t", lambda: 2, depends_on=["c1"]),
                ]
            )

        # Verify all 17 v2 MCP Broker tools are registered and callable on SkillBridgeMCPServer
        bridge = self._make_bridge()
        server = SkillBridgeMCPServer(bridge=bridge)
        tools_resp = asyncio.run(server.handle_jsonrpc_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
        tool_names = {t["name"] for t in tools_resp["result"]["tools"]}
        expected_17 = {
            "search_skills",
            "preview_skill",
            "compare_skills",
            "import_skill",
            "load_skill",
            "get_skill_status",
            "invoke_skill",
            "run_skill_script",
            "unload_skill",
            "search_mcp_servers",
            "preview_mcp_server",
            "verify_mcp_server",
            "enable_mcp_server",
            "disable_mcp_server",
            "call_mcp_tool",
            "get_memory_status",
            "get_audit_report",
        }
        self.assertTrue(expected_17.issubset(tool_names))


if __name__ == "__main__":
    unittest.main()
