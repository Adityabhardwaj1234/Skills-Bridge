"""Integration tests for mocked GitHub, skills.sh, well-known, MCP Registry, OpenCode/Claude Code adapters, and live stdio MCP server."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import httpx

from skillbridge.bridge import SkillBridge
from skillbridge.config import SkillBridgeConfig
from skillbridge.mcp_server.server import MCPStdioClient
from skillbridge.providers.base import GuardedHttpClient


class TestSkillBridgeIntegration(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="sb_int_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_mocked_remote_providers_github_skillssh_wellknown_and_mcp_registry(self) -> None:
        def mock_router(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "skills.sh/api/search" in url:
                return httpx.Response(
                    200,
                    json={
                        "skills": [
                            {
                                "id": "vercel/ai/nextjs-streaming",
                                "name": "nextjs-streaming",
                                "description": "Implement Next.js streaming UI with AI SDK",
                                "tags": ["nextjs", "streaming", "frontend"],
                                "installs": 4200,
                            }
                        ]
                    },
                )
            if "api.github.com/repos/vercel/ai/git/trees/main" in url:
                return httpx.Response(
                    200,
                    json={
                        "sha": "commitsha123456",
                        "truncated": False,
                        "tree": [
                            {"path": "nextjs-streaming/SKILL.md", "type": "blob", "mode": "100644"},
                            {"path": "nextjs-streaming/references/guide.md", "type": "blob", "mode": "100644"},
                        ],
                    },
                )
            if "api.github.com/repos/vercel/ai" in url:
                return httpx.Response(200, json={"default_branch": "main"})
            if "raw.githubusercontent.com/vercel/ai/commitsha123456/nextjs-streaming/SKILL.md" in url or "raw.githubusercontent.com/vercel/ai/main/nextjs-streaming/SKILL.md" in url:
                return httpx.Response(
                    200,
                    text="---\nname: nextjs-streaming\ndescription: Implement Next.js streaming UI with AI SDK\n---\n"
                    "# Next.js Streaming\nSee [references/guide.md](references/guide.md).\n",
                )
            if "raw.githubusercontent.com/vercel/ai/commitsha123456/nextjs-streaming/references/guide.md" in url:
                return httpx.Response(200, text="# Streaming Guide\nUse streamText().\n")

            if "docs.example.com/.well-known/skills/index.json" in url:
                return httpx.Response(
                    200,
                    json={
                        "skills": [
                            {
                                "name": "acme-deploy",
                                "description": "Deploy Acme cloud services via well-known skill",
                                "files": ["SKILL.md", "references/deploy.md"],
                            }
                        ]
                    },
                )
            if "docs.example.com/.well-known/skills/acme-deploy/SKILL.md" in url:
                return httpx.Response(
                    200,
                    text="---\nname: acme-deploy\ndescription: Deploy Acme cloud services via well-known skill\n---\n"
                    "# Acme Deploy\nSee [references/deploy.md](references/deploy.md).\n",
                )
            if "docs.example.com/.well-known/skills/acme-deploy/references/deploy.md" in url:
                return httpx.Response(200, text="Run `acme deploy --prod`.\n")

            if "registry.modelcontextprotocol.io/v0/servers" in url:
                return httpx.Response(
                    200,
                    json={
                        "servers": [
                            {
                                "name": "io.github.acme/sqlite-mcp",
                                "description": "Query local SQLite databases over MCP",
                                "version": "1.2.0",
                                "packages": [
                                    {
                                        "registry_name": "pypi",
                                        "name": "mcp-server-sqlite",
                                        "runtime_hint": "uvx",
                                    }
                                ],
                            }
                        ]
                    },
                )
            return httpx.Response(404)

        cfg = SkillBridgeConfig(home_dir=self.tmp_dir / ".sb", project_root=self.tmp_dir)
        cfg.network.offline_mode = False
        http_client = GuardedHttpClient(cfg.network, transport=httpx.MockTransport(mock_router))
        bridge = SkillBridge(config=cfg)
        bridge.discovery.http = http_client
        bridge.discovery.hermes_hub_provider.http = http_client
        bridge.discovery.github_provider.http = http_client
        bridge.discovery.well_known_provider.http = http_client
        bridge.discovery.mcp_provider.http = http_client

        async def _run() -> None:
            sh_hits = bridge.discovery.hermes_hub_provider.search_skills_sh("nextjs")
            self.assertTrue(any(r.name == "nextjs-streaming" for r in sh_hits))
            gh_bundle = bridge.discovery.github_provider.fetch_bundle("vercel/ai/nextjs-streaming")
            self.assertIsNotNone(gh_bundle)
            assert gh_bundle is not None
            self.assertIn("references/guide.md", gh_bundle.files)
            self.assertEqual(gh_bundle.metadata["revision"], "commitsha123456")

            wk_hits = bridge.discovery.well_known_provider.search("https://docs.example.com")
            self.assertEqual(len(wk_hits), 1)
            self.assertEqual(wk_hits[0].name, "acme-deploy")
            wk_bundle = bridge.discovery.well_known_provider.fetch_bundle(wk_hits[0].extension_id)
            self.assertIsNotNone(wk_bundle)
            assert wk_bundle is not None
            self.assertIn("references/deploy.md", wk_bundle.files)

            mcp_hits = await bridge.search_mcp("sqlite")
            self.assertTrue(any(r.name == "sqlite-mcp" for r in mcp_hits))

        asyncio.run(_run())

    def test_opencode_and_claude_code_config_merge_backup_and_rollback(self) -> None:
        proj_dir = self.tmp_dir / "project"
        user_home = self.tmp_dir / "home"
        proj_dir.mkdir(parents=True)
        user_home.mkdir(parents=True)

        oc_cfg_path = proj_dir / "opencode.jsonc"
        initial_oc = """// Team OpenCode config
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["existing-plugin"],
  "mcp": {
    "existing-server": {
      "type": "remote",
      "url": "https://mcp.existing.dev/mcp"
    }
  }
}
"""
        oc_cfg_path.write_text(initial_oc, encoding="utf-8")

        cc_mcp_path = proj_dir / ".mcp.json"
        initial_cc = json.dumps(
            {"mcpServers": {"existing-claude-mcp": {"type": "http", "url": "https://docs.claude.com/mcp"}}},
            indent=2,
        ) + "\n"
        cc_mcp_path.write_text(initial_cc, encoding="utf-8")

        cfg = SkillBridgeConfig(home_dir=self.tmp_dir / ".sb", project_root=proj_dir)
        cfg.network.offline_mode = True
        bridge = SkillBridge(config=cfg, project_root=proj_dir, user_home=user_home)

        async def _run() -> None:
            plan_oc = await bridge.plan_install(
                "mcp/playwright",
                "opencode",
                scope="project",
                dry_run=False,
                approved=True,
                lazy_disable_globally=True,
            )
            res_oc = await bridge.apply_install(plan_oc, approved=True)
            self.assertTrue(res_oc["verification"]["discoverable"])

            updated_oc_text = oc_cfg_path.read_text(encoding="utf-8")
            self.assertIn("// Team OpenCode config", updated_oc_text)
            self.assertIn("existing-plugin", updated_oc_text)
            self.assertIn("existing-server", updated_oc_text)
            self.assertIn('"playwright"', updated_oc_text)
            self.assertIn('"playwright_*": false', updated_oc_text)

            rb_oc = await bridge.rollback_install(plan_oc.plan_id)
            self.assertEqual(rb_oc["status"], "rolled_back")
            self.assertEqual(oc_cfg_path.read_text(encoding="utf-8"), initial_oc)

            plan_cc = await bridge.plan_install(
                "mcp/playwright",
                "claude-code",
                scope="project",
                dry_run=False,
                approved=True,
            )
            res_cc = await bridge.apply_install(plan_cc, approved=True)
            self.assertTrue(res_cc["verification"]["discoverable"])
            cc_data = json.loads(cc_mcp_path.read_text(encoding="utf-8"))
            self.assertIn("existing-claude-mcp", cc_data["mcpServers"])
            self.assertIn("playwright", cc_data["mcpServers"])
            self.assertEqual(cc_data["mcpServers"]["playwright"]["type"], "stdio")

            rb_cc = await bridge.rollback_install(plan_cc.plan_id)
            self.assertEqual(rb_cc["status"], "rolled_back")
            self.assertEqual(cc_mcp_path.read_text(encoding="utf-8"), initial_cc)

            agent_plan_oc = await bridge.plan_install(
                "official/devops/sdlc-review",
                "opencode",
                scope="project",
                dry_run=False,
                approved=True,
                extension_type_override="agent",
            )
            await bridge.apply_install(agent_plan_oc, approved=True)
            self.assertTrue((proj_dir / ".opencode" / "agents" / "sdlc-review.md").is_file())
            await bridge.rollback_install(agent_plan_oc.plan_id)
            self.assertFalse((proj_dir / ".opencode" / "agents" / "sdlc-review.md").exists())

        asyncio.run(_run())

    def test_real_protocol_level_stdio_mcp_server(self) -> None:
        env = dict(os.environ)
        src_path = str(Path(__file__).resolve().parents[2] / "src")
        env["PYTHONPATH"] = f"{src_path}{os.pathsep}{env.get('PYTHONPATH', '')}"
        env["SKILLBRIDGE_HOME"] = str(self.tmp_dir / ".sb_mcp")

        cmd = [sys.executable, "-m", "skillbridge", "--offline", "mcp-serve"]
        with MCPStdioClient(command=cmd, env=env) as client:
            init_resp = client.initialize()
            self.assertEqual(init_resp["result"]["serverInfo"]["name"], "skillbridge")

            tools = client.list_tools()
            tool_names = {t["name"] for t in tools}
            self.assertIn("skillbridge_preflight", tool_names)
            self.assertIn("skillbridge_search_skills", tool_names)
            self.assertIn("skillbridge_load_skill", tool_names)
            self.assertIn("skillbridge_unload_skill", tool_names)

            pf_call = client.call_tool("skillbridge_preflight", {"task": "Extract tables from a PDF file", "session_id": "mcp_sess_1"})
            self.assertFalse(pf_call["isError"])
            pf_data = pf_call["data"]
            self.assertIn("decision_id", pf_data)
            self.assertTrue(pf_data["runtime_loaded"])

            ul_call = client.call_tool("skillbridge_unload_skill", {"skill_id": "*", "session_id": "mcp_sess_1"})
            self.assertFalse(ul_call["isError"])
            self.assertGreaterEqual(ul_call["data"]["unloaded_count"], 1)


if __name__ == "__main__":
    unittest.main()
