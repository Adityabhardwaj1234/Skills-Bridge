"""Protocol-compliant MCP JSON-RPC 2.0 Broker Server and Client over stdio for SkillBridge v2.

Exposes the complete 19-operation v2 MCP Broker toolset alongside v1 tool aliases so connected
coding agents (OpenCode, Claude Code, Hermes) can dynamically search, preview, compare, import,
load, batch-load, invoke, execute scripts, manage MCP servers, and monitor memory without registering
hundreds of permanent model-visible tools.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Dict, List, Optional

from skillbridge.bridge import SkillBridge
from skillbridge.config import SkillBridgeConfig

MCP_PROTOCOL_VERSION = "2024-11-05"

SKILLBRIDGE_MCP_TOOLS: List[Dict[str, Any]] = [
    # --- V2 Canonical 17 Broker Tools (Section 10) ---
    {
        "name": "search_skills",
        "description": "Search available skills across local, Hermes 100k+ Hub, skills.sh, GitHub, NVIDIA, and well-known catalogs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "default": 10},
                "source_filter": {"type": "string", "default": "all"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "preview_skill",
        "description": "Non-executing preview of a candidate skill's SKILL.md, file tree, scripts, dependencies, capabilities, and security history.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "skill_id": {"type": "string"},
                "target_client": {"type": "string"},
            },
            "required": ["skill_id"],
        },
    },
    {
        "name": "compare_skills",
        "description": "Preview and compare multiple candidate skills side-by-side, including suitability scores and capability overlap/conflict analysis.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "skill_ids": {"type": "array", "items": {"type": "string"}},
                "query": {"type": "string", "default": ""},
                "target_client": {"type": "string"},
            },
            "required": ["skill_ids"],
        },
    },
    {
        "name": "import_skill",
        "description": "Import a whole-directory skill bundle through the mandatory 13-state Tier 0–3 verification pipeline into temporary active staging.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "skill_id": {"type": "string"},
                "session_id": {"type": "string", "default": "default"},
                "pin": {"type": "boolean", "default": False},
                "approved": {"type": "boolean", "default": False},
            },
            "required": ["skill_id"],
        },
    },
    {
        "name": "import_directory",
        "description": "Import an entire local skill directory (every nested file, not just SKILL.md) through the Tier 0–3 verification pipeline by filesystem path.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "directory": {"type": "string"},
                "session_id": {"type": "string", "default": "default"},
                "pin": {"type": "boolean", "default": False},
                "approved": {"type": "boolean", "default": False},
            },
            "required": ["directory"],
        },
    },
    {
        "name": "load_skill",
        "description": "Load a verified skill's instructions and supporting references just-in-time into isolated session memory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "skill_id": {"type": "string"},
                "session_id": {"type": "string", "default": "default"},
                "include_references": {"type": "boolean", "default": True},
                "allow_dedup_stub": {"type": "boolean", "default": False},
                "approved": {"type": "boolean", "default": False},
            },
            "required": ["skill_id"],
        },
    },
    {
        "name": "load_skills_batch",
        "description": "Load multiple verified skills concurrently through a bounded worker pool. Per-skill failures are isolated and reported without aborting the batch.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "skill_ids": {"type": "array", "items": {"type": "string"}},
                "session_id": {"type": "string", "default": "default"},
                "include_references": {"type": "boolean", "default": True},
                "allow_dedup_stub": {"type": "boolean", "default": False},
                "approved": {"type": "boolean", "default": False},
                "max_workers": {"type": "integer"},
            },
            "required": ["skill_ids"],
        },
    },
    {
        "name": "get_skill_status",
        "description": "Get lifecycle state, digest, verification status, or recalled metadata for a specific skill or all active skills.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "skill_id": {"type": "string"},
            },
        },
    },
    {
        "name": "invoke_skill",
        "description": "Retrieve an active skill's verified instructions and mark it as used for LRU tracking.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "skill_id": {"type": "string"},
                "session_id": {"type": "string", "default": "default"},
            },
            "required": ["skill_id"],
        },
    },
    {
        "name": "run_skill_script",
        "description": "Execute a permitted script inside an active, verified skill bundle in an isolated worker subprocess.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "skill_id": {"type": "string"},
                "relative_path": {"type": "string"},
                "arguments": {"type": "array", "items": {"type": "string"}},
                "approved": {"type": "boolean", "default": False},
            },
            "required": ["skill_id", "relative_path"],
        },
    },
    {
        "name": "unload_skill",
        "description": "Explicitly unload an active skill bundle or session skill, removing temporary staging files while retaining source recall metadata.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "skill_id": {"type": "string", "description": "Skill ID to unload, or '*' to unload the session"},
                "session_id": {"type": "string", "default": "default"},
            },
            "required": ["skill_id"],
        },
    },
    {
        "name": "search_mcp_servers",
        "description": "Search MCP servers across the Official MCP Registry and curated MCP catalog.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "default": 10},
            },
            "required": ["query"],
        },
    },
    {
        "name": "preview_mcp_server",
        "description": "Preview an MCP server's transport, launch command, dependencies, and security assessment.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "server_id": {"type": "string"},
                "target_client": {"type": "string"},
            },
            "required": ["server_id"],
        },
    },
    {
        "name": "verify_mcp_server",
        "description": "Run security, IOC, and least-privilege verification on an MCP server specification.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "server_id": {"type": "string"},
            },
            "required": ["server_id"],
        },
    },
    {
        "name": "enable_mcp_server",
        "description": "Verify and enable an MCP server in the SkillBridge broker.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "server_id": {"type": "string"},
                "approved": {"type": "boolean", "default": False},
            },
            "required": ["server_id"],
        },
    },
    {
        "name": "disable_mcp_server",
        "description": "Disable an active MCP server in the SkillBridge broker and clean up resources.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "server_id": {"type": "string"},
            },
            "required": ["server_id"],
        },
    },
    {
        "name": "call_mcp_tool",
        "description": "Dispatch a validated tool call to an enabled MCP server with concurrency and policy controls.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "server_id": {"type": "string"},
                "tool_name": {"type": "string"},
                "arguments": {"type": "object"},
            },
            "required": ["server_id", "tool_name"],
        },
    },
    {
        "name": "get_memory_status",
        "description": "Return current process-tree RSS, 250 MiB threshold status, 25-skill active capacity, and eviction history.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "get_audit_report",
        "description": "Return recent redacted audit events, verification engine status, and parallel orchestration metrics.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "default": 25},
            },
        },
    },
    # --- V1 Compatible Tool Aliases ---
    {
        "name": "skillbridge_preflight",
        "description": "Mandatory task preflight: searches local and Hermes Hub (100k+) catalogs, previews top candidates, runs security scans, compares suitability, selects the best skill or explicit NO_MATCH, and loads instructions just-in-time.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "task": {"type": "string"},
                "session_id": {"type": "string"},
                "source_filter": {"type": "string", "default": "all"},
                "auto_load": {"type": "boolean", "default": True},
                "approved": {"type": "boolean", "default": False},
            },
            "required": ["task"],
        },
    },
    {
        "name": "skillbridge_search_skills",
        "description": "Alias for search_skills.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "default": 10},
                "source_filter": {"type": "string", "default": "all"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "skillbridge_preview_skill",
        "description": "Alias for preview_skill.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "skill_id": {"type": "string"},
                "target_client": {"type": "string"},
            },
            "required": ["skill_id"],
        },
    },
    {
        "name": "skillbridge_load_skill",
        "description": "Alias for load_skill.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "skill_id": {"type": "string"},
                "session_id": {"type": "string", "default": "default"},
                "include_references": {"type": "boolean", "default": True},
                "allow_dedup_stub": {"type": "boolean", "default": False},
                "approved": {"type": "boolean", "default": False},
            },
            "required": ["skill_id"],
        },
    },
    {
        "name": "skillbridge_load_skills_batch",
        "description": "Alias for load_skills_batch.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "skill_ids": {"type": "array", "items": {"type": "string"}},
                "session_id": {"type": "string", "default": "default"},
                "include_references": {"type": "boolean", "default": True},
                "allow_dedup_stub": {"type": "boolean", "default": False},
                "approved": {"type": "boolean", "default": False},
                "max_workers": {"type": "integer"},
            },
            "required": ["skill_ids"],
        },
    },
    {
        "name": "skillbridge_unload_skill",
        "description": "Alias for unload_skill.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "skill_id": {"type": "string"},
                "session_id": {"type": "string", "default": "default"},
            },
            "required": ["skill_id"],
        },
    },
    {
        "name": "skillbridge_search_mcp",
        "description": "Alias for search_mcp_servers.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "default": 10},
            },
            "required": ["query"],
        },
    },
    {
        "name": "skillbridge_plan_install",
        "description": "Create a dry-run installation plan and configuration diff for installing an extension into OpenCode or Claude Code.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "extension_id": {"type": "string"},
                "target": {"type": "string", "enum": ["opencode", "claude-code"]},
                "scope": {"type": "string", "enum": ["project", "user"], "default": "project"},
            },
            "required": ["extension_id", "target"],
        },
    },
    {
        "name": "skillbridge_record_outcome",
        "description": "Record a verified task outcome to update suitability ranking.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "extension_id": {"type": "string"},
                "decision_id": {"type": "string", "default": "mcp"},
                "session_id": {"type": "string", "default": "default"},
                "task_category": {"type": "string", "default": "general_software"},
                "success": {"type": "boolean"},
                "tests_passed": {"type": "boolean", "default": True},
                "regression_detected": {"type": "boolean", "default": False},
            },
            "required": ["extension_id", "success"],
        },
    },
]


class SkillBridgeMCPServer:
    """Protocol-level JSON-RPC 2.0 MCP broker server over stdio."""

    def __init__(self, bridge: Optional[SkillBridge] = None, config: Optional[SkillBridgeConfig] = None):
        self.bridge = bridge or SkillBridge(config=config)

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch an MCP tools/call invocation to the SkillBridge engine."""
        try:
            if name == "skillbridge_preflight":
                decision = await self.bridge.preflight(
                    str(arguments["task"]),
                    session_id=arguments.get("session_id"),
                    source_filter=str(arguments.get("source_filter", "all")),
                    auto_load=bool(arguments.get("auto_load", True)),
                    approved=bool(arguments.get("approved", False)),
                )
                return self._ok(decision.to_dict())

            if name in ("search_skills", "skillbridge_search_skills"):
                recs = await self.bridge.search_skills(
                    str(arguments["query"]),
                    limit=int(arguments.get("limit", 10)),
                    source_filter=str(arguments.get("source_filter", "all")),
                )
                return self._ok({"count": len(recs), "skills": [r.to_dict() for r in recs]})

            if name in ("preview_skill", "skillbridge_preview_skill"):
                prev = await self.bridge.preview_skill(
                    str(arguments["skill_id"]),
                    target_client=arguments.get("target_client"),
                )
                if not prev:
                    return self._err(f"Extension '{arguments['skill_id']}' not found")
                return self._ok(prev.to_dict())

            if name == "compare_skills":
                comp = await self.bridge.compare_skills(
                    list(arguments.get("skill_ids") or []),
                    query=str(arguments.get("query", "")),
                    target_client=arguments.get("target_client"),
                )
                return self._ok(comp)

            if name == "import_skill":
                imp = await self.bridge.import_skill(
                    str(arguments["skill_id"]),
                    session_id=str(arguments.get("session_id", "default")),
                    pin=bool(arguments.get("pin", False)),
                    approved=bool(arguments.get("approved", False)),
                )
                return self._ok(imp)

            if name == "import_directory":
                imp = await self.bridge.import_local_directory(
                    str(arguments["directory"]),
                    session_id=str(arguments.get("session_id", "default")),
                    pin=bool(arguments.get("pin", False)),
                    approved=bool(arguments.get("approved", False)),
                )
                return self._ok(imp)

            if name in ("load_skill", "skillbridge_load_skill"):
                handle = await self.bridge.load_skill(
                    str(arguments["skill_id"]),
                    session_id=str(arguments.get("session_id", "default")),
                    include_references=bool(arguments.get("include_references", True)),
                    allow_dedup_stub=bool(arguments.get("allow_dedup_stub", False)),
                    approved=bool(arguments.get("approved", False)),
                )
                return self._ok(handle.to_dict(include_body=True))

            if name in ("load_skills_batch", "skillbridge_load_skills_batch"):
                raw_ids = arguments.get("skill_ids") or []
                if not isinstance(raw_ids, list):
                    return self._err("Invalid 'skill_ids': must be an array of skill identifiers")
                res = await self.bridge.load_skills_parallel(
                    [str(x) for x in raw_ids],
                    session_id=str(arguments.get("session_id", "default")),
                    include_references=bool(arguments.get("include_references", True)),
                    allow_dedup_stub=bool(arguments.get("allow_dedup_stub", False)),
                    approved=bool(arguments.get("approved", False)),
                    max_workers=arguments.get("max_workers"),
                )
                return self._ok(res)

            if name == "get_skill_status":
                st = await self.bridge.get_skill_status(arguments.get("skill_id"))
                return self._ok(st)

            if name == "invoke_skill":
                inv = await self.bridge.invoke_skill(
                    str(arguments["skill_id"]),
                    session_id=str(arguments.get("session_id", "default")),
                )
                return self._ok(inv)

            if name == "run_skill_script":
                res = await self.bridge.run_skill_script(
                    str(arguments["skill_id"]),
                    str(arguments["relative_path"]),
                    arguments=list(arguments.get("arguments") or []),
                    approved=bool(arguments.get("approved", False)),
                )
                return self._ok(res.to_dict())

            if name in ("unload_skill", "skillbridge_unload_skill"):
                skill_id = str(arguments["skill_id"])
                session_id = str(arguments.get("session_id", "default"))
                if skill_id == "*":
                    res = await self.bridge.unload_session(session_id)
                else:
                    res = await self.bridge.unload_skill(skill_id, session_id=session_id)
                return self._ok(res)

            if name in ("search_mcp_servers", "skillbridge_search_mcp"):
                recs = await self.bridge.search_mcp(
                    str(arguments["query"]),
                    limit=int(arguments.get("limit", 10)),
                )
                return self._ok({"count": len(recs), "mcp_servers": [r.to_dict() for r in recs]})

            if name == "preview_mcp_server":
                sid = str(arguments["server_id"])
                ext_id = sid if sid.startswith("mcp") else f"mcp/{sid}"
                prev = await self.bridge.preview_extension(ext_id, target_client=arguments.get("target_client"))
                if not prev:
                    prev = await self.bridge.preview_extension(sid, target_client=arguments.get("target_client"))
                if not prev:
                    return self._err(f"MCP server '{sid}' not found")
                return self._ok(prev.to_dict())

            if name == "verify_mcp_server":
                ver = await self.bridge.verify_mcp_server(str(arguments["server_id"]))
                return self._ok(ver)

            if name == "enable_mcp_server":
                en = await self.bridge.enable_mcp_server(
                    str(arguments["server_id"]),
                    approved=bool(arguments.get("approved", False)),
                )
                return self._ok(en)

            if name == "disable_mcp_server":
                dis = await self.bridge.disable_mcp_server(str(arguments["server_id"]))
                return self._ok(dis)

            if name == "call_mcp_tool":
                call_out = await self.bridge.call_mcp_tool(
                    str(arguments["server_id"]),
                    str(arguments["tool_name"]),
                    arguments=arguments.get("arguments"),
                )
                return self._ok(call_out)

            if name == "get_memory_status":
                mem = await self.bridge.get_memory_status()
                return self._ok(mem)

            if name == "get_audit_report":
                aud = await self.bridge.get_audit_report(limit=int(arguments.get("limit", 25)))
                return self._ok(aud)

            if name == "skillbridge_plan_install":
                plan = await self.bridge.plan_install(
                    str(arguments["extension_id"]),
                    str(arguments["target"]),
                    scope=str(arguments.get("scope", "project")),
                    dry_run=True,
                )
                return self._ok(plan.to_dict())

            if name == "skillbridge_record_outcome":
                recorded = await self.bridge.record_outcome(arguments)
                return self._ok({"recorded": recorded})

            return self._err(f"Unknown tool: {name}")
        except Exception as exc:
            return self._err(f"{type(exc).__name__}: {exc}")

    @staticmethod
    def _ok(payload: Any) -> Dict[str, Any]:
        return {
            "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, default=str)}],
            "isError": False,
        }

    @staticmethod
    def _err(message: str) -> Dict[str, Any]:
        return {
            "content": [{"type": "text", "text": json.dumps({"error": message}, ensure_ascii=False)}],
            "isError": True,
        }

    async def handle_jsonrpc_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a single JSON-RPC 2.0 request or notification."""
        method = message.get("method", "")
        msg_id = message.get("id")
        params = message.get("params") or {}

        if msg_id is None:
            return None

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "resources": {"subscribe": False, "listChanged": False},
                        "prompts": {"listChanged": False},
                    },
                    "serverInfo": {
                        "name": "skillbridge",
                        "version": "2.0.0",
                    },
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": SKILLBRIDGE_MCP_TOOLS},
            }

        if method == "tools/call":
            tool_name = str(params.get("name") or "")
            tool_args = params.get("arguments") or {}
            if not isinstance(tool_args, dict):
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32602, "message": "Invalid arguments: must be an object"},
                }
            call_res = await self.handle_tool_call(tool_name, tool_args)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": call_res,
            }

        if method == "resources/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "resources": [
                        {
                            "uri": "skillbridge://catalog/summary",
                            "name": "SkillBridge Catalog Summary",
                            "mimeType": "application/json",
                            "description": "Current counts and health of the SkillBridge extension catalog",
                        }
                    ]
                },
            }

        if method == "resources/read":
            uri = params.get("uri", "")
            status = await self.bridge.verify_target()
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": json.dumps(status, default=str),
                        }
                    ]
                },
            }

        if method == "prompts/list":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"prompts": []}}

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    def run_stdio_sync(self) -> int:
        """Run the newline-delimited JSON-RPC 2.0 MCP server loop over sys.stdin / sys.stdout."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            for raw_line in sys.stdin:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    err_resp = {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": "Parse error"},
                    }
                    sys.stdout.write(json.dumps(err_resp) + "\n")
                    sys.stdout.flush()
                    continue

                resp = loop.run_until_complete(self.handle_jsonrpc_message(msg))
                if resp is not None:
                    sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
                    sys.stdout.flush()
            return 0
        finally:
            loop.close()


class MCPStdioClient:
    """Protocol-level MCP stdio client that spawns a real subprocess and communicates via JSON-RPC 2.0 over pipes."""

    def __init__(self, command: Optional[List[str]] = None, env: Optional[Dict[str, str]] = None):
        self.command = command or [sys.executable, "-m", "skillbridge", "mcp-serve"]
        self.env = env
        self.proc: Optional[subprocess.Popen] = None
        self._req_id = 0

    def __enter__(self) -> MCPStdioClient:
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def start(self) -> None:
        self.proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
            env=self.env,
        )

    def request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not self.proc or not self.proc.stdin or not self.proc.stdout:
            raise RuntimeError("MCPStdioClient process is not running")
        self._req_id += 1
        req = {
            "jsonrpc": "2.0",
            "id": self._req_id,
            "method": method,
            "params": params or {},
        }
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            stderr_out = self.proc.stderr.read() if self.proc.stderr else ""
            raise RuntimeError(f"MCP server closed stdout unexpectedly. Stderr: {stderr_out}")
        return json.loads(line)

    def notify(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        if not self.proc or not self.proc.stdin:
            raise RuntimeError("MCPStdioClient process is not running")
        msg = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def initialize(self) -> Dict[str, Any]:
        resp = self.request(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "skillbridge-test-client", "version": "2.0.0"},
            },
        )
        self.notify("notifications/initialized")
        return resp

    def list_tools(self) -> List[Dict[str, Any]]:
        resp = self.request("tools/list")
        return resp.get("result", {}).get("tools", [])

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        resp = self.request("tools/call", {"name": name, "arguments": arguments})
        if "error" in resp:
            raise RuntimeError(f"MCP RPC error: {resp['error']}")
        result = resp.get("result", {})
        content = result.get("content", [])
        parsed = json.loads(content[0]["text"]) if content and "text" in content[0] else {}
        return {"isError": result.get("isError", False), "data": parsed}

    def close(self) -> None:
        if self.proc:
            try:
                for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
                    if stream:
                        try:
                            stream.close()
                        except Exception:
                            pass
                self.proc.wait(timeout=3.0)
            except Exception:
                self.proc.kill()
                self.proc.wait(timeout=1.0)
            finally:
                self.proc = None
