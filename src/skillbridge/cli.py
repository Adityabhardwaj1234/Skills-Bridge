"""Command-Line Interface for SkillBridge v2."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import sys
from typing import Any, List, Optional

from skillbridge import __version__
from skillbridge.bridge import SkillBridge
from skillbridge.config import SkillBridgeConfig
from skillbridge.evaluation.runner import run_evaluation_suite
from skillbridge.mcp_server.server import SkillBridgeMCPServer
from skillbridge.reporting.generator import generate_dashboard_html
from skillbridge.security.policy import format_security_report


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skillbridge",
        description="SkillBridge v2 — Flagship Security, Multi-Tier Verification, Runtime Memory & MCP Orchestration for Coding Agents",
    )
    parser.add_argument("--json", action="store_true", help="Emit structured JSON output for automation")
    parser.add_argument("--offline", action="store_true", help="Force offline mode (local catalog and cached index only)")
    parser.add_argument("--home", type=str, default=None, help="Override SkillBridge state directory (~/.skillbridge)")
    parser.add_argument("--project-root", type=str, default=None, help="Override target project root directory")
    parser.add_argument("--version", action="version", version=f"skillbridge {__version__}")

    sub = parser.add_subparsers(dest="command", help="Available SkillBridge v2 operations")

    # scan
    p_scan = sub.add_parser("scan", help="Scan a skill directory or index local catalogs for security issues")
    p_scan.add_argument("path", nargs="?", default=None, help="Optional path to a specific skill directory or file to scan")
    p_scan.add_argument("--source", default="community", help="Source label for trust policy evaluation")
    p_scan.add_argument("--trust", default="community", choices=["builtin", "trusted", "community", "untrusted"])

    # search-skills
    p_ss = sub.add_parser("search-skills", help="Search available skills across local, Hermes 100k+ Hub, GitHub, NVIDIA, and well-known catalogs")
    p_ss.add_argument("query", help="Search query string")
    p_ss.add_argument("--source", default="all", help="Filter by source provider (all, local, hermes-hub, github, well-known)")
    p_ss.add_argument("--limit", type=int, default=15, help="Maximum results to return")

    # list (v2)
    p_list = sub.add_parser("list", help="List indexed catalog skills or MCP servers")
    p_list.add_argument("--limit", type=int, default=25, help="Maximum entries to list")

    # preview-skill & preview (v2 alias)
    for cmd_name in ("preview-skill", "preview"):
        p_ps = sub.add_parser(cmd_name, help="Preview a candidate skill's metadata, instructions, references, scripts, dependencies, and security")
        p_ps.add_argument("skill_id", help="Skill identifier or name")
        p_ps.add_argument("--target", default=None, choices=["opencode", "claude-code", "hermes"], help="Target client for compatibility check")

    # import (v2 13-state bundle import)
    p_imp = sub.add_parser("import", help="Import a whole-directory skill bundle through the mandatory Tier 0–3 verification pipeline")
    p_imp.add_argument("skill_id", help="Skill identifier to import")
    p_imp.add_argument("--session-id", default="cli_session", help="Session identifier")
    p_imp.add_argument("--pin", action="store_true", help="Pin skill to protect from automatic LRU eviction")
    p_imp.add_argument("--approve", action="store_true", help="Approve CAUTION community extensions")

    # preflight
    p_pf = sub.add_parser("preflight", help="Execute mandatory task preflight (search -> preview -> compare -> scan -> select -> load)")
    p_pf.add_argument("task", help="Task description or user prompt")
    p_pf.add_argument("--session-id", default="cli_session", help="Session identifier")
    p_pf.add_argument("--source", default="all", help="Source filter")
    p_pf.add_argument("--no-load", action="store_true", help="Do not load selected skill into temporary runtime memory")
    p_pf.add_argument("--approve", action="store_true", help="Approve CAUTION or community code extensions (never overrides DANGEROUS)")

    # load-skill
    p_ls = sub.add_parser("load-skill", help="Load a verified skill just-in-time into isolated session runtime memory")
    p_ls.add_argument("skill_id", help="Skill identifier to load")
    p_ls.add_argument("--session-id", default="cli_session", help="Isolated session identifier")
    p_ls.add_argument("--approve", action="store_true", help="Approve CAUTION community skill if needed")
    p_ls.add_argument("--unload-after", action="store_true", help="Automatically unload skill after verification")

    # load-batch
    p_lb = sub.add_parser("load-batch", help="Load multiple skills concurrently through a bounded parallel worker pool")
    p_lb.add_argument("skill_ids", nargs="+", help="Skill identifiers to load in parallel")
    p_lb.add_argument("--session-id", default="cli_session", help="Isolated session identifier")
    p_lb.add_argument("--workers", type=int, default=None, help="Override worker count (default: loader_limits.max_parallel_workers)")
    p_lb.add_argument("--approve", action="store_true", help="Approve CAUTION community skills if needed")

    # import-dir
    p_idir = sub.add_parser("import-dir", help="Import an entire local skill directory (all files, not just SKILL.md) through Tier 0-3")
    p_idir.add_argument("directory", help="Path to a skill directory containing SKILL.md at its root")
    p_idir.add_argument("--session-id", default="cli_session", help="Session identifier")
    p_idir.add_argument("--pin", action="store_true", help="Pin the imported skill to protect it from LRU eviction")
    p_idir.add_argument("--approve", action="store_true", help="Approve CAUTION community extensions")

    # ui
    p_ui = sub.add_parser("ui", help="Generate (and optionally serve) the flagship HTML product console from live state")
    p_ui.add_argument("--out", default="reports/ui.html", help="Output HTML path (default: reports/ui.html)")
    p_ui.add_argument("--serve", action="store_true", help="Serve the console over localhost after generating it")
    p_ui.add_argument("--port", type=int, default=8760, help="Port for --serve (default: 8760)")
    p_ui.add_argument("--open", action="store_true", help="Open the console in the default browser when serving")

    # unload-skill & unload (v2 alias)
    for cmd_name in ("unload-skill", "unload"):
        p_us = sub.add_parser(cmd_name, help="Unload a skill or entire session from runtime memory and release references")
        p_us.add_argument("skill_id", nargs="?", default="*", help="Skill identifier to unload, or '*' to unload all")
        p_us.add_argument("--all", action="store_true", help="Unload all active skills and sessions")
        p_us.add_argument("--session-id", default="cli_session", help="Isolated session identifier")

    # status & loaded (v2)
    for cmd_name in ("status", "loaded"):
        p_st = sub.add_parser(cmd_name, help="Show active loaded skills, bundle states, and runtime status")
        p_st.add_argument("skill_id", nargs="?", default=None, help="Optional specific skill ID")

    # run-script (v2)
    p_rs = sub.add_parser("run-script", help="Execute a permitted script inside an imported skill bundle in an isolated worker")
    p_rs.add_argument("skill_id", help="Skill ID containing the script")
    p_rs.add_argument("relative_path", help="Relative script path inside the bundle (e.g. scripts/example.py)")
    p_rs.add_argument("script_args", nargs="*", default=[], help="Arguments passed to the script")
    p_rs.add_argument("--approve", action="store_true", help="Explicitly approve script execution")

    # search-mcp
    p_sm = sub.add_parser("search-mcp", help="Search MCP servers across the Official MCP Registry and Nous-approved catalog")
    p_sm.add_argument("query", help="Search query for MCP servers")
    p_sm.add_argument("--limit", type=int, default=15, help="Maximum results")

    # preview-mcp
    p_pm = sub.add_parser("preview-mcp", help="Preview an MCP server's transport, launch command, auth, dependencies, and security")
    p_pm.add_argument("server_id", help="MCP server identifier or name (e.g., mcp/context7, filesystem, playwright)")
    p_pm.add_argument("--target", default=None, choices=["opencode", "claude-code"], help="Target client")

    # enable-mcp & disable-mcp (v2)
    p_em = sub.add_parser("enable-mcp", help="Verify and enable an MCP server in the SkillBridge broker")
    p_em.add_argument("server_id", help="MCP server identifier")
    p_em.add_argument("--approve", action="store_true", help="Approve enabling MCP server")

    p_dm = sub.add_parser("disable-mcp", help="Disable an active MCP server in the SkillBridge broker")
    p_dm.add_argument("server_id", help="MCP server identifier")

    # memory (v2)
    sub.add_parser("memory", help="Show process-tree RSS, 250 MiB threshold, 25-skill active limit, and eviction telemetry")

    # doctor (v2)
    sub.add_parser("doctor", help="Run comprehensive diagnostics on OS, Python, SQLite, verification engines, and client configs")

    # sbom (v2)
    p_sbom = sub.add_parser("sbom", help="Generate CycloneDX 1.6 Software Bill of Materials (SBOM)")
    p_sbom.add_argument("--output", default="reports/sbom.cdx.json", help="Output path for CycloneDX SBOM JSON")

    # install
    p_inst = sub.add_parser("install", help="Plan or apply installation of a skill, agent, or MCP server into OpenCode or Claude Code")
    p_inst.add_argument("extension_id", help="Extension ID to install (or 'skillbridge-mcp' to register SkillBridge as an MCP server)")
    p_inst.add_argument("--target", required=True, choices=["opencode", "claude-code"], help="Target coding agent client")
    p_inst.add_argument("--scope", default="project", choices=["project", "user"], help="Installation scope (project or user)")
    p_inst.add_argument("--type", default=None, choices=["skill", "agent", "mcp_server"], help="Optional extension type override")
    p_inst.add_argument("--dry-run", action="store_true", default=True, help="Preview planned changes without writing files (default)")
    p_inst.add_argument("--apply", action="store_true", help="Apply the installation plan to disk with atomic writes and backup")
    p_inst.add_argument("--approve", action="store_true", help="Explicitly approve CAUTION or config-modifying changes")
    p_inst.add_argument("--lazy-mcp", action="store_true", help="Disable MCP tools globally in OpenCode so they activate per-agent only")

    # rollback
    p_rb = sub.add_parser("rollback", help="Roll back a previously applied installation plan using its backup manifest")
    p_rb.add_argument("plan_id", help="Installation plan ID (e.g., plan_...)")

    # verify
    p_ver = sub.add_parser("verify", help="Verify SkillBridge database, providers, cache stats, and detected native clients")
    p_ver.add_argument("--target", default=None, choices=["opencode", "claude-code"], help="Optional specific client target")

    # evaluate
    p_eval = sub.add_parser("evaluate", help="Run the end-to-end evaluation suite and output metrics")
    p_eval.add_argument("--output", default="reports/eval_report.json", help="Path to write JSON evaluation report")
    p_eval.add_argument("--dashboard", default="reports/dashboard.html", help="Path to write HTML evaluation dashboard")

    # report
    sub.add_parser("report", help="Display a summary of system catalog, recent audit trail, and evaluation metrics")

    # mcp-serve
    sub.add_parser("mcp-serve", help="Run the SkillBridge MCP broker server over stdio (JSON-RPC 2.0)")

    return parser


def _print_output(data: Any, as_json: bool, human_text: Optional[str] = None) -> None:
    if as_json or human_text is None:
        print(json.dumps(data, indent=2, default=str, ensure_ascii=False))
    else:
        print(human_text)


def _main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    cfg = SkillBridgeConfig()
    if args.home:
        cfg.home_dir = Path(args.home)
    if args.project_root:
        cfg.project_root = Path(args.project_root)
    if args.offline:
        cfg.network.offline_mode = True

    if args.command == "mcp-serve":
        server = SkillBridgeMCPServer(config=cfg)
        return server.run_stdio_sync()

    bridge = SkillBridge(config=cfg)

    try:
        if args.command == "scan":
            if args.path:
                target = Path(args.path)
                if not target.exists():
                    print(f"Error: Scan path does not exist: {target}", file=sys.stderr)
                    return 2
                assessment = bridge.scan_path(target, source=args.source, trust_level=args.trust)
                _print_output(assessment.to_dict(), args.json, format_security_report(assessment))
                return 1 if assessment.verdict == "DANGEROUS" else 0
            else:
                counts = bridge.discovery.ensure_catalog_seeded(force_rescan=True)
                msg = (
                    f"SkillBridge Catalog Scan Complete:\n"
                    f"  Indexed Skills      : {counts['skills']}\n"
                    f"  Indexed MCP Servers : {counts['mcp_servers']}\n"
                    f"  SQLite Catalog Path : {cfg.db_path}"
                )
                _print_output(counts, args.json, msg)
                return 0

        if args.command == "search-skills":
            recs = asyncio.run(bridge.search_skills(args.query, source_filter=args.source, limit=args.limit))
            lines = [f"Found {len(recs)} skill(s) for '{args.query}':"]
            for r in recs:
                lines.append(f"  - {r.extension_id:45s} [{r.source_provider}/{r.trust_level}] {r.description[:80]}")
            _print_output([r.to_dict() for r in recs], args.json, "\n".join(lines))
            return 0

        if args.command == "list":
            recs = asyncio.run(bridge.search_skills("python git testing security", limit=args.limit))
            lines = [f"Catalog Listing ({len(recs)} items):"]
            for r in recs:
                lines.append(f"  - {r.extension_id:45s} [{r.source_provider}] {r.description[:75]}")
            _print_output([r.to_dict() for r in recs], args.json, "\n".join(lines))
            return 0

        if args.command in ("preview-skill", "preview"):
            prev = asyncio.run(bridge.preview_skill(args.skill_id, target_client=args.target))
            if not prev:
                print(f"Error: Skill '{args.skill_id}' not found.", file=sys.stderr)
                return 2
            verdict = prev.security.verdict if prev.security else "UNKNOWN"
            text = (
                f"Skill Preview: {prev.extension_id} ({prev.name})\n"
                f"  Source / Trust     : {prev.source_provider} ({prev.trust_level})\n"
                f"  Description        : {prev.description}\n"
                f"  Body Size / Tokens : {prev.full_body_chars} chars (~{prev.estimated_tokens} tokens)\n"
                f"  Referenced Files   : {', '.join(prev.referenced_files) or 'none'}\n"
                f"  Scripts Detected   : {', '.join(prev.scripts_detected) or 'none'}\n"
                f"  Security Verdict   : {verdict} ({len(prev.security.findings if prev.security else [])} finding(s))\n"
                f"  Suitability Score  : {prev.total_score:.1f}/100 {prev.score_breakdown}\n"
                f"  Limitations        : {'; '.join(prev.limitations) or 'none'}"
            )
            _print_output(prev.to_dict(), args.json, text)
            return 0

        if args.command == "import":
            imp = asyncio.run(
                bridge.import_skill(
                    args.skill_id,
                    session_id=args.session_id,
                    pin=args.pin,
                    approved=args.approve,
                )
            )
            ver = imp["verification"]
            text = (
                f"Imported Whole-Directory Skill Bundle: {imp['skill_id']}\n"
                f"  Import State     : {imp['import_state']}\n"
                f"  Bundle Digest    : {imp['bundle_digest']}\n"
                f"  Assurance State  : {ver['assurance_state']} (Quality Score: {ver['quality_score']:.1f}/100)\n"
                f"  Closure Digest   : {ver['closure_digest']}\n"
                f"  Staged Directory : {imp['staged_dir']}\n"
                f"  Persistence      : catalog, quarantine, and audit persist under --home; staging is temporary and process-local\n"
                f"  Transition Trail : {' -> '.join(imp['state_history'])}"
            )
            _print_output(imp, args.json, text)
            return 0

        if args.command == "preflight":
            decision = asyncio.run(
                bridge.preflight(
                    args.task,
                    session_id=args.session_id,
                    source_filter=args.source,
                    auto_load=not args.no_load,
                    approved=args.approve,
                )
            )
            text = (
                f"SkillBridge Mandatory Preflight Summary\n"
                f"  Decision ID      : {decision.decision_id}\n"
                f"  Session ID       : {decision.session_id}\n"
                f"  Task Category    : {decision.task_category}\n"
                f"  Lifecycle State  : {decision.state}\n"
                f"  Candidates Found : {len(decision.candidate_ids)} (Previewed top {len(decision.previews_inspected)})\n"
                f"  Selected         : {', '.join(decision.selected_ids) if not decision.no_match else 'NO_MATCH'}\n"
                f"  Runtime Loaded   : {decision.runtime_loaded} (Handles: {', '.join(decision.loaded_handles) or 'none'})\n"
                f"  Reason           : {decision.selection_reason}\n"
                f"  Elapsed          : {decision.elapsed_ms:.1f} ms"
            )
            _print_output(decision.to_dict(), args.json, text)
            return 0

        if args.command == "load-skill":
            handle = asyncio.run(
                bridge.load_skill(args.skill_id, session_id=args.session_id, approved=args.approve)
            )
            payload = handle.to_dict(include_body=True)
            if getattr(args, "unload_after", False):
                unload_res = asyncio.run(bridge.unload_skill(handle.extension_id, session_id=args.session_id))
                payload["unloaded_after"] = unload_res
            text = (
                f"Loaded Skill into Temporary Session Memory:\n"
                f"  Handle ID    : {handle.handle_id}\n"
                f"  Session ID   : {handle.session_id}\n"
                f"  Extension ID : {handle.extension_id}\n"
                f"  Content Hash : {handle.content_hash}\n"
                f"  Total Bytes  : {handle.total_bytes} (~{handle.estimated_tokens} tokens)\n"
                f"  References   : {', '.join(handle.loaded_references.keys()) or 'none'}\n"
                f"  Scope        : process-local (this CLI process exits after the command; use 'skillbridge mcp-serve' for persistent sessions)\n"
                f"  Note         : {handle.context_isolation_note}"
            )
            _print_output(payload, args.json, text)
            return 0

        if args.command == "load-batch":
            res = asyncio.run(
                bridge.load_skills_parallel(
                    args.skill_ids,
                    session_id=args.session_id,
                    approved=args.approve,
                    max_workers=args.workers,
                )
            )
            lines = [
                f"Parallel Batch Load Complete:",
                f"  Session        : {res['session_id']}",
                f"  Requested      : {res['requested_count']}",
                f"  Loaded         : {res['loaded_count']} (workers: {res['workers']})",
                f"  Failed         : {res['failed_count']}",
                f"  Elapsed        : {res['elapsed_ms']} ms",
                f"  Scope          : process-local (use 'skillbridge mcp-serve' for persistent sessions)",
            ]
            for item in res["loaded"]:
                lines.append(f"  + {item['extension_id']:45s} {item['total_bytes']} bytes, {item['references_loaded']} refs")
            for failure in res["failed"]:
                lines.append(f"  - {failure['extension_id']:45s} {failure['error']}")
            _print_output(res, args.json, "\n".join(lines))
            return 0 if res["loaded_count"] else 2

        if args.command == "import-dir":
            imp = asyncio.run(
                bridge.import_local_directory(
                    args.directory,
                    session_id=args.session_id,
                    pin=args.pin,
                    approved=args.approve,
                )
            )
            ver = imp["verification"]
            text = (
                f"Imported Local Skill Directory: {imp['imported_path']}\n"
                f"  Extension ID     : {imp['skill_id']}\n"
                f"  Import State     : {imp['import_state']}\n"
                f"  Bundle Digest    : {imp['bundle_digest']}\n"
                f"  Assurance State  : {ver['assurance_state']} (Quality Score: {ver['quality_score']:.1f}/100)\n"
                f"  Staged Directory : {imp['staged_dir']}\n"
                f"  Persistence      : catalog, quarantine, and audit persist under --home; staging is temporary and process-local\n"
                f"  Transition Trail : {' -> '.join(imp['state_history'])}"
            )
            _print_output(imp, args.json, text)
            return 0

        if args.command == "ui":
            from skillbridge.reporting.ui import collect_ui_data, generate_ui_html, serve_ui

            try:
                bridge.discovery.ensure_catalog_seeded()
            except Exception:
                pass
            data = collect_ui_data(bridge)
            out = generate_ui_html(data, Path(args.out))
            if args.serve:
                serve_ui(out, port=args.port, open_browser=args.open)
                return 0
            _print_output(
                {"output": str(out), "catalog": data["catalog"], "providers": len(data["providers"]), "mcp_tools": len(data["mcp_tools"])},
                args.json,
                f"SkillBridge product console generated: {out}\n"
                f"  Catalog   : {data['catalog']['total']} extensions ({data['catalog']['skills']} skills, {data['catalog']['mcp_servers']} MCP servers)\n"
                f"  Providers : {len(data['providers'])}\n"
                f"  MCP tools : {len(data['mcp_tools'])}\n"
                f"  Serve it  : skillbridge ui --serve --open",
            )
            return 0

        if args.command in ("unload-skill", "unload"):
            if getattr(args, "all", False) or args.skill_id == "*":
                res = asyncio.run(bridge.unload_session(args.session_id))
            else:
                res = asyncio.run(bridge.unload_skill(args.skill_id, session_id=args.session_id))
            _print_output(res, args.json, f"Unload Result: {json.dumps(res, indent=2)}")
            return 0

        if args.command in ("status", "loaded"):
            st = asyncio.run(bridge.get_skill_status(args.skill_id))
            _print_output(st, args.json, f"SkillBridge Runtime Status:\n{json.dumps(st, indent=2, default=str)}")
            return 0

        if args.command == "run-script":
            # Ensure bundle is imported first if not already active
            if args.skill_id not in bridge.loader._active_bundles:
                asyncio.run(bridge.import_skill(args.skill_id, approved=args.approve))
            res = asyncio.run(
                bridge.run_skill_script(
                    args.skill_id,
                    args.relative_path,
                    arguments=args.script_args,
                    approved=args.approve,
                )
            )
            _print_output(res.to_dict(), args.json, f"Script Execution Result:\n{json.dumps(res.to_dict(), indent=2)}")
            return 0 if res.exit_code == 0 else 1

        if args.command == "search-mcp":
            recs = asyncio.run(bridge.search_mcp(args.query, limit=args.limit))
            lines = [f"Found {len(recs)} MCP server(s) for '{args.query}':"]
            for r in recs:
                t_type = r.mcp_transport.transport_type if r.mcp_transport else "unknown"
                lines.append(f"  - {r.extension_id:28s} [transport={t_type:5s} | {r.source_provider}] {r.description[:75]}")
            _print_output([r.to_dict() for r in recs], args.json, "\n".join(lines))
            return 0

        if args.command == "preview-mcp":
            ext_id = args.server_id if args.server_id.startswith("mcp") else f"mcp/{args.server_id}"
            prev = asyncio.run(bridge.preview_extension(ext_id, target_client=args.target))
            if not prev:
                prev = asyncio.run(bridge.preview_extension(args.server_id, target_client=args.target))
            if not prev:
                print(f"Error: MCP server '{args.server_id}' not found.", file=sys.stderr)
                return 2
            rec = bridge.discovery.resolve_extension(prev.extension_id)
            t = rec.mcp_transport if rec else None
            text = (
                f"MCP Server Preview: {prev.extension_id} ({prev.name})\n"
                f"  Description      : {prev.description}\n"
                f"  Transport        : {t.transport_type if t else 'n/a'}\n"
                f"  Command / URL    : {(f'{t.command} {t.args}' if t.transport_type == 'stdio' else t.url) if t else 'n/a'}\n"
                f"  Auth Type        : {t.auth_type if t else 'none'}\n"
                f"  Security Verdict : {prev.security.verdict if prev.security else 'UNKNOWN'}\n"
                f"  Missing Deps     : {', '.join(prev.missing_dependencies) or 'none'}"
            )
            _print_output(prev.to_dict(), args.json, text)
            return 0

        if args.command == "enable-mcp":
            en = asyncio.run(bridge.enable_mcp_server(args.server_id, approved=args.approve))
            _print_output(en, args.json, f"Enabled MCP Server:\n{json.dumps(en, indent=2)}")
            return 0

        if args.command == "disable-mcp":
            dis = asyncio.run(bridge.disable_mcp_server(args.server_id))
            _print_output(dis, args.json, f"Disabled MCP Server:\n{json.dumps(dis, indent=2)}")
            return 0

        if args.command == "memory":
            mem = asyncio.run(bridge.get_memory_status())
            _print_output(mem, args.json, f"SkillBridge Memory & Capacity Status:\n{json.dumps(mem, indent=2)}")
            return 0

        if args.command == "doctor":
            doc = asyncio.run(bridge.doctor())
            _print_output(doc, args.json, f"SkillBridge Doctor Report:\n{json.dumps(doc, indent=2, default=str)}")
            return 0

        if args.command == "sbom":
            out_p = Path(args.output)
            sbom = bridge.generate_sbom(output_path=out_p)
            _print_output(sbom, args.json, f"Generated CycloneDX 1.6 SBOM at {out_p} ({len(sbom['components'])} components)")
            return 0

        if args.command == "install":
            ext_id = "mcp/skillbridge" if args.extension_id == "skillbridge-mcp" else args.extension_id
            dry_run = not args.apply
            plan = asyncio.run(
                bridge.plan_install(
                    ext_id,
                    args.target,
                    scope=args.scope,
                    dry_run=dry_run,
                    approved=args.approve,
                    extension_type_override=args.type,
                    lazy_disable_globally=args.lazy_mcp,
                )
            )
            sec_report = format_security_report(plan.security_assessment) if plan.security_assessment else "No security scan"
            if plan.blocked:
                msg = f"{sec_report}\n\nInstallation BLOCKED: {plan.block_reason}"
                _print_output(plan.to_dict(), args.json, msg)
                return 1

            if dry_run:
                msg = (
                    f"{sec_report}\n\n"
                    f"Dry-Run Installation Plan ({plan.plan_id}):\n"
                    f"  Extension         : {plan.extension_id} ({plan.extension_type})\n"
                    f"  Target Client     : {plan.target_client} (scope={plan.scope})\n"
                    f"  Requires Approval : {plan.requires_approval}\n"
                    f"  Unpreserved Fields: {', '.join(plan.unpreserved_fields) or 'none'}\n"
                    f"  Planned Diff      :\n{plan.planned_config_diff}"
                )
                _print_output(plan.to_dict(), args.json, msg)
                return 0

            applied = asyncio.run(bridge.apply_install(plan, approved=args.approve))
            msg = (
                f"{sec_report}\n\n"
                f"Applied Installation ({plan.plan_id}):\n"
                f"  Target Client : {applied['target_client']} ({applied['scope']})\n"
                f"  Files Written : {', '.join(applied['files_written'])}\n"
                f"  Backup Dir    : {applied['backup_dir']}\n"
                f"  Discoverable  : {applied['verification'].get('discoverable')}"
            )
            _print_output(applied, args.json, msg)
            return 0

        if args.command == "rollback":
            res = asyncio.run(bridge.rollback_install(args.plan_id))
            _print_output(res, args.json, f"Rollback Complete: {json.dumps(res, indent=2)}")
            return 0

        if args.command == "verify":
            res = asyncio.run(bridge.verify_target(args.target))
            _print_output(res, args.json, f"SkillBridge Verification Report:\n{json.dumps(res, indent=2, default=str)}")
            return 0

        if args.command == "evaluate":
            out_path = Path(args.output)
            dash_path = Path(args.dashboard)
            report = run_evaluation_suite(output_json_path=out_path)
            generate_dashboard_html(report, dash_path)
            m = report["metrics"]
            summary = (
                f"SkillBridge Evaluation Complete (Verdict: {report['verdict']} | Scenarios: {m['total_scenarios']})\n"
                f"  Hit@1 Accuracy              : {m['hit_at_1']*100:.1f}% (Threshold: >=75.0% | Lexical Baseline: {m['lexical_baseline_hit_at_1']*100:.1f}%)\n"
                f"  Hit@3 Accuracy              : {m['hit_at_3']*100:.1f}% (Threshold: >=90.0%)\n"
                f"  NO_MATCH Accuracy           : {m['no_match_accuracy']*100:.1f}%\n"
                f"  Dangerous Fixture Rejection : {m['dangerous_fixture_rejection_rate']*100:.1f}% (Threshold: 100.0%)\n"
                f"  Benign False Positives      : {m['benign_false_positive_block_rate']*100:.1f}% (Threshold: 0.0%)\n"
                f"  Duplicate Skill Avoidance   : {m['duplicate_skill_avoidance_rate']*100:.1f}%\n"
                f"  Scan Cache Hit Rate         : {m['scan_cache_hit_rate']*100:.1f}%\n"
                f"  Avg Preflight Latency       : {m['avg_preflight_latency_ms']:.1f} ms\n"
                f"  Runtime Sessions Unloaded   : {m['all_sessions_unloaded_cleanly']}\n"
                f"  JSON Report Saved To        : {out_path}\n"
                f"  HTML Dashboard Saved To     : {dash_path}"
            )
            _print_output(report, args.json, summary)
            return 0 if report["thresholds_passed"] else 1

        if args.command == "report":
            ver = asyncio.run(bridge.verify_target())
            audits = bridge.db.get_recent_audit_logs(limit=15)
            payload = {"verification": ver, "recent_audit_logs": audits}
            _print_output(payload, args.json, f"SkillBridge Operational Report:\n{json.dumps(payload, indent=2, default=str)}")
            return 0

        parser.print_help()
        return 2
    except PermissionError as exc:
        print(f"Security/Permission Blocked: {exc}", file=sys.stderr)
        return 3
    except ValueError as exc:
        print(f"Validation Error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"Error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point that converts storage/startup failures into actionable messages."""
    try:
        return _main(argv)
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        if os.environ.get("SKILLBRIDGE_DEBUG"):
            raise
        hint = ""
        if "database" in str(exc).lower() or "sqlite" in type(exc).__name__.lower():
            hint = " The corrupt database is moved to skillbridge.db.corrupt-<timestamp> on next open."
        print(f"Error: {type(exc).__name__}: {exc}{hint}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
