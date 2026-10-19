"""Flagship single-file HTML product console for SkillBridge v2.

The console is generated from *live* runtime state (catalog counts, providers, security policy,
runtime limits, memory snapshot, audit trail, quarantine, MCP broker tools, verification engine
readiness, and optional evaluation results). It is a self-contained HTML file with embedded CSS
and JavaScript — no external CDNs, fonts, or network calls are required to view it.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from skillbridge import __version__
from skillbridge.security.policy import POLICY_MATRIX

PRODUCT_TAGLINE = "Discover, verify, stage, and load whole-directory agent skills with multi-tier security and a lazy MCP broker."


def _safe_dict(obj: Any) -> Dict[str, Any]:
    try:
        return obj.to_dict()
    except AttributeError:
        return dict(obj) if isinstance(obj, dict) else {}


def collect_ui_data(bridge: Any, *, audit_limit: int = 25) -> Dict[str, Any]:
    """Collect a JSON-serializable snapshot of live SkillBridge v2 state for the UI."""
    from skillbridge.mcp_server.server import SKILLBRIDGE_MCP_TOOLS

    cfg = bridge.config
    db = bridge.db
    settings = bridge.settings
    catalog = {
        "total": db.count_extensions(),
        "skills": db.count_extensions("skill"),
        "mcp_servers": db.count_extensions("mcp_server"),
    }
    providers: List[Dict[str, Any]] = []
    for prov in bridge.discovery.all_providers:
        providers.append(
            {
                "id": prov.PROVIDER_ID,
                "extension_type": getattr(prov, "EXTENSION_TYPE", "skill"),
                "class": type(prov).__name__,
            }
        )
    try:
        memory_snapshot = bridge.loader.get_memory_snapshot(
            active_mcp_processes=len(bridge._enabled_mcp_servers)
        ).to_dict()
    except Exception as exc:  # noqa: BLE001 - UI must never crash on telemetry
        memory_snapshot = {"error": f"{type(exc).__name__}: {exc}"}
    try:
        engines = bridge.verification_coordinator.check_all_engines()
    except Exception as exc:  # noqa: BLE001
        engines = {"error": f"{type(exc).__name__}: {exc}"}
    try:
        scheduler_stats = bridge.parallel_scheduler.get_stats()
    except Exception as exc:  # noqa: BLE001
        scheduler_stats = {"error": f"{type(exc).__name__}: {exc}"}
    try:
        active_sessions = bridge.loader.get_all_active_sessions_summary()
    except Exception as exc:  # noqa: BLE001
        active_sessions = {"error": f"{type(exc).__name__}: {exc}"}
    try:
        audit = db.get_recent_audit_logs(limit=audit_limit)
    except Exception as exc:  # noqa: BLE001
        audit = [{"error": f"{type(exc).__name__}: {exc}"}]
    try:
        quarantine = bridge.loader.quarantine.list_quarantined() if getattr(bridge.loader, "quarantine", None) else []
    except Exception:  # noqa: BLE001
        quarantine = []

    eval_report: Optional[Dict[str, Any]] = None
    for candidate in (
        cfg.project_root / "reports" / "eval_report.json",
        Path("reports") / "eval_report.json",
    ):
        try:
            if candidate.is_file():
                eval_report = json.loads(candidate.read_text(encoding="utf-8"))
                break
        except (OSError, json.JSONDecodeError):
            continue

    return {
        "version": __version__,
        "tagline": PRODUCT_TAGLINE,
        "generated_at": __import__("datetime").datetime.now().astimezone().isoformat(timespec="seconds"),
        "home_dir": str(cfg.home_dir),
        "project_root": str(cfg.project_root),
        "offline_mode": bool(cfg.network.offline_mode),
        "catalog": catalog,
        "providers": providers,
        "limits": {k: (list(v) if isinstance(v, tuple) else v) for k, v in vars(cfg.loader_limits).items()},
        "network": {
            "max_response_mib": round(cfg.network.max_response_bytes / (1024 * 1024), 1),
            "connect_timeout_sec": cfg.network.connect_timeout_sec,
            "read_timeout_sec": cfg.network.read_timeout_sec,
            "max_retries": cfg.network.max_retries,
            "max_redirects": cfg.network.max_redirects,
        },
        "settings": settings.to_dict(),
        "security": {
            "policy_matrix": POLICY_MATRIX,
            "allow_builtin_dangerous_override": bool(cfg.security_policy.allow_builtin_dangerous_override),
            "trusted_repos": list(cfg.security_policy.trusted_repos),
            "allowed_domains": list(cfg.security_policy.allowed_domains),
        },
        "verification_engines": engines,
        "memory": memory_snapshot,
        "scheduler": scheduler_stats,
        "active_sessions": active_sessions,
        "audit": audit,
        "quarantine": quarantine,
        "quarantine_count": len(quarantine),
        "mcp_tools": [
            {
                "name": t.get("name", ""),
                "description": t.get("description", ""),
                "properties": sorted((t.get("inputSchema") or {}).get("properties", {}).keys()),
                "required": list((t.get("inputSchema") or {}).get("required", [])),
            }
            for t in SKILLBRIDGE_MCP_TOOLS
        ],
        "evaluation": eval_report,
    }


def _e(value: Any) -> str:
    """Escape a value for safe HTML embedding."""
    return html.escape("" if value is None else str(value), quote=True)


def _fmt_bytes(n: Any) -> str:
    try:
        num = float(n)
    except (TypeError, ValueError):
        return _e(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0 or unit == "TB":
            return f"{num:.1f} {unit}" if unit != "B" else f"{int(num)} B"
        num /= 1024.0
    return _e(n)


def _verdict_badge(value: str) -> str:
    cls = {"allow": "ok", "ask": "warn", "block": "bad"}.get(value, "neutral")
    return f'<span class="pill {cls}">{_e(value)}</span>'


def _render_matrix(matrix: Dict[str, Dict[str, str]]) -> str:
    verdicts = ["SAFE", "CAUTION", "DANGEROUS", "UNKNOWN"]
    head = "".join(f"<th>{_e(v)}</th>" for v in verdicts)
    rows = []
    for trust in ["builtin", "trusted", "community", "untrusted"]:
        cells = "".join(f"<td>{_verdict_badge(matrix.get(trust, {}).get(v, '-'))}</td>" for v in verdicts)
        rows.append(f"<tr><th>{_e(trust)}</th>{cells}</tr>")
    return f'<table class="matrix"><thead><tr><th>Trust \\ Verdict</th>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table>'


def _render_engines(engines: Dict[str, Any]) -> str:
    if not engines or "error" in engines:
        return f'<p class="muted">Verification engine telemetry unavailable: {_e(engines.get("error") if isinstance(engines, dict) else engines)}</p>'
    rows = []
    for name, info in engines.items():
        if not isinstance(info, dict):
            info = {"available": info}
        available = info.get("available", info.get("installed", False))
        detail = info.get("version") or info.get("path") or info.get("detail") or ""
        badge = '<span class="pill ok">ready</span>' if available else '<span class="pill neutral">optional</span>'
        rows.append(f"<tr><td class='mono'>{_e(name)}</td><td>{badge}</td><td class='muted'>{_e(detail)}</td></tr>")
    return f'<table><thead><tr><th>Engine</th><th>Status</th><th>Detail</th></tr></thead><tbody>{"".join(rows)}</tbody></table>'


def _render_providers(providers: List[Dict[str, Any]]) -> str:
    rows = []
    for p in providers:
        rows.append(
            f"<tr><td class='mono'>{_e(p['id'])}</td><td>{_e(p['extension_type'])}</td>"
            f"<td class='muted'>{_e(p['class'])}</td></tr>"
        )
    return (
        '<table><thead><tr><th>Provider</th><th>Type</th><th>Adapter</th></tr></thead><tbody>'
        + "".join(rows)
        + "</tbody></table>"
    )


def _render_audit(audit: List[Dict[str, Any]]) -> str:
    if not audit:
        return '<p class="muted">No audit events recorded yet.</p>'
    rows = []
    for entry in audit:
        rows.append(
            "<tr>"
            f"<td class='mono small'>{_e(entry.get('timestamp', entry.get('at', '')))}</td>"
            f"<td class='mono'>{_e(entry.get('operation', entry.get('action', '')))}</td>"
            f"<td>{_e(entry.get('provider', ''))}</td>"
            f"<td class='mono small'>{_e(entry.get('session_id', ''))}</td>"
            f"<td class='mono small'>{_e(entry.get('elapsed_ms', ''))}</td>"
            "</tr>"
        )
    return (
        '<table><thead><tr><th>Timestamp</th><th>Operation</th><th>Provider</th><th>Session</th><th>ms</th></tr></thead><tbody>'
        + "".join(rows)
        + "</tbody></table>"
    )


def _render_quarantine(quarantine: List[Dict[str, Any]]) -> str:
    if not quarantine:
        return '<div class="empty"><strong>Quarantine is empty.</strong><span>No bundles are currently isolated.</span></div>'
    rows = []
    for item in quarantine:
        rows.append(
            f"<tr><td class='mono'>{_e(item.get('extension_id', item.get('name', '')))}</td>"
            f"<td>{_e(item.get('verdict', ''))}</td>"
            f"<td class='mono small'>{_e(item.get('quarantined_at', item.get('created_at', '')))}</td></tr>"
        )
    return '<table><thead><tr><th>Extension</th><th>Verdict</th><th>Quarantined</th></tr></thead><tbody>' + "".join(rows) + "</tbody></table>"


def _render_tools(tools: List[Dict[str, Any]]) -> str:
    cards = []
    for tool in tools:
        props = ", ".join(tool["properties"]) if tool["properties"] else "none"
        required = ", ".join(tool["required"]) if tool["required"] else "none"
        cards.append(
            '<article class="tool" data-name="' + _e(tool["name"].lower()) + '">'
            f'<h4><span class="mono">{_e(tool["name"])}</span></h4>'
            f'<p>{_e(tool["description"])}</p>'
            f'<div class="tool-meta"><span>args: <span class="mono small">{_e(props)}</span></span>'
            f'<span>required: <span class="mono small">{_e(required)}</span></span></div>'
            "</article>"
        )
    return '<div class="tool-grid" id="toolGrid">' + "".join(cards) + "</div>"


def _render_eval(evaluation: Optional[Dict[str, Any]]) -> str:
    if not evaluation:
        return (
            '<div class="empty"><strong>No evaluation report found.</strong>'
            "<span>Run <span class='mono'>skillbridge evaluate</span> to generate one, then rebuild this console.</span></div>"
        )
    metrics = evaluation.get("metrics", {})
    verdict = evaluation.get("verdict", "UNKNOWN")
    badge = {"PASS": "ok", "FAIL": "bad"}.get(str(verdict).upper(), "neutral")
    cards = []
    for key, value in metrics.items():
        if isinstance(value, (int, float, str)):
            cards.append(
                f'<div class="metric"><span class="metric-label">{_e(key.replace("_", " "))}</span>'
                f'<span class="metric-value">{_e(value)}</span></div>'
            )
    return f'<p>Overall verdict: <span class="pill {badge}">{_e(verdict)}</span></p><div class="metric-grid">{"".join(cards)}</div>'


def generate_ui_html(data: Dict[str, Any], output_html_path: Path) -> Path:
    """Render the flagship product console to a self-contained HTML file."""
    output_html_path = Path(output_html_path)
    output_html_path.parent.mkdir(parents=True, exist_ok=True)

    catalog = data.get("catalog", {})
    limits = data.get("limits", {})
    settings = data.get("settings", {})
    network = data.get("network", {})
    security = data.get("security", {})
    memory = data.get("memory", {})
    sessions = data.get("active_sessions", {})
    scheduler = data.get("scheduler", {})

    stat_cards = [
        ("Indexed extensions", catalog.get("total", 0)),
        ("Skills", catalog.get("skills", 0)),
        ("MCP servers", catalog.get("mcp_servers", 0)),
        ("Providers", len(data.get("providers", []))),
        ("MCP broker tools", len(data.get("mcp_tools", []))),
        ("Quarantined", data.get("quarantine_count", 0)),
    ]
    stats_html = "".join(
        f'<div class="stat"><span class="stat-value">{_e(value)}</span><span class="stat-label">{_e(label)}</span></div>'
        for label, value in stat_cards
    )

    capabilities = [
        ("Whole-directory bundles", "Import skills with every nested script, reference, template, and asset — not just SKILL.md."),
        ("Multi-tier verification", "Tier 0 provenance → Tier 1 static scan → Tier 2 semantic review → Tier 3 behavioral evaluation, fail-closed."),
        ("Parallel by design", "Batch discovery and loading across a bounded worker pool with per-provider circuit breakers and DAG orchestration."),
        ("Bounded payloads", f"Up to {_fmt_bytes(limits.get('max_file_size_bytes'))}/file, {_fmt_bytes(limits.get('max_total_bytes'))}/bundle, "
                              f"{_e(limits.get('max_references'))} references, depth {_e(limits.get('max_nesting_depth'))}, "
                              f"{_e(limits.get('max_parallel_workers'))} load workers."),
        ("Security policy engine", "Deterministic trust × verdict matrix. DANGEROUS community bundles are never overridable; curated builtins require explicit approval."),
        ("Runtime memory governance", f"Evicts under pressure toward {_e(settings.get('memory_target_mib'))} MiB with a {_e(settings.get('active_skill_limit'))}-skill active cap."),
        ("Lazy MCP broker", "One stable MCP surface that loads tools on demand instead of registering hundreds of model-visible tools."),
        ("Native installers", "Atomic, reversible plans for OpenCode and Claude Code with backups, approvals, and rollback."),
    ]
    capabilities_html = "".join(
        f'<article class="card"><h3>{_e(title)}</h3><p>{_e(text)}</p></article>' for title, text in capabilities
    )

    limit_rows = "".join(
        f"<tr><td>{_e(key.replace('_', ' '))}</td><td class='mono'>{_e(_fmt_bytes(value) if 'bytes' in key else value)}</td></tr>"
        for key, value in limits.items()
        if not isinstance(value, (list, tuple))
    )
    settings_rows = "".join(
        f"<tr><td>{_e(key.replace('_', ' '))}</td><td class='mono'>{_e(value)}</td></tr>"
        for key, value in settings.items()
        if not isinstance(value, (dict, list))
    )

    providers_html = _render_providers(data.get("providers", []))
    audit_html = _render_audit(data.get("audit", []))
    quarantine_html = _render_quarantine(data.get("quarantine", []))
    tools_html = _render_tools(data.get("mcp_tools", []))
    engines_html = _render_engines(data.get("verification_engines", {}))
    matrix_html = _render_matrix(security.get("policy_matrix", {}))
    eval_html = _render_eval(data.get("evaluation"))

    memory_json = json.dumps(memory, indent=2, default=str)
    sessions_json = json.dumps(sessions, indent=2, default=str)
    scheduler_json = json.dumps(scheduler, indent=2, default=str)

    quickstart_install = """# from a checkout of this repository
python -m pip install -e .

# verify the environment
skillbridge doctor"""
    quickstart_cli = """# search 100k+ skills across local + remote providers
skillbridge search-skills "pdf tables" --limit 10

# import an entire skill directory (all files) through Tier 0-3
skillbridge import-dir ./my-skill --approve

# load several verified skills at once (parallel workers)
skillbridge load-batch skills-sh/pdf anthropics/skills/docx clawhub/acme/scraper

# build this product console from live state
skillbridge ui --serve --port 8760"""
    mcp_config = """{
  "mcp": {
    "skillbridge": {
      "type": "local",
      "command": ["skillbridge", "mcp-serve"],
      "enabled": true
    }
  }
}"""

    doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SkillBridge v{_e(data.get('version', ''))} — Product Console</title>
<style>
:root {{
  --bg: #070b14;
  --bg-soft: #0d1424;
  --panel: rgba(18, 28, 48, 0.72);
  --panel-solid: #111a2d;
  --line: rgba(120, 160, 255, 0.14);
  --text: #e8eefc;
  --muted: #8fa3c7;
  --accent: #4f8cff;
  --accent-2: #22d3ee;
  --ok: #34d399;
  --warn: #fbbf24;
  --bad: #f87171;
  --radius: 16px;
  --mono: "Cascadia Code", "JetBrains Mono", Consolas, monospace;
}}
* {{ box-sizing: border-box; }}
html {{ scroll-behavior: smooth; }}
body {{
  margin: 0;
  font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
  background:
    radial-gradient(1200px 600px at 12% -10%, rgba(79, 140, 255, 0.18), transparent 60%),
    radial-gradient(900px 500px at 95% 0%, rgba(34, 211, 238, 0.12), transparent 55%),
    var(--bg);
  color: var(--text);
  line-height: 1.55;
}}
a {{ color: var(--accent-2); }}
.shell {{ max-width: 1240px; margin: 0 auto; padding: 0 24px 72px; }}
header.top {{
  position: sticky; top: 0; z-index: 20;
  backdrop-filter: blur(18px);
  background: rgba(7, 11, 20, 0.72);
  border-bottom: 1px solid var(--line);
}}
.top-inner {{ max-width: 1240px; margin: 0 auto; padding: 14px 24px; display: flex; align-items: center; gap: 18px; }}
.brand {{ display: flex; align-items: center; gap: 10px; font-weight: 700; letter-spacing: 0.2px; }}
.logo {{
  width: 30px; height: 30px; border-radius: 9px;
  background: linear-gradient(135deg, var(--accent), var(--accent-2));
  display: grid; place-items: center; font-size: 14px; color: #06101f; font-weight: 900;
}}
.version {{ font-family: var(--mono); font-size: 12px; color: var(--muted); border: 1px solid var(--line); padding: 2px 8px; border-radius: 999px; }}
nav.tabs {{ margin-left: auto; display: flex; flex-wrap: wrap; gap: 4px; }}
nav.tabs button {{
  background: transparent; color: var(--muted); border: 0; font: inherit; font-size: 14px;
  padding: 7px 12px; border-radius: 9px; cursor: pointer;
}}
nav.tabs button:hover {{ color: var(--text); background: rgba(79, 140, 255, 0.08); }}
nav.tabs button.active {{ color: var(--text); background: rgba(79, 140, 255, 0.16); }}
.hero {{ padding: 64px 0 28px; }}
.eyebrow {{ text-transform: uppercase; letter-spacing: 0.24em; font-size: 11px; color: var(--accent-2); font-weight: 700; }}
h1 {{ font-size: clamp(34px, 5.2vw, 58px); line-height: 1.05; margin: 14px 0 16px; letter-spacing: -0.02em; }}
h1 .grad {{ background: linear-gradient(90deg, #7fb0ff, #22d3ee 55%, #a78bfa); -webkit-background-clip: text; background-clip: text; color: transparent; }}
.tagline {{ max-width: 780px; color: var(--muted); font-size: 17px; }}
.chips {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 20px; }}
.chip {{
  font-family: var(--mono); font-size: 12px; color: var(--muted);
  border: 1px solid var(--line); background: rgba(17, 26, 45, 0.6); padding: 5px 10px; border-radius: 999px;
}}
.stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 30px 0 8px; }}
.stat {{
  background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius);
  padding: 18px; text-align: left;
}}
.stat-value {{ display: block; font-size: 30px; font-weight: 800; letter-spacing: -0.02em; }}
.stat-label {{ color: var(--muted); font-size: 13px; }}
section.tab-panel {{ display: none; padding-top: 28px; }}
section.tab-panel.active {{ display: block; }}
h2 {{ font-size: 25px; margin: 34px 0 6px; letter-spacing: -0.01em; }}
h2 .sub {{ display: block; font-size: 13px; color: var(--muted); font-weight: 400; margin-top: 4px; }}
h3 {{ font-size: 15px; margin: 0 0 8px; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 14px; margin: 18px 0; }}
.card {{ background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius); padding: 18px; }}
.card p {{ margin: 0; color: var(--muted); font-size: 14px; }}
.panel {{ background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius); padding: 6px 18px 14px; margin: 16px 0; overflow-x: auto; }}
.panel h3 {{ margin-top: 12px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13.5px; }}
th, td {{ text-align: left; padding: 9px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }}
thead th {{ color: var(--muted); font-size: 11.5px; text-transform: uppercase; letter-spacing: 0.08em; }}
tbody tr:last-child td, tbody tr:last-child th {{ border-bottom: 0; }}
.matrix td, .matrix th {{ text-align: center; }}
.matrix th:first-child {{ text-align: left; }}
.pill {{ display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 11.5px; font-weight: 700; letter-spacing: 0.03em; }}
.pill.ok {{ color: #052e1f; background: var(--ok); }}
.pill.warn {{ color: #3a2a00; background: var(--warn); }}
.pill.bad {{ color: #3f0a0a; background: var(--bad); }}
.pill.neutral {{ color: var(--muted); background: rgba(143, 163, 199, 0.14); border: 1px solid var(--line); }}
.muted {{ color: var(--muted); }}
.small {{ font-size: 12px; }}
.mono {{ font-family: var(--mono); }}
pre {{
  background: #060a12; border: 1px solid var(--line); border-radius: 12px;
  padding: 16px; overflow-x: auto; font-family: var(--mono); font-size: 13px; line-height: 1.6;
}}
.empty {{
  border: 1px dashed var(--line); border-radius: var(--radius); padding: 26px; text-align: center;
  color: var(--muted); display: grid; gap: 4px; margin: 14px 0;
}}
.empty strong {{ color: var(--text); }}
.toolbar {{ display: flex; gap: 10px; align-items: center; margin: 14px 0; flex-wrap: wrap; }}
.toolbar input {{
  flex: 1 1 260px; background: var(--panel-solid); color: var(--text); border: 1px solid var(--line);
  border-radius: 10px; padding: 9px 12px; font: inherit; font-size: 14px; outline: none;
}}
.toolbar input:focus {{ border-color: var(--accent); }}
.tool-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 12px; margin-top: 14px; }}
.tool {{ background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 15px; }}
.tool h4 {{ margin: 0 0 6px; font-size: 14px; color: #9cc3ff; }}
.tool p {{ margin: 0; color: var(--muted); font-size: 13px; }}
.tool-meta {{ display: flex; flex-direction: column; gap: 2px; margin-top: 9px; color: var(--muted); font-size: 11.5px; }}
.metric-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 10px; }}
.metric {{ background: var(--bg-soft); border: 1px solid var(--line); border-radius: 12px; padding: 12px; }}
.metric-label {{ display: block; color: var(--muted); font-size: 11.5px; text-transform: uppercase; letter-spacing: 0.07em; }}
.metric-value {{ font-family: var(--mono); font-size: 18px; }}
.split {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; }}
footer {{ margin-top: 56px; padding-top: 18px; border-top: 1px solid var(--line); color: var(--muted); font-size: 12.5px; display: flex; flex-wrap: wrap; gap: 10px; justify-content: space-between; }}
@media (max-width: 760px) {{
  .top-inner {{ flex-wrap: wrap; }}
  nav.tabs {{ margin-left: 0; }}
}}
</style>
</head>
<body>
<header class="top">
  <div class="top-inner">
    <div class="brand"><span class="logo">SB</span> SkillBridge <span class="version">v{_e(data.get('version', ''))}</span></div>
    <nav class="tabs" id="tabs">
      <button data-tab="overview" class="active">Overview</button>
      <button data-tab="catalog">Catalog</button>
      <button data-tab="providers">Providers</button>
      <button data-tab="security">Security</button>
      <button data-tab="runtime">Runtime</button>
      <button data-tab="broker">MCP Broker</button>
      <button data-tab="start">Get Started</button>
    </nav>
  </div>
</header>
<main class="shell">
  <section class="tab-panel active" id="tab-overview">
    <div class="hero">
      <div class="eyebrow">Agent extension infrastructure · live product console</div>
      <h1>One bridge for <span class="grad">every agent skill.</span></h1>
      <p class="tagline">{_e(data.get('tagline', ''))}</p>
      <div class="chips">
        <span class="chip">mode: {_e('offline' if data.get('offline_mode') else 'online')}</span>
        <span class="chip">state: {_e(data.get('home_dir', ''))}</span>
        <span class="chip">generated: {_e(data.get('generated_at', ''))}</span>
      </div>
      <div class="stats">{stats_html}</div>
    </div>
    <h2>What ships in the box<span class="sub">Every capability below is backed by the running implementation, not a mock.</span></h2>
    <div class="grid">{capabilities_html}</div>
    <h2>Evaluation snapshot<span class="sub">Loaded from reports/eval_report.json when present.</span></h2>
    <div class="panel">{eval_html}</div>
  </section>

  <section class="tab-panel" id="tab-catalog">
    <h2>Catalog<span class="sub">Live SQLite catalog counts and the most recent audit events.</span></h2>
    <div class="stats">{stats_html}</div>
    <div class="panel"><h3>Recent audit trail</h3>{audit_html}</div>
    <div class="panel"><h3>Quarantine ({_e(data.get('quarantine_count', 0))})</h3>{quarantine_html}</div>
  </section>

  <section class="tab-panel" id="tab-providers">
    <h2>Discovery providers<span class="sub">Local directories, Hermes 100k+ index, skills.sh, ClawHub, browse.sh, LobeHub, GitHub, MCP Registry, and Smithery.</span></h2>
    <div class="panel">{providers_html}</div>
    <div class="panel"><h3>Network posture</h3>
      <table><tbody>
        <tr><td>Max response size</td><td class="mono">{_e(network.get('max_response_mib'))} MiB</td></tr>
        <tr><td>Connect timeout</td><td class="mono">{_e(network.get('connect_timeout_sec'))} s</td></tr>
        <tr><td>Read timeout</td><td class="mono">{_e(network.get('read_timeout_sec'))} s</td></tr>
        <tr><td>Retries / redirects</td><td class="mono">{_e(network.get('max_retries'))} / {_e(network.get('max_redirects'))}</td></tr>
        <tr><td>Allowlisted domains</td><td class="mono small">{_e(', '.join(security.get('allowed_domains', [])))}</td></tr>
      </tbody></table>
    </div>
  </section>

  <section class="tab-panel" id="tab-security">
    <h2>Security model<span class="sub">Fail-closed trust policy applied before any skill or script touches the runtime.</span></h2>
    <div class="grid">
      <article class="card"><h3>Tier 0 — Provenance</h3><p>Whole-directory staging into quarantine, manifest hashing, path validation, symlink and size limits.</p></article>
      <article class="card"><h3>Tier 1 — Static analysis</h3><p>SkillSpector pattern engine detects secret reads, exfiltration, destructive commands, and prompt injection.</p></article>
      <article class="card"><h3>Tier 2 — Semantic review</h3><p>SKIL and optional deep scanners inspect instructions and capabilities for intent-level risk.</p></article>
      <article class="card"><h3>Tier 3 — Behavioral evaluation</h3><p>SkillEvaluator runs bounded checks against declared behavior before an assurance state is issued.</p></article>
    </div>
    <div class="panel"><h3>Policy matrix</h3>{matrix_html}
      <p class="muted small">Builtin DANGEROUS override: {_e('enabled (explicit approval required)' if security.get('allow_builtin_dangerous_override') else 'disabled')}.
      Community/untrusted DANGEROUS bundles are never overridable.</p>
    </div>
    <div class="panel"><h3>Verification engines</h3>{engines_html}</div>
    <div class="panel"><h3>Trusted repositories</h3>
      <p class="mono small">{_e(', '.join(security.get('trusted_repos', [])))}</p>
    </div>
  </section>

  <section class="tab-panel" id="tab-runtime">
    <h2>Runtime & resources<span class="sub">Limits, memory governance, sessions, and scheduler telemetry.</span></h2>
    <div class="split">
      <div class="panel"><h3>Loader limits</h3><table><tbody>{limit_rows}</tbody></table></div>
      <div class="panel"><h3>Runtime settings</h3><table><tbody>{settings_rows}</tbody></table></div>
    </div>
    <div class="panel"><h3>Memory snapshot</h3><pre>{_e(memory_json)}</pre></div>
    <div class="split">
      <div class="panel"><h3>Active sessions</h3><pre>{_e(sessions_json)}</pre></div>
      <div class="panel"><h3>Parallel scheduler</h3><pre>{_e(scheduler_json)}</pre></div>
    </div>
  </section>

  <section class="tab-panel" id="tab-broker">
    <h2>MCP broker<span class="sub">One stable surface. Tools are resolved lazily instead of flooding the model's tool list.</span></h2>
    <div class="toolbar">
      <input id="toolFilter" type="search" placeholder="Filter MCP tools by name or argument…" aria-label="Filter MCP tools">
      <span class="chip" id="toolCount">{_e(len(data.get('mcp_tools', [])))} tools</span>
    </div>
    {tools_html}
  </section>

  <section class="tab-panel" id="tab-start">
    <h2>Get started<span class="sub">Install, import a whole-directory skill, load a parallel batch, and wire the MCP broker into your agent.</span></h2>
    <div class="split">
      <div class="panel"><h3>1 · Install</h3><pre>{_e(quickstart_install)}</pre></div>
      <div class="panel"><h3>2 · Everyday commands</h3><pre>{_e(quickstart_cli)}</pre></div>
    </div>
    <div class="panel"><h3>3 · MCP client configuration</h3>
      <p class="muted small">Point your MCP-capable client at the stdio broker. Replace client-specific keys as needed.</p>
      <pre>{_e(mcp_config)}</pre>
    </div>
    <div class="panel"><h3>Project paths</h3>
      <table><tbody>
        <tr><td>State directory</td><td class="mono">{_e(data.get('home_dir', ''))}</td></tr>
        <tr><td>Project root</td><td class="mono">{_e(data.get('project_root', ''))}</td></tr>
        <tr><td>Console file</td><td class="mono">{_e(str(output_html_path))}</td></tr>
      </tbody></table>
    </div>
  </section>

  <footer>
    <span>SkillBridge v{_e(data.get('version', ''))} · product console generated from live runtime state</span>
    <span class="mono">generated {_e(data.get('generated_at', ''))}</span>
  </footer>
</main>
<script>
(function () {{
  const buttons = Array.from(document.querySelectorAll('#tabs button'));
  const panels = Array.from(document.querySelectorAll('.tab-panel'));
  function activate(name) {{
    buttons.forEach(function (b) {{ b.classList.toggle('active', b.dataset.tab === name); }});
    panels.forEach(function (p) {{ p.classList.toggle('active', p.id === 'tab-' + name); }});
  }}
  buttons.forEach(function (b) {{ b.addEventListener('click', function () {{ activate(b.dataset.tab); window.scrollTo({{top: 0, behavior: 'smooth'}}); }}); }});

  const filter = document.getElementById('toolFilter');
  const grid = document.getElementById('toolGrid');
  const count = document.getElementById('toolCount');
  if (filter && grid) {{
    const cards = Array.from(grid.querySelectorAll('.tool'));
    filter.addEventListener('input', function () {{
      const q = filter.value.trim().toLowerCase();
      let shown = 0;
      cards.forEach(function (card) {{
        const match = !q || card.textContent.toLowerCase().indexOf(q) !== -1;
        card.style.display = match ? '' : 'none';
        if (match) shown++;
      }});
      if (count) count.textContent = shown + ' tools';
    }});
  }}
}})();
</script>
</body>
</html>
"""
    output_html_path.write_text(doc, encoding="utf-8")
    return output_html_path


def serve_ui(html_path: Path, *, host: str = "127.0.0.1", port: int = 8760, open_browser: bool = False) -> None:
    """Serve a generated product console over HTTP on localhost (single-file, no directory listing)."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import webbrowser

    html_path = Path(html_path)
    payload = html_path.read_bytes()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - stdlib naming
            if self.path in ("/", "/index.html", "/ui.html"):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(payload)
                return
            self.send_error(404, "Not found")

        def log_message(self, fmt, *args):  # silence per-request stderr noise
            return

    server = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}/"
    print(f"SkillBridge product console: {url}")
    print("Press Ctrl+C to stop.")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
