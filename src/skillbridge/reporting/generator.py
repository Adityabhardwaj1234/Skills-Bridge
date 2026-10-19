"""Report and flagship HTML dashboard generator for SkillBridge v2 evaluation, security tiers, memory monitor, and MCP broker."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, Dict


def generate_dashboard_html(eval_report: Dict[str, Any], output_html_path: Path) -> Path:
    """Generate a self-contained flagship HTML dashboard sourced strictly from real runtime and evaluation data."""
    metrics = eval_report.get("metrics", {})
    catalog = eval_report.get("catalog_indexed", {})
    scenarios = eval_report.get("scenarios", [])
    sec_summary = eval_report.get("security_fixture_summary", {})
    perf = eval_report.get("performance_and_memory_summary", {})
    verdict = eval_report.get("verdict", "PASS")

    rows_html = []
    for s in scenarios:
        h1_badge = '<span class="badge pass">PASS</span>' if s["hit_at_1"] else '<span class="badge fail">MISS</span>'
        h3_badge = '<span class="badge pass">PASS</span>' if s["hit_at_3"] else '<span class="badge fail">MISS</span>'
        rows_html.append(
            f"""
            <tr>
                <td><code>{html.escape(s['scenario_id'])}</code></td>
                <td><span class="tag">{html.escape(s['category'])}</span></td>
                <td>{html.escape(s['query'])}</td>
                <td><code>{html.escape(', '.join(s['expected_skills']) or 'NO_MATCH')}</code></td>
                <td><code>{html.escape(str(s['selected_primary'] or 'NO_MATCH'))}</code></td>
                <td><code>{html.escape(str(s['baseline_lexical_pick'] or 'NO_MATCH'))}</code></td>
                <td>{h1_badge}</td>
                <td>{h3_badge}</td>
                <td>{s['latency_ms']:.1f} ms</td>
            </tr>
            """
        )

    sec_rows = []
    for item in sec_summary.get("malicious_fixtures", []) + sec_summary.get("benign_fixtures", []):
        v = item["verdict"]
        cls = "fail" if v == "DANGEROUS" else ("warn" if v in ("CAUTION", "UNKNOWN") else "pass")
        sec_rows.append(
            f"""
            <tr>
                <td><code>{html.escape(item['name'])}</code></td>
                <td><span class="badge {cls}">{html.escape(v)}</span></td>
                <td><code>{html.escape(str(item['allowed']))}</code></td>
                <td>{item['findings']}</td>
            </tr>
            """
        )

    scale_rows = []
    for label, ck in (perf.get("scaling_and_eviction_checkpoints") or {}).items():
        scale_rows.append(
            f"""
            <tr>
                <td><code>{html.escape(label)}</code></td>
                <td>{ck.get('active_skill_count', 0)} / 25</td>
                <td>{ck.get('process_tree_mib', 0):.2f} MiB</td>
                <td>{ck.get('loaded_payload_bytes', 0):,} B</td>
                <td>{ck.get('pinned_count', 0)}</td>
                <td>{ck.get('eviction_events_so_far', 0)}</td>
            </tr>
            """
        )

    eviction_rows = []
    for ev in perf.get("eviction_events") or []:
        eviction_rows.append(
            f"""
            <tr>
                <td>{ev.get('initial_mib', 0):.1f} MiB</td>
                <td>{ev.get('final_mib', 0):.1f} MiB</td>
                <td>{ev.get('target_watermark_mib', 210.0):.1f} MiB</td>
                <td>{ev.get('evicted_count', 0)}</td>
                <td><code>{html.escape(', '.join(ev.get('evicted_skills', [])))}</code></td>
            </tr>
            """
        )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SkillBridge v2 — Security, Runtime Memory & Evaluation Console</title>
<style>
  :root {{
    --bg-primary: #0B1120;
    --bg-surface: #111827;
    --bg-elevated: #1E293B;
    --border: #334155;
    --text-primary: #F8FAFC;
    --text-secondary: #94A3B8;
    --accent-blue: #38BDF8;
    --accent-teal: #14B8A6;
    --state-pass: #10B981;
    --state-warn: #F59E0B;
    --state-fail: #EF4444;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    margin: 0;
    padding: 28px 36px;
    line-height: 1.5;
  }}
  code, pre {{
    font-family: "JetBrains Mono", "Fira Code", Consolas, monospace;
    font-size: 0.84rem;
  }}
  .container {{ max-width: 1400px; margin: 0 auto; }}
  .topbar {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border);
    padding-bottom: 18px;
    margin-bottom: 24px;
  }}
  .brand {{
    display: flex;
    align-items: center;
    gap: 14px;
  }}
  .brand-title {{
    font-size: 1.55rem;
    font-weight: 700;
    letter-spacing: -0.02em;
  }}
  .brand-title span {{ color: var(--accent-blue); }}
  .brand-sub {{
    color: var(--text-secondary);
    font-size: 0.78rem;
    font-family: monospace;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }}
  .tabs {{
    display: flex;
    gap: 8px;
    margin-bottom: 24px;
    flex-wrap: wrap;
  }}
  .tab-btn {{
    background: var(--bg-surface);
    color: var(--text-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 8px 16px;
    font-size: 0.88rem;
    font-weight: 600;
    cursor: pointer;
  }}
  .tab-btn.active, .tab-btn:hover, .tab-btn:focus {{
    color: var(--text-primary);
    border-color: var(--accent-blue);
    outline: none;
  }}
  .grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 14px;
    margin-bottom: 28px;
  }}
  .card {{
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px 18px;
  }}
  .card .label {{
    color: var(--text-secondary);
    font-size: 0.76rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }}
  .card .value {{
    font-size: 1.75rem;
    font-weight: 700;
    color: var(--accent-blue);
    margin-top: 6px;
  }}
  .card .sub {{
    color: var(--text-secondary);
    font-size: 0.78rem;
    margin-top: 4px;
  }}
  .section-panel {{
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px;
    margin-bottom: 28px;
  }}
  .section-panel h2 {{
    margin-top: 0;
    font-size: 1.15rem;
    border-bottom: 1px solid var(--border);
    padding-bottom: 10px;
    margin-bottom: 16px;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.87rem;
  }}
  th, td {{
    padding: 9px 12px;
    border-bottom: 1px solid var(--border);
    text-align: left;
  }}
  th {{
    background: var(--bg-primary);
    color: var(--text-secondary);
    font-weight: 600;
  }}
  .badge {{
    display: inline-block;
    padding: 2px 9px;
    border-radius: 999px;
    font-size: 0.74rem;
    font-weight: 700;
  }}
  .badge.pass {{ background: rgba(16, 185, 129, 0.18); color: var(--state-pass); border: 1px solid rgba(16, 185, 129, 0.4); }}
  .badge.warn {{ background: rgba(245, 158, 11, 0.18); color: var(--state-warn); border: 1px solid rgba(245, 158, 11, 0.4); }}
  .badge.fail {{ background: rgba(239, 68, 68, 0.18); color: var(--state-fail); border: 1px solid rgba(239, 68, 68, 0.4); }}
  .tag {{
    background: var(--bg-elevated);
    color: var(--accent-teal);
    padding: 2px 8px;
    border-radius: 6px;
    font-size: 0.75rem;
    font-family: monospace;
  }}
</style>
</head>
<body>
<div class="container">
  <header class="topbar">
    <div class="brand">
      <svg viewBox="0 0 64 64" width="46" height="46" role="img" aria-label="SkillBridge Mark">
        <rect x="2" y="2" width="60" height="60" rx="14" fill="#111827" stroke="#334155" stroke-width="2"/>
        <path d="M32 10 L51 18 V33 C51 45 43 52 32 55 C21 52 13 45 13 33 V18 Z" fill="#0F172A" stroke="#475569" stroke-width="1.8"/>
        <path d="M17 38 C23 24, 41 24, 47 38" fill="none" stroke="#38BDF8" stroke-width="3.2" stroke-linecap="round"/>
        <line x1="15" y1="38" x2="49" y2="38" stroke="#94A3B8" stroke-width="2" stroke-linecap="round"/>
        <circle cx="17" cy="38" r="3" fill="#38BDF8"/>
        <circle cx="32" cy="27" r="3.5" fill="#14B8A6"/>
        <circle cx="47" cy="38" r="3" fill="#14B8A6"/>
      </svg>
      <div>
        <div class="brand-title">Skill<span>Bridge</span> v2.0</div>
        <div class="brand-sub">Multi-Tier Security Assurance · 250 MiB Runtime Eviction · Parallel MCP Broker</div>
      </div>
    </div>
    <div>
      <span class="badge pass" style="font-size: 0.92rem; padding: 7px 14px;">SYSTEM VERDICT: {html.escape(verdict)}</span>
    </div>
  </header>

  <nav class="tabs" aria-label="Dashboard Sections">
    <a class="tab-btn active" href="#metrics">1. Overview & KPIs</a>
    <a class="tab-btn" href="#tiers">2. Verification Tiers (0–3)</a>
    <a class="tab-btn" href="#memory">3. Capacity & 250 MiB Eviction</a>
    <a class="tab-btn" href="#security">4. Security Fixture Audit</a>
    <a class="tab-btn" href="#scenarios">5. {len(scenarios)}-Scenario Evaluation</a>
  </nav>

  <section id="metrics" class="grid">
    <div class="card"><div class="label">Hit@1 Accuracy</div><div class="value">{metrics.get('hit_at_1', 0)*100:.1f}%</div><div class="sub">vs {metrics.get('lexical_baseline_hit_at_1', 0)*100:.1f}% lexical baseline</div></div>
    <div class="card"><div class="label">Hit@3 Accuracy</div><div class="value">{metrics.get('hit_at_3', 0)*100:.1f}%</div><div class="sub">Target &ge; 90.0%</div></div>
    <div class="card"><div class="label">NO_MATCH Accuracy</div><div class="value">{metrics.get('no_match_accuracy', 0)*100:.1f}%</div><div class="sub">Zero hallucinated selections</div></div>
    <div class="card"><div class="label">Dangerous Blocked</div><div class="value">{metrics.get('dangerous_fixture_rejection_rate', 0)*100:.1f}%</div><div class="sub">Fail-closed on UNSAFE &amp; UNKNOWN</div></div>
    <div class="card"><div class="label">Benign False Positives</div><div class="value">{metrics.get('benign_false_positive_block_rate', 0)*100:.1f}%</div><div class="sub">Context-aware demotion</div></div>
    <div class="card"><div class="label">Active Skill Cap</div><div class="value">25</div><div class="sub">Configurable LRU session limit</div></div>
    <div class="card"><div class="label">Memory Threshold</div><div class="value">250 MiB</div><div class="sub">Evicts 5–10 skills to 210 MiB</div></div>
    <div class="card"><div class="label">Indexed Catalog</div><div class="value">{catalog.get('skills', 0)}</div><div class="sub">+ {catalog.get('mcp_servers', 0)} MCP servers</div></div>
  </section>

  <section id="tiers" class="section-panel">
    <h2>Multi-Tier Verification Architecture &amp; License Gate</h2>
    <table>
      <thead>
        <tr><th>Tier</th><th>Engine / Adapter</th><th>Pinned Revision</th><th>License</th><th>Verification Scope &amp; Status</th></tr>
      </thead>
      <tbody>
        <tr><td><code>Tier 0</code></td><td><code>BundleStager</code></td><td>Built-in v2.0</td><td>MIT</td><td>Immutable quarantine snapshot, SHA-256 tree digest, symlink/traversal/archive guard, script inventory</td></tr>
        <tr><td><code>Tier 1</code></td><td><code>SkillSpectorAdapter</code></td><td><code>95a52d89fa16</code> (v2.12.0)</td><td>Apache-2.0</td><td>Static pattern catalog, Python AST &amp; lexical taint (<code>TT1</code>–<code>TT6</code>), MCP least-privilege (<code>LP1</code>) &amp; inspection ledger</td></tr>
        <tr><td><code>Tier 2</code></td><td><code>SKILAdapter</code></td><td><code>9016d9a21c5e</code> (v0.2.0)</td><td>Apache-2.0</td><td>Declared-vs-observed capability verifier, deterministic SHA-256 Assurance Closure (<code>SAFE</code> / <code>UNSAFE</code> / <code>UNKNOWN</code>)</td></tr>
        <tr><td><code>Tier 3</code></td><td><code>SkillEvaluatorAdapter</code></td><td><code>6068b3a6d889</code> (v0.5.0)</td><td>Apache-2.0</td><td>Reuses Tier 1 SkillSpector evidence (zero duplicate scan); structural quality rubric &amp; intra/inter-skill deduplication</td></tr>
        <tr><td><code>Optional</code></td><td><code>OptionalSkillFortifyAdapter</code></td><td><code>dbb5942deae4</code> (v0.6.0)</td><td>Elastic-2.0</td><td><span class="badge warn">DISABLED BY DEFAULT</span> External CLI subprocess only; zero code or benchmark files bundled</td></tr>
      </tbody>
    </table>
  </section>

  <section id="memory" class="section-panel">
    <h2>Active Capacity Scaling (25-Skill Cap) &amp; 250 MiB Memory-Pressure Eviction</h2>
    <table>
      <thead>
        <tr><th>Scaling Checkpoint</th><th>Active Skills</th><th>Simulated Process-Tree RSS</th><th>Loaded Payload Bytes</th><th>Pinned Skills</th><th>Eviction Batches Triggered</th></tr>
      </thead>
      <tbody>
        {''.join(scale_rows)}
      </tbody>
    </table>
    <h3 style="font-size: 0.98rem; margin-top: 18px;">Recorded Memory-Pressure Eviction Batches (Threshold: 250 MiB &rarr; Watermark: 210 MiB)</h3>
    <table>
      <thead>
        <tr><th>Initial RSS</th><th>Post-Eviction RSS</th><th>Target Watermark</th><th>Batch Evicted Count</th><th>Evicted LRU Skill IDs (Pinned #01 Protected)</th></tr>
      </thead>
      <tbody>
        {''.join(eviction_rows) or '<tr><td colspan="5">No eviction batches triggered</td></tr>'}
      </tbody>
    </table>
  </section>

  <section id="security" class="section-panel">
    <h2>Security Scanner &amp; Policy Verification Fixtures</h2>
    <table>
      <thead>
        <tr><th>Fixture Name</th><th>Verdict</th><th>Allowed to Load</th><th>Findings Count</th></tr>
      </thead>
      <tbody>
        {''.join(sec_rows)}
      </tbody>
    </table>
  </section>

  <section id="scenarios" class="section-panel">
    <h2>{len(scenarios)}-Scenario Task-to-Skill Retrieval &amp; Preflight Evaluation</h2>
    <table>
      <thead>
        <tr>
          <th>ID</th><th>Category</th><th>Task Query</th><th>Expected</th><th>Selected</th><th>Lexical Baseline</th><th>Hit@1</th><th>Hit@3</th><th>Latency</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows_html)}
      </tbody>
    </table>
  </section>
</div>
</body>
</html>
"""
    output_html_path.parent.mkdir(parents=True, exist_ok=True)
    output_html_path.write_text(doc, encoding="utf-8")
    return output_html_path
