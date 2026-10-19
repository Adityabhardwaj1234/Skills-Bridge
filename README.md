# SkillBridge v2

**One bridge for every agent skill.** SkillBridge discovers, verifies, stages, loads, and orchestrates skills,
MCP servers, and agent extensions for MCP-capable coding agents such as **OpenCode**, **Claude Code**, and
**Hermes** — without flooding the model with hundreds of permanent tools.

SkillBridge v2 is a production-oriented rewrite: whole-directory skill bundles, a mandatory multi-tier
verification pipeline, a trust-aware security policy engine, bounded parallel batch loading, runtime memory
governance, a lazy MCP broker, and a generated HTML product console.

---

## Highlights

| Capability | What it does |
| --- | --- |
| **Whole-directory bundles** | Imports every nested script, reference, template, asset, workflow, and test — not just `SKILL.md` — through a 13-state Tier 0–3 pipeline. |
| **Multi-tier verification** | Tier 0 provenance/staging → Tier 1 static security scanning → Tier 2 semantic review (SKIL) → Tier 3 behavioral evaluation. Fail-closed by default. |
| **Security policy engine** | Deterministic trust × verdict matrix. DANGEROUS community/untrusted bundles are never overridable. Curated builtins require explicit operator approval. |
| **Parallel batch loading** | Load many skills at once through a bounded worker pool (`max_parallel_workers`, default **8**); per-skill failures are isolated and reported. |
| **Raised payload limits** | **4 MB** per file, **32 MB** per loaded bundle, **100** references, nesting depth **6**, **128 MB** HTTP response cap, **5,000**-file / **256 MB** staged bundle limits. |
| **Runtime memory governance** | Tracks process-tree RSS, evicts under pressure toward a 210 MiB watermark, and enforces a 25-skill active cap with pinned-skill protection. |
| **Lazy MCP broker** | 19 first-class tools plus compatibility aliases over one stable stdio JSON-RPC surface. Search, preview, import, load, batch-load, invoke, run scripts, manage MCP servers. |
| **Wide discovery** | Local client directories, bundled Hermes index, live Hermes index, skills.sh, ClawHub, browse.sh, LobeHub, GitHub, Official MCP Registry, and Smithery. |
| **Native installers** | Atomic, reversible install plans for OpenCode and Claude Code, with backups, approval gates, and rollback. |
| **Product console** | `skillbridge ui` generates a self-contained HTML dashboard from live runtime state and can serve it locally. |

---

## Requirements

- Python **3.10+** (tested through 3.13)
- Windows, macOS, or Linux
- Network access for remote providers (optional — the bundled catalog works fully offline)
- Optional: `psutil` for richer cross-platform child-process memory accounting
- Optional: externally installed verification CLIs (`skillspector`, `skil`, `skillevaluator`, `skillfortify`);
  SkillBridge ships internal fallbacks and marks missing engines as optional

---

## Installation

### From a checkout (recommended for development)

```bash
git clone <your-repo-url>
cd <repo>/V2/skillbridge
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install -e .
skillbridge doctor
```

### With optional extras

```bash
python -m pip install -e ".[dev,mcp,monitoring]"
```

### Verify the install

```bash
skillbridge --help
skillbridge doctor
skillbridge verify
```

`doctor` checks the OS, Python, SQLite, verification engines, memory provider, and detected native clients.
`verify` reports catalog counts, provider wiring, cache stats, and client readiness.

---

## Quickstart

### 1. Search the catalog

```bash
skillbridge search-skills "pdf tables extraction" --limit 10
skillbridge search-mcp "playwright"
```

The first search seeds the local SQLite catalog from the bundled Hermes index (100k+ records across index
caches) plus your local OpenCode / Claude Code / Hermes skill directories.

### 2. Preview and compare before loading

```bash
skillbridge preview-skill <skill-id>
skillbridge preflight "build a financial model with formulas" --source all
```

### 3. Import an entire local skill directory

```bash
skillbridge import-dir ./examples/my-skill --approve
```

`import-dir` stages **all** files in the directory (scripts, references, templates, assets, tests), hashes
the bundle, runs Tier 0–3 verification, and makes it available to the loader. Optional `--pin` protects the
imported bundle from LRU eviction.

You can also import by catalog ID:

```bash
skillbridge import <skill-id> --approve
```

### 4. Load one or many skills

```bash
skillbridge load-skill <skill-id> --session-id demo

# Parallel batch load (bounded worker pool)
skillbridge load-batch <skill-id-1> <skill-id-2> <skill-id-3> --workers 8 --approve
```

Each session is isolated. Use `skillbridge status`, `skillbridge memory`, and
`skillbridge unload-skill <id> --session-id demo` to inspect and release runtime state.

### 5. Generate the product console

```bash
skillbridge ui                       # writes reports/ui.html
skillbridge ui --serve --open        # serves it at http://127.0.0.1:8760/
skillbridge ui --out reports/console.html --serve --port 9000
```

The console is a single HTML file with embedded CSS/JS. It shows live catalog counts, providers, the
security matrix, verification engines, runtime limits, memory, sessions, scheduler telemetry, the audit
trail, quarantine contents, MCP tools, and an evaluation snapshot when `reports/eval_report.json` exists.

### 6. Run the evaluation suite

```bash
skillbridge evaluate
# optional: choose output locations
skillbridge evaluate --output reports/eval_report.json --dashboard reports/dashboard.html
```

---

## Use as an MCP server

SkillBridge exposes a stdio MCP broker:

```bash
skillbridge mcp-serve
```

### OpenCode

Add a local MCP server entry to your OpenCode configuration (project or global), pointing at the
installed executable:

```json
{
  "mcp": {
    "skillbridge": {
      "type": "local",
      "command": ["skillbridge", "mcp-serve"],
      "enabled": true
    }
  }
}
```

Prefer a virtualenv? Point `command` at the absolute path of the `skillbridge` executable inside it,
or use `["python", "-m", "skillbridge.cli", "mcp-serve"]` with the venv interpreter.

### Claude Code

```bash
claude mcp add skillbridge -- skillbridge mcp-serve
```

### Broker tools (19 first-class operations)

| Tool | Purpose |
| --- | --- |
| `search_skills` | Search local + remote skill catalogs. |
| `preview_skill` | Inspect metadata, body, references, scripts, dependencies, security. |
| `compare_skills` | Rank and compare multiple candidates with conflict analysis. |
| `import_skill` | Import a whole-directory bundle by catalog ID. |
| `import_directory` | Import a whole local directory by filesystem path. |
| `load_skill` | Load one verified skill into isolated session memory. |
| `load_skills_batch` | Load many skills concurrently with isolated failures. |
| `get_skill_status` | Inspect active/recalled bundle state. |
| `invoke_skill` | Read active instructions and update LRU state. |
| `run_skill_script` | Run a permitted, verified bundle script in an isolated worker. |
| `unload_skill` | Release a skill or an entire session. |
| `search_mcp_servers` | Search MCP registries. |
| `preview_mcp_server` | Inspect transport, launch command, auth, dependencies. |
| `verify_mcp_server` | Scan and verify an MCP server manifest. |
| `enable_mcp_server` / `disable_mcp_server` | Manage the active broker set. |
| `call_mcp_tool` | Invoke a tool on an enabled MCP server. |
| `get_memory_status` | RSS, thresholds, active skills, eviction history. |
| `get_audit_report` | Recent audit events, engines, scheduler stats. |

Compatibility aliases are also registered for the v1 names (`skillbridge_preflight`,
`skillbridge_search_skills`, `skillbridge_load_skill`, `skillbridge_load_skills_batch`, and others).

---

## Security model

SkillBridge applies policy **before** any skill body or script reaches the runtime.

```
Tier 0  Provenance & staging   → path validation, symlink rejection, size/depth caps, quarantine
Tier 1  Static analysis        → secret access, exfiltration, destructive commands, injection patterns
Tier 2  Semantic review        → SKIL capability/intent review, declared-vs-observed mismatch
Tier 3  Behavioral evaluation  → SkillEvaluator checks, redundancy and assurance scoring
        Policy gate            → trust × verdict matrix; DANGEROUS community never overridable
```

Policy matrix (`allow` / `ask` / `block`):

| Trust \ Verdict | SAFE | CAUTION | DANGEROUS | UNKNOWN |
| --- | --- | --- | --- | --- |
| builtin | allow | allow | block (explicit approval may allow) | ask |
| trusted | allow | allow | block | ask |
| community | allow | ask | block | ask |
| untrusted | ask | ask | block | ask |

Notes:

- Community bundles that contain executable scripts or alter client configuration require explicit
  approval even when their verdict is SAFE (`--approve` / `approved: true`).
- Builtin DANGEROUS bundles can only load when **explicitly approved** and
  `allow_builtin_dangerous_override` is enabled (default on). Community/untrusted DANGEROUS bundles are
  never allowed.
- Blocked bundles are quarantined under `~/.skillbridge/quarantine` with a JSON assessment.

---

## Configuration and limits

State lives in `~/.skillbridge` by default (override with `--home`):

```
~/.skillbridge/
├── skillbridge.db      # SQLite catalog, FTS5 index, audit, outcomes, install plans
├── quarantine/         # blocked bundle snapshots
├── backups/            # atomic install backups
├── index-cache/        # fetched provider indexes
└── settings.json       # runtime settings overrides
```

### Loader limits (`LoaderLimits`)

| Setting | Default |
| --- | --- |
| `max_file_size_bytes` | 4 MB |
| `max_total_bytes` | 32 MB |
| `max_nesting_depth` | 6 |
| `max_references` | 100 |
| `max_selected_skills` | 3 |
| `max_context_tokens` | 12,000 |
| `max_parallel_workers` | 8 |

### Bundle staging limits (`RuntimeSettings`)

| Setting | Default |
| --- | --- |
| `max_parallel_skill_workers` | 8 |
| `bundle_max_files` | 5,000 |
| `bundle_max_total_bytes` | 256 MB |
| `bundle_max_single_file_bytes` | 8 MB |
| `bundle_max_depth` | 12 |
| `active_skill_limit` | 25 |
| `memory_threshold_mib` | 250 |
| `memory_target_mib` | 210 |

### Network limits (`NetworkConfig`)

| Setting | Default |
| --- | --- |
| `max_response_bytes` | 128 MB |
| `connect_timeout_sec` | 8 |
| `read_timeout_sec` | 15 |
| `max_redirects` | 5 |
| `max_retries` | 2 |

Network requests are SSRF-guarded: explicit timeouts, redirect-hop validation, allowlisted domains, size
caps, and no interaction with private/loopback addresses by default.

---

## Discovery providers

| Provider ID | Content |
| --- | --- |
| `local` / `local-custom` | OpenCode, Claude Code, Hermes, and custom skill directories. |
| `hermes-hub` | Bundled Hermes index caches, live Hermes index, skills.sh, ClawHub, browse.sh, LobeHub. |
| `github` | Revision-pinned GitHub subtrees (whole-directory fetch). |
| `well-known` | Well-known `/.well-known/skills.json` endpoints. |
| `mcp-registry` | Official MCP Registry + curated local MCP catalog. |
| `smithery` | Smithery MCP registry (hosted HTTP or stdio via `npx @smithery/cli`). |

Offline mode (`--offline`) restricts discovery to the local catalog and cached indexes. Remote-only index
records produce actionable load errors explaining whether the failure is a stale index or offline mode.

---

## Python API

```python
import asyncio
from skillbridge import SkillBridge, SkillBridgeConfig

config = SkillBridgeConfig()
bridge = SkillBridge(config=config)

async def main():
    # Whole-directory import
    imported = await bridge.import_local_directory("./my-skill", approved=True)

    # Parallel load
    batch = await bridge.load_skills_parallel(
        ["my-skill", "anthropics/skills/docx"],
        session_id="demo",
        approved=True,
        max_workers=8,
    )

    # Protected task execution (mandatory preflight gate)
    decision = await bridge.preflight("summarize a PDF", session_id="demo")
    result, final = await bridge.execute_protected_task(decision.decision_id, lambda handles: ...)

    await bridge.unload_session("demo")

asyncio.run(main())
```

Explicit unload matters in long-lived processes: `unload_skill` / `unload_session` clear bodies, reference
maps, dedup digests, and staging directories.

---

## Development

```bash
python -m pip install -e ".[dev]"
python -m unittest discover -s tests -t .
```

Or with pytest:

```bash
PYTHONPATH=src pytest -q
```

Test categories:

- `tests/unit` — loader, enforcement, database, verification tiers, memory, scripts, parity regressions
- `tests/security` — scanner, policy, symlink/archive traversal, hash invalidation
- `tests/integration` — end-to-end bridge workflows
- `tests/evaluation` — evaluation suite scoring
- `tests/live` — opt-in live marketplace checks (skipped by default; network-gated)

Windows notes:

- Symlink-related assertions are skipped when the host lacks symlink privileges; ZIP-level symlink rejection
  is still verified.
- Memory measurement uses the Win32 working-set API when `psutil` is unavailable.

---

## Project layout

```
src/skillbridge/
├── bridge.py               # high-level async facade
├── cli.py                  # argparse CLI
├── config.py               # limits, paths, security policy config
├── settings.py             # runtime settings + settings manager
├── models.py               # records, bundles, assessments, decisions
├── bundles/manager.py      # Tier 0 staging, manifest, script inspection
├── cache/database.py       # SQLite catalog + FTS5 + audit + outcomes
├── discovery/              # engine, normalizer, candidate inspector
├── enforcement/            # preflight orchestrator + lifecycle state machine
├── evaluation/             # deterministic evaluation suite
├── installers/             # OpenCode / Claude Code adapters and plans
├── mcp_server/             # JSON-RPC stdio broker + client
├── orchestration/          # asyncio DAG scheduler, circuit breakers
├── preview/                # candidate preview generation
├── providers/              # local, GitHub, Hermes hub, MCP registry, Smithery
├── ranking/                # explainable multi-factor scoring
├── reporting/              # evaluation dashboard + product console
├── runtime/                # JIT loader, memory governance, script execution
├── security/               # scanner, policy engine, quarantine
└── verification/           # Tier 0–3 adapters and models
```

---

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `Extension '<id>' is a remote '<provider>' index record…` | The record exists only in an index. Re-run online to fetch it, or load a local/cached bundle. |
| `REQUIRES_APPROVAL: … contains executable scripts` | Re-run with `--approve` (CLI) or `"approved": true` (MCP) after reviewing the preview. |
| `DANGEROUS extensions cannot be overridden…` | The bundle is blocked by policy. Inspect the quarantine report; community DANGEROUS is never allowed. |
| First search is slow | The initial catalog seed walks bundled indexes and local skill directories. Subsequent runs reuse SQLite. |
| `WinError 1314` in tests | Enable Windows Developer Mode or run tests in an environment with symlink privileges; the suite skips host symlink assertions otherwise. |
| `psutil` not installed | Optional. SkillBridge falls back to `/proc`, `resource`, Win32 APIs, or a conservative estimate. |

---

## License

MIT — see [LICENSE](LICENSE).
