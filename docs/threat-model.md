# SkillBridge v2 Comprehensive Threat Model (`docs/threat-model.md`)

## 1. Threat Matrix & Defensive Controls (22 Threat Vectors)

| # | Threat Vector | Mitigating Control in SkillBridge v2 | Verification Test |
| :--- | :--- | :--- | :--- |
| 1 | **Prompt Injection in `SKILL.md`** | Tier 1 static pattern catalog (`prompt_injection_ignore`, `sys_prompt_override`, `deception_hide`, HTML comments) | `test_security_suite.py` |
| 2 | **Malicious Scripts in Supporting Dirs** | Whole-bundle Tier 0–1 scanning across `scripts/`, `references/`, `assets/`, `examples/` (never trusts clean `SKILL.md` alone) | `test_verification_tiers.py` |
| 3 | **Python Import-Time Execution** | Never imports skill `.py` files into SkillBridge; uses `ast.parse()` for inspection and isolated subprocesses for execution | `test_runtime_v2_memory_and_scripts.py` |
| 4 | **Dependency Confusion & Unpinned Packages** | Static manifest parser (`requirements.txt`, `pyproject.toml`, `package.json`) flags unpinned specs and custom PyPI URLs; never runs `setup.py` | `test_verification_tiers.py` |
| 5 | **Registry or Repository Compromise** | All remote fetches pass through quarantine staging and Tier 0–3 scanning regardless of repository popularity | `test_live_marketplaces.py` |
| 6 | **Mutable Branch and Tag Attacks** | `GitHubSkillsProvider` resolves and pins commit/tree SHAs (`version_or_revision`) before fetching bundle files | `test_integration_suite.py` |
| 7 | **Hash Mismatches & TOCTOU Tampering** | `BundleStager.recompute_staged_digest()` re-verifies the bundle SHA-256 tree digest on promotion and immediately before script execution | `test_runtime_v2_memory_and_scripts.py` |
| 8 | **Unicode & Text Obfuscation** | Detects zero-width chars, Unicode Tag smuggling (`U+E0001`), Cyrillic/Greek homoglyphs (`UC1`), and newline-split instructions (`AE6`) | `test_verification_tiers.py` |
| 9 | **Path Traversal & Malicious Symlinks** | `validate_bundle_rel_path` and `BundleStager` reject `..`, absolute paths, Windows drives, and any symlink inside a bundle | `test_security_suite.py` |
| 10 | **Archive Bombs & Oversized Downloads** | `GuardedHttpClient`, `HermesHubProvider`, and `BundleStager` enforce byte caps, file count caps (`500`), and decompression ratio bounds | `test_unit_core.py` |
| 11 | **Credential Theft & Env Harvesting** | Tier 1 lexical taint tracker (`TT1`–`TT6`) + secret stripping in `ScriptExecutionManager` worker environment | `test_verification_tiers.py` |
| 12 | **Unapproved Network Access** | Tier 2 SKIL capability verifier flags undeclared `network:outbound`; `ScriptExecutionManager` disables sockets by default | `test_verification_tiers.py` |
| 13 | **Destructive Filesystem Operations** | Static & AST detection of `rm -rf /`, `rm -rf $HOME`, `mkfs`, `dd`, `shutil.rmtree` on variables | `test_security_suite.py` |
| 14 | **MCP Tool Poisoning & Privilege Escalation** | B.3.1 Least Privilege (`LP1_WILDCARD_GRANT`), B.3.2 Tool Poisoning, and malicious MCP package IOC blocklist (`postmark-mcp`, `mcp-remote`) | `test_security_suite.py` |
| 15 | **Malicious Agent Definitions & Hooks** | Blocks skills/scripts attempting to modify `AGENTS.md`, `CLAUDE.md`, `.claude/settings.json`, or `opencode.jsonc` | `test_security_suite.py` |
| 16 | **Confused-Deputy Behavior in MCP Broker** | `call_mcp_tool` and `run_skill_script` validate registered IDs, active verification state, and argument safety before dispatch | `test_runtime_v2_memory_and_scripts.py` |
| 17 | **Parallel-Task State Contamination** | Session-keyed handles (`_active_sessions[session_id]`) and per-session staging directories (`active_staging/<session_id>/`) | `test_enforcement.py` |
| 18 | **Unsafe Cleanup of Shared Artifacts** | `in_use=True` reference guarding prevents evicting or deleting a staged bundle while a script worker or task is using it | `test_runtime_v2_memory_and_scripts.py` |
| 19 | **Log & Report Disclosure of Secrets** | `redact_secrets()` scrubs `sk-*`, `ghp_*`, `github_pat_*`, `AKIA*`, and `Bearer` tokens from all stdout/stderr, DB logs, and reports | `test_security_suite.py` |
| 20 | **Registry Timeouts & Scanner Outages** | Missing, crashing, or timed-out scanners produce `AssuranceState.UNKNOWN` (`analysis_complete=False`), failing closed | `test_verification_tiers.py` |
| 21 | **Compromised Cache Entries** | Verification cache entries are bound to `(skill_id, bundle_digest, scanner_version)`; digest changes invalidate cached verdicts | `test_security_suite.py` |
| 22 | **Attempts to Bypass Mandatory Preflight** | `PreflightOrchestrator.execute_protected_task` enforces all lifecycle states and raises `PreflightBypassError` on unverified tasks | `test_enforcement.py` |
