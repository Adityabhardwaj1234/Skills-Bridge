# SkillBridge v2 Security Policy & Fail-Closed Assurance Rules (`docs/security-policy.md`)

## 1. Three-Valued Assurance States (`AssuranceState`)

SkillBridge v2 enforces a strict three-valued assurance lattice across Tiers 0–3 (`src/skillbridge/verification/models.py`):

| Assurance State | Definition | Import & Execution Disposition |
| :--- | :--- | :--- |
| **`SAFE`** | Every required artifact and dependency node is resolved, fully analyzed (`analysis_complete=True`), verified against declared capabilities, and free of blocking `HIGH`/`CRITICAL` findings. | Eligible for temporary bundle import (`APPROVED_BY_POLICY`). Script execution requires `allow_untrusted_script_execution=True` or explicit `--approve`. |
| **`UNSAFE`** | One or more blocking issues (`HIGH`/`CRITICAL` security findings, Tier 0 integrity violations, or undeclared capability violations) were identified. `UNSAFE` dominates `UNKNOWN`. | **Hard-blocked (`allowed_to_load=False`)**. Quarantined in `~/.skillbridge/quarantine/`. Cannot be overridden by `--approve` or `--force`. |
| **`UNKNOWN`** | Required verification evidence is incomplete, a mandatory scanner binary was missing/crashed/timed out, or a required file had uninterpretable encoding. | **Fail-closed blocked by default (`security_fail_closed=True`)**. Never promoted to `SAFE`. Restricted read-only instruction loading is permitted only if an operator explicitly sets `security_fail_closed=False` and `load_unknown_extensions=True` on a bundle with zero executable scripts. |

## 2. Temporal & Digest Binding of `SAFE` Verdicts

`SAFE` is never treated as an eternal property of a skill name or repository:
- Every verification verdict is bound to `(skill_id, bundle_digest, closure_digest, policy_digest)`.
- Changing a single byte in `SKILL.md`, a reference file, a helper script, or a dependency manifest changes `bundle_digest` and `closure_digest`, immediately invalidating prior approvals.
- Changing a security setting via `SettingsManager` updates `policy_digest()` and never reinterprets previously blocked or incomplete scans as approved.

## 3. Offline Deterministic Default (No Unconsented LLM Transmission)

SkillBridge never transmits skill contents or local files to third-party LLM APIs by default (`--no-llm` / `--static-only` profile). Optional semantic LLM analyzers in external tools (`SkillSpector`, `SkillEvaluator`, `SKIL`) remain disabled unless explicitly configured by the user.
