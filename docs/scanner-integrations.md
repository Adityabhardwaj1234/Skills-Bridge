# External Verification Engine Integrations (`docs/scanner-integrations.md`)

## 1. Coordinator & Adapter Contract (`VerificationCoordinator`)

Implemented in `src/skillbridge/verification/adapters.py`, `VerificationCoordinator` orchestrates four typed `VerificationEngineAdapter` implementations:

```text
VerificationCoordinator
  ├── SkillSpectorAdapter         (Tier 1 — Apache-2.0)
  ├── SKILAdapter                 (Tier 2 — Apache-2.0)
  ├── SkillEvaluatorAdapter       (Tier 3 — Apache-2.0)
  └── OptionalSkillFortifyAdapter (Optional — Elastic-2.0 External CLI Only)
```

Each adapter implements:
- `is_installed()` & `resolve_executable()`
- `get_installed_version()` & `check_prerequisites()`
- `build_command(exe, target_path)` (returns argument array, never shell string)
- `execute_subprocess(target_path)` (`shell=False`, timeout, bounded stdout/stderr, stripped secrets)
- Normalization into `NormalizedScanReport` (`schema_version="2.0.0"`, `findings[]`, `dependency_evidence[]`, `capability_evidence[]`, `report_artifacts`, `exit_code`, `assurance_state`).

---

## 2. Per-Engine CLI Contracts & Built-In Apache-2.0 Fallbacks

### A. NVIDIA SkillSpector (`SkillSpectorAdapter` — Tier 1)
- **Pinned Revision**: `95a52d89fa16f608f0b18ccee76b0918ea4b7eef` (`v2.12.0`)
- **CLI Command**: `skillspector scan <staged_path> --format json --no-llm`
- **Exit Codes**: `0` = pass (`SAFE`), `1` = policy/risk failure (`UNSAFE`), `2` = incomplete scan or runtime error (`UNKNOWN`).
- **Built-In Python 3.11 Engine (`tier1_skillspector.py`)**: Executes static pattern catalogs, Python AST & lexical-scope taint tracking (`TT1`–`TT6`), callable alias resolution (`BA1_ALIAS_SHELL_EXEC`), newline-split obfuscated instruction reconstruction (`AE6`), Unicode confusable detection (`UC1`), MCP least-privilege (`LP1_WILDCARD_GRANT`), and inspection ledger completeness accounting.

### B. SKIL (`SKILAdapter` — Tier 2)
- **Pinned Revision**: `9016d9a21c5e1a2b5fb9c11b97100d444f7d7071` (`v0.2.0`)
- **CLI Command**: `skil scan <staged_path> --static-only --fail-on-incomplete --format json`
- **Exit Codes**: `0` (`ExitOK`), `1` (`ExitGateFail`), `2` (`ExitInput`), `3` (`ExitInternal`).
- **Built-In Python 3.11 Engine (`tier2_skil.py`)**: Compares declared vs. statically observed capabilities (`CapabilityEvidence`) and constructs the canonical order-independent SHA-256 `AssuranceClosure` graph (`SAFE`, `UNSAFE`, `UNKNOWN`).

### C. NVIDIA SkillEvaluator (`SkillEvaluatorAdapter` — Tier 3)
- **Pinned Revision**: `6068b3a6d8895430c0ff35c89635e58f2d99f1c2` (`v0.5.0`)
- **CLI Command**: `skillevaluator validate <staged_path> --no-llm --report json`
- **Non-Redundant Tier 1 Reuse**: Records `reused_tier1_scan_id = tier1_report.scan_id` so `SkillSpector` is never executed twice on the same bundle.
- **Built-In Python 3.11 Engine (`tier3_evaluator.py`)**: Computes structural quality rubric scores (`0`–`100`), script syntax lint checks, intra-skill duplicate section detection, and inter-skill catalog overlap similarity.

### D. Qualixar SkillFortify (`OptionalSkillFortifyAdapter` — Optional)
- **Pinned Revision**: `dbb5942deae46afdb5b85440d5f5d851c197c30e` (`v0.6.0`)
- **CLI Command**: `skillfortify scan <staged_path> --format json`
- **Strict License Boundary**: Disabled by default (`enable_skillfortify=False`). Zero source code, watermarks, or benchmark files from `skillfortify` are included in SkillBridge.
