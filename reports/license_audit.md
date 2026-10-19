# License & Supply-Chain Audit Report (`reports/license_audit.md`)

- **Audit Date**: 2026-10-19
- **Primary Package License**: MIT (`LICENSE`)
- **Supply-Chain Policy**: Subprocess-first external scanner invocation, pinned commit SHAs, full Apache-2.0 attribution preservation, and zero redistribution of Elastic License 2.0 material.

---

## 1. Upstream License Classification Matrix

| Component | Repository | Pinned Commit SHA | Declared License | Redistribution Permitted in MIT/Apache Package? | SkillBridge v2 Disposition |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **NVIDIA SkillSpector** | `https://github.com/NVIDIA/SkillSpector` | `95a52d89fa16f608f0b18ccee76b0918ea4b7eef` | **Apache-2.0** | **YES** (with `LICENSE`, copyright, and modification notices) | Supported via `SkillSpectorAdapter` CLI subprocess and Apache-2.0 attributed Tier 1 analyzer contract (`src/skillbridge/verification/tier1_skillspector.py`). |
| **NVIDIA SkillEvaluator** | `https://github.com/NVIDIA/SkillEvaluator` | `6068b3a6d8895430c0ff35c89635e58f2d99f1c2` | **Apache-2.0** | **YES** (with `LICENSE`, `NOTICE`, and modification notices) | Supported via `SkillEvaluatorAdapter` CLI subprocess and Apache-2.0 attributed Tier 3 quality/dedup analyzer (`src/skillbridge/verification/tier3_evaluator.py`). |
| **SKIL** | `https://github.com/domehahn/skil` | `9016d9a21c5e1a2b5fb9c11b97100d444f7d7071` | **Apache-2.0** | **YES** (with `LICENSE` and copyright notices) | Supported via `SKILAdapter` CLI subprocess and Apache-2.0 attributed Tier 2 Assurance Closure & capability verifier (`src/skillbridge/verification/tier2_skil.py`). |
| **Qualixar SkillFortify** | `https://github.com/qualixar/skillfortify` | `dbb5942deae46afdb5b85440d5f5d851c197c30e` | **Elastic License 2.0** | **NO** (restricts managed service hosting, requires license propagation, contains proprietary watermarks `_watermark.py`) | **EXCLUDED FROM DISTRIBUTION**. Zero code, watermarks, or benchmark files copied. Supported **only** as an optional, disabled-by-default external CLI adapter (`OptionalSkillFortifyAdapter`). |
| **SkillFortifyBench (In-Repo)** | `qualixar/skillfortify/benchmarks` | `dbb5942deae46afdb5b85440d5f5d851c197c30e` | Bundled inside Elastic-2.0 repository (`benchmarks/ATTRIBUTION.md`) | **NOT USED** (bundled inside Elastic-2.0 repo without a separate standalone `LICENSE` file in `benchmarks/`) | **OMITTED**. Because `benchmarks/` in the audited archive sits inside the Elastic-2.0 repository without an independent `LICENSE` file, SkillBridge uses its own original adversarial & benign test fixtures in `tests/fixtures/`. |

---

## 2. Verification of Compliance Controls

1. **Zero Elastic-2.0 Contamination**:
   - Verified via repository tree scan that no files, functions, classes, or benchmark specimens from `skillfortify` exist anywhere in `/working_dir/c_450284e786a4c499/skillbridge`.
2. **Apache-2.0 Section 4 Compliance**:
   - Full Apache-2.0 license text, NVIDIA `NOTICE` text, copyright headers, and prominent notices of adaptation for Python 3.11 compatibility are included in `docs/THIRD_PARTY_NOTICES.md`, `docs/license-and-attribution.md`, and source module headers.
3. **Trademark & Non-Endorsement Compliance**:
   - SkillBridge uses original SVG brand marks (`assets/brand/skillbridge-mark.svg`) and explicitly states in `docs/THIRD_PARTY_NOTICES.md` that it is not affiliated with or endorsed by NVIDIA Corporation, Qualixar, or DomeHahn.
4. **Software Bill of Materials (SBOM)**:
   - CycloneDX 1.6 SBOM generated at `reports/sbom.cdx.json` enumerating SkillBridge v2.0.0, runtime dependencies (`PyYAML`, optional `httpx`), bundled catalogs, and pinned external verification engine contracts.
