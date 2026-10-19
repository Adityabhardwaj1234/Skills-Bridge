# License, Attribution & Supply-Chain Governance (`docs/license-and-attribution.md`)

## 1. Licensing Overview

SkillBridge is distributed under the **MIT License** (`LICENSE`), while preserving full **Apache License 2.0** attributions and notices (`docs/THIRD_PARTY_NOTICES.md`) for adapted verification contracts and schemas from:
- **NVIDIA SkillSpector** (`Apache-2.0`, commit `95a52d89fa16f608f0b18ccee76b0918ea4b7eef`)
- **NVIDIA SkillEvaluator** (`Apache-2.0`, commit `6068b3a6d8895430c0ff35c89635e58f2d99f1c2`)
- **SKIL — Skill Inspector and Linter** (`Apache-2.0`, commit `9016d9a21c5e1a2b5fb9c11b97100d444f7d7071`)

## 2. Strict Isolation of Elastic License 2.0 Components (`SkillFortify`)

`qualixar/skillfortify` (`v0.6.0`, commit `dbb5942deae46afdb5b85440d5f5d851c197c30e`) is licensed under the **Elastic License 2.0**. To keep SkillBridge 100% open-source and free of proprietary/source-available licensing restrictions:
1. **No Code or Binary Distribution**: SkillBridge does not vendor, copy, translate, or package any `skillfortify` source code, watermarks, or executables.
2. **No Benchmark Corpus Copying**: Although `SkillFortifyBench` is described in external papers as MIT-licensed, the `benchmarks/` directory inside the `skillfortify` repository archive resides under the root `Elastic License 2.0` without a standalone `benchmarks/LICENSE` file. Therefore, SkillBridge does not copy any `SkillFortifyBench` specimens and instead ships its own clean-room test fixtures under `tests/fixtures/`.
3. **Opt-In External Subprocess Only**: `OptionalSkillFortifyAdapter` (`src/skillbridge/verification/adapters.py`) is disabled by default (`RuntimeSettings.enable_skillfortify = False`). Operators who have independently installed `skillfortify` and reviewed the Elastic License 2.0 may opt in via settings (`enable_skillfortify=True`).

## 3. Pinned Revisions & Upgrade/Rollback Procedure

All upstream adapter contracts are pinned in `src/skillbridge/verification/models.py`:
- `SKILLSPECTOR_PINNED_COMMIT = "95a52d89fa16f608f0b18ccee76b0918ea4b7eef"` (`v2.12.0`)
- `SKILLEVALUATOR_PINNED_COMMIT = "6068b3a6d8895430c0ff35c89635e58f2d99f1c2"` (`v0.5.0`)
- `SKIL_PINNED_COMMIT = "9016d9a21c5e1a2b5fb9c11b97100d444f7d7071"` (`v0.2.0`)
- `SKILLFORTIFY_PINNED_COMMIT = "dbb5942deae46afdb5b85440d5f5d851c197c30e"` (`v0.6.0`)

### Upgrading an External Verification Engine
1. Install the new version of the external tool in an isolated virtual environment or container.
2. Run `python -m skillbridge doctor` to verify version compatibility and CLI schema conformance.
3. Run the adapter contract suite (`python -m unittest tests/unit/test_verification_tiers.py -v`) before updating the pinned commit constant.
4. Because cached verification verdicts in SQLite are keyed by `(content_hash, engine_id, engine_version, policy_hash)`, upgrading an engine automatically invalidates stale verdicts without manual cache deletion.
