# Third-Party Notices & Attributions (`docs/THIRD_PARTY_NOTICES.md`)

**SkillBridge** (`skillbridge`) is licensed under the **MIT License** (see `LICENSE`).

SkillBridge v2 integrates with external security and evaluation tools via subprocess CLI adapters and incorporates clean-room / adapted verification models compatible with the **Apache License, Version 2.0** from the open-source projects listed below.

---

## 1. NVIDIA SkillSpector (Apache-2.0)

- **Repository**: [https://github.com/NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector)
- **Pinned Revision Audited**: `95a52d89fa16f608f0b18ccee76b0918ea4b7eef` (`v2.12.0` / `v2.13.0-dev`)
- **Copyright**: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
- **License**: Apache License, Version 2.0 (`http://www.apache.org/licenses/LICENSE-2.0`)
- **Usage in SkillBridge**:
  - `SkillSpectorAdapter` (`src/skillbridge/verification/adapters.py`) invokes an installed `skillspector` CLI binary over subprocess (`skillspector scan <path> --format json --no-llm`) and normalizes its JSON/SARIF output, inspection ledger (`LedgerOutcome`, `LedgerReason`), and analyzer completeness reports (`analysis_completeness`).
  - When the external Python 3.12+ `skillspector` CLI is not installed on the host, SkillBridge's built-in Tier 1 engine (`src/skillbridge/verification/tier1_skillspector.py`) implements contract-compatible static pattern checks, Python AST behavioral and lexical-scope taint analysis (`TT1`–`TT6`), Unicode confusable/whitespace padding checks, MCP least-privilege (`LP1`–`LP4`) and tool-poisoning (`TP1`–`TP4`) checks, and inspection ledger accounting adapted under Apache-2.0.
- **Non-Endorsement Notice**: SkillBridge is an independent project and is not endorsed by, affiliated with, or sponsored by NVIDIA Corporation.

---

## 2. NVIDIA SkillEvaluator (Apache-2.0)

- **Repository**: [https://github.com/NVIDIA/SkillEvaluator](https://github.com/NVIDIA/SkillEvaluator)
- **Pinned Revision Audited**: `6068b3a6d8895430c0ff35c89635e58f2d99f1c2` (`v0.5.0`)
- **Copyright**: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
- **License**: Apache License, Version 2.0 (`http://www.apache.org/licenses/LICENSE-2.0`)
- **Required Notice (`NOTICE`)**:
  > SkillEvaluator
  > Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  > This product includes software developed by NVIDIA CORPORATION & AFFILIATES.
- **Usage in SkillBridge**:
  - `SkillEvaluatorAdapter` (`src/skillbridge/verification/adapters.py`) invokes `skillevaluator` when installed (`skillevaluator validate <path> --no-llm --report json` and `skillevaluator similarity-check`) and reuses Tier 1 `SkillSpector` results to prevent duplicate security scans.
  - SkillBridge's built-in Tier 3 evaluator (`src/skillbridge/verification/tier3_evaluator.py`) implements structural quality rubric scoring, hygiene/license/version validation, intra-skill section redundancy detection, and inter-skill catalog similarity checks adapted under Apache-2.0.

---

## 3. SKIL — Skill Inspector and Linter (Apache-2.0)

- **Repository**: [https://github.com/domehahn/skil](https://github.com/domehahn/skil)
- **Pinned Revision Audited**: `9016d9a21c5e1a2b5fb9c11b97100d444f7d7071` (`v0.2.0` / `v0.6.0-spec`)
- **License**: Apache License, Version 2.0 (`http://www.apache.org/licenses/LICENSE-2.0`)
- **Usage in SkillBridge**:
  - `SKILAdapter` (`src/skillbridge/verification/adapters.py`) invokes the `skil` Go binary when installed (`skil scan <path> --static-only --fail-on-incomplete --format json` and `skil verify`).
  - SkillBridge's built-in Tier 2 assurance engine (`src/skillbridge/verification/tier2_skil.py`) implements deterministic SHA-256 Assurance Closure graph construction (`ClosureNode`, `ClosureEdge`), three-valued assurance state propagation (`SAFE`, `UNSAFE`, `UNKNOWN`), and declared-versus-observed capability verification (including Python callable alias tracking) adapted under Apache-2.0.

---

## 4. Qualixar SkillFortify (Elastic License 2.0 — NOT DISTRIBUTED OR INCLUDED)

- **Repository**: [https://github.com/qualixar/skillfortify](https://github.com/qualixar/skillfortify)
- **Audited Revision**: `dbb5942deae46afdb5b85440d5f5d851c197c30e` (`v0.6.0`)
- **License**: Elastic License 2.0 (`https://www.elastic.co/licensing/elastic-license`)
- **Strict Separation Notice**:
  - **No source code, binary, watermark, or benchmark file from `skillfortify` is copied, vendored, embedded, or redistributed in SkillBridge.**
  - SkillBridge provides `OptionalSkillFortifyAdapter` solely as an external, disabled-by-default CLI wrapper (`skillfortify scan <path> --format json`) for users who independently install `skillfortify` in compliance with the Elastic License 2.0.

---

## 5. Hermes Agent Catalog Snapshot

- **Source**: Nous Research Hermes Agent (`hermes-agent`)
- **License**: MIT License
- **Usage in SkillBridge**: Bundled skill metadata and reference templates in `src/skillbridge/data/hermes_catalog/` and threat pattern adaptations from `skills_guard.py` / `mcp_security.py`.

---

## Full Text of the Apache License, Version 2.0

```text
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (ii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work.

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:
      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and
      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and
      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work; and
      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character.
```
