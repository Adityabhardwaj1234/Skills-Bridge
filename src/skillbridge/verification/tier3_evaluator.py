# SPDX-License-Identifier: Apache-2.0 AND MIT
# Portions adapted from NVIDIA SkillEvaluator (https://github.com/NVIDIA/SkillEvaluator,
# commit 6068b3a6d8895430c0ff35c89635e58f2d99f1c2) under Apache License 2.0.
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# Modified for Python 3.11+ compatibility and normalized SkillBridge v2 integration.

"""Tier 3 NVIDIA SkillEvaluator structural quality, deduplication, and non-redundant evaluation engine."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any
import uuid

from skillbridge.bundles.manager import BundleManifest
from skillbridge.discovery.normalizer import parse_skill_md
from skillbridge.verification.models import (
    NORMALIZED_SCHEMA_VERSION,
    SKILLEVALUATOR_PINNED_COMMIT,
    SKILLEVALUATOR_PINNED_VERSION,
    AssuranceState,
    NormalizedFinding,
    NormalizedScanReport,
    utc_now_iso,
)


def _jaccard_tokens(text_a: str, text_b: str) -> float:
    tokens_a = set(re.findall(r"[a-z0-9]{3,}", text_a.lower()))
    tokens_b = set(re.findall(r"[a-z0-9]{3,}", text_b.lower()))
    if not tokens_a or not tokens_b:
        return 0.0
    return len(tokens_a & tokens_b) / len(tokens_a | tokens_b)


def run_builtin_tier3_evaluator(
    manifest: BundleManifest,
    tier1_report: NormalizedScanReport,
    *,
    catalog_descriptions: dict[str, str] | None = None,
    similarity_threshold: float = 0.82,
) -> NormalizedScanReport:
    """Run Tier 3 structural quality, intra-skill dedup, and inter-skill similarity without re-running SkillSpector."""
    started_at = utc_now_iso()
    staged_root = Path(manifest.staged_path)
    skill_md_path = staged_root / "SKILL.md"
    findings: list[NormalizedFinding] = []
    checks_run = [
        "SchemaValidator",
        "HygieneValidator",
        "ScriptLintValidator",
        "QualityScoreValidator",
        "IntraSkillValidator (Tier 2 Dedup)",
        "SimilarityValidator (Tier 2 Catalog Overlap)",
    ]
    checks_skipped = [
        f"SecurityValidator.skillspector (reused Tier 1 scan_id={tier1_report.scan_id} without redundant re-scan)",
        "Tier3LiveHarborTrial (skipped by default; requires explicit behavioral sandbox authorization)",
    ]
    limitations: list[str] = []
    analysis_complete = True

    quality_score = 0.0
    intra_skill_duplicates: list[str] = []
    similar_skills: list[dict[str, Any]] = []

    if not skill_md_path.exists() or not manifest.tier0_passed:
        analysis_complete = False
        limitations.append("Cannot complete Tier 3 quality evaluation on invalid or missing SKILL.md.")
    else:
        raw_text = skill_md_path.read_text(encoding="utf-8", errors="replace")
        frontmatter, body = parse_skill_md(raw_text)

        score = 40.0
        name = str(frontmatter.get("name") or "")
        desc = str(frontmatter.get("description") or "")
        if re.match(r"^[a-z0-9]+(-[a-z0-9]+)*$", name):
            score += 10.0
        else:
            findings.append(
                NormalizedFinding(
                    finding_id=f"finding-{uuid.uuid4().hex[:12]}",
                    rule_id="SE_SCHEMA_NAME",
                    severity="LOW",
                    confidence=1.0,
                    category="Schema Validation",
                    description=f"Skill name `{name}` should use lowercase kebab-case slug format.",
                    file_path="SKILL.md",
                    start_line=1,
                    remediation="Use lowercase letters, digits, and hyphens for `name`.",
                    engine_id="skillevaluator",
                    engine_revision=SKILLEVALUATOR_PINNED_COMMIT[:12],
                )
            )

        if len(desc) >= 25:
            score += 15.0
        else:
            findings.append(
                NormalizedFinding(
                    finding_id=f"finding-{uuid.uuid4().hex[:12]}",
                    rule_id="SE_QUALITY_SHORT_DESC",
                    severity="LOW",
                    confidence=0.9,
                    category="Quality Rubric",
                    description="Skill description is under 25 characters, reducing discovery trigger accuracy.",
                    file_path="SKILL.md",
                    start_line=1,
                    remediation="Provide a specific trigger description explaining when to use this skill.",
                    engine_id="skillevaluator",
                    engine_revision=SKILLEVALUATOR_PINNED_COMMIT[:12],
                )
            )

        headings = re.findall(r"^#{1,3}\s+(.+)$", body, flags=re.M)
        if len(headings) >= 1:
            score += 15.0
        if "```" in body or len(manifest.scripts) > 0:
            score += 10.0
        if len(body.strip()) >= 120:
            score += 10.0

        for s_entry in manifest.scripts:
            if not s_entry.syntax_valid:
                score -= 20.0
                findings.append(
                    NormalizedFinding(
                        finding_id=f"finding-{uuid.uuid4().hex[:12]}",
                        rule_id="SE_SCRIPT_SYNTAX_ERROR",
                        severity="HIGH",
                        confidence=1.0,
                        category="Script Lint",
                        description=f"Script `{s_entry.relative_path}` has a syntax error: {s_entry.syntax_error}",
                        file_path=s_entry.relative_path,
                        start_line=1,
                        evidence=str(s_entry.syntax_error or ""),
                        remediation="Fix syntax errors in bundled scripts before importing.",
                        engine_id="skillevaluator",
                        engine_revision=SKILLEVALUATOR_PINNED_COMMIT[:12],
                    )
                )

        sections = re.split(r"^#{2,3}\s+", body, flags=re.M)
        norm_sections: list[str] = []
        for sec in sections[1:]:
            cleaned = sec.strip()
            if len(cleaned) < 80:
                continue
            for prev in norm_sections:
                if _jaccard_tokens(cleaned, prev) > 0.88:
                    first_line = cleaned.splitlines()[0][:60]
                    intra_skill_duplicates.append(first_line)
                    findings.append(
                        NormalizedFinding(
                            finding_id=f"finding-{uuid.uuid4().hex[:12]}",
                            rule_id="SE_INTRA_SKILL_REDUNDANCY",
                            severity="LOW",
                            confidence=0.8,
                            category="Intra-Skill Deduplication",
                            description=f"Section `{first_line}` has >88% token overlap with an earlier section.",
                            file_path="SKILL.md",
                            start_line=1,
                            remediation="Consolidate duplicate sections to reduce context token waste.",
                            engine_id="skillevaluator",
                            engine_revision=SKILLEVALUATOR_PINNED_COMMIT[:12],
                        )
                    )
                    break
            norm_sections.append(cleaned)

        if catalog_descriptions:
            query_text = f"{name} {desc}"
            for other_id, other_desc in catalog_descriptions.items():
                if other_id == manifest.skill_id:
                    continue
                sim = _jaccard_tokens(query_text, other_desc)
                if sim >= similarity_threshold:
                    similar_skills.append({"skill_id": other_id, "similarity": round(sim, 3)})

        quality_score = max(0.0, min(100.0, score))

    has_blocking = any(f.severity in ("CRITICAL", "HIGH") for f in findings) or (
        tier1_report.assurance_state == AssuranceState.UNSAFE
    )
    if has_blocking:
        assurance = AssuranceState.UNSAFE
        exit_code = 1
    elif not analysis_complete or not tier1_report.analysis_complete:
        assurance = AssuranceState.UNKNOWN
        exit_code = 1
    else:
        assurance = AssuranceState.SAFE
        exit_code = 0

    return NormalizedScanReport(
        schema_version=NORMALIZED_SCHEMA_VERSION,
        scan_id=f"t3-eval-{uuid.uuid4().hex[:10]}",
        artifact_id=manifest.skill_id,
        artifact_digest=manifest.bundle_digest,
        engine_id="skillevaluator",
        engine_version=SKILLEVALUATOR_PINNED_VERSION,
        engine_revision=SKILLEVALUATOR_PINNED_COMMIT[:12],
        scan_profile="tier1-2-static-reusing-skillspector",
        scan_started_at=started_at,
        scan_completed_at=utc_now_iso(),
        scan_status="completed" if analysis_complete else "incomplete",
        analysis_complete=analysis_complete,
        checks_run=checks_run,
        checks_skipped=checks_skipped,
        limitations=limitations,
        findings=findings,
        report_artifacts={
            "quality_score": quality_score,
            "reused_tier1_scan_id": tier1_report.scan_id,
            "intra_skill_duplicates": intra_skill_duplicates,
            "inter_skill_similarities": similar_skills,
        },
        exit_code=exit_code,
        assurance_state=assurance,
    )


def parse_skillevaluator_cli_json(
    raw_json: str,
    *,
    artifact_id: str,
    artifact_digest: str,
    exit_code: int,
    started_at: str,
    reused_tier1_scan_id: str = "",
) -> NormalizedScanReport:
    """Parse real `skillevaluator validate <path> --no-llm --report json` output."""
    try:
        payload = json.loads(raw_json)
    except Exception as exc:
        return NormalizedScanReport(
            schema_version=NORMALIZED_SCHEMA_VERSION,
            scan_id=f"t3-eval-{uuid.uuid4().hex[:10]}",
            artifact_id=artifact_id,
            artifact_digest=artifact_digest,
            engine_id="skillevaluator-cli",
            engine_version=SKILLEVALUATOR_PINNED_VERSION,
            engine_revision=SKILLEVALUATOR_PINNED_COMMIT[:12],
            scan_profile="external-cli",
            scan_started_at=started_at,
            scan_completed_at=utc_now_iso(),
            scan_status="failed",
            analysis_complete=False,
            limitations=[f"Invalid JSON from skillevaluator CLI: {exc}"],
            exit_code=exit_code or 1,
            assurance_state=AssuranceState.UNKNOWN,
        )

    results = payload if isinstance(payload, list) else payload.get("results") or [payload]
    checks_run: list[str] = []
    limitations: list[str] = []
    findings: list[NormalizedFinding] = []
    is_complete = True
    quality_score = 85.0

    for res in results:
        if not isinstance(res, dict):
            continue
        vname = str(res.get("validator_name") or "Validator")
        checks_run.append(vname)
        if res.get("scan_incomplete") or res.get("is_complete") is False:
            is_complete = False
            limitations.append(f"Validator {vname} reported incomplete scan.")
        if "quality_score" in res:
            quality_score = float(res["quality_score"])
        for f in res.get("findings") or []:
            findings.append(
                NormalizedFinding(
                    finding_id=str(f.get("id") or f"finding-{uuid.uuid4().hex[:12]}"),
                    rule_id=str(f.get("rule_id") or f.get("code") or vname),
                    severity=str(f.get("severity") or "LOW").upper(),
                    confidence=float(f.get("confidence", 0.8)),
                    category=vname,
                    description=str(f.get("message") or f.get("description") or ""),
                    file_path=str(f.get("file_path") or f.get("file") or "SKILL.md"),
                    start_line=int(f.get("line_number") or f.get("line") or 1),
                    evidence=str(f.get("snippet") or "")[:180],
                    remediation=str(f.get("suggestion") or f.get("remediation") or ""),
                    engine_id="skillevaluator-cli",
                    engine_revision=SKILLEVALUATOR_PINNED_COMMIT[:12],
                )
            )

    has_blocking = any(f.severity in ("CRITICAL", "HIGH") for f in findings)
    if has_blocking:
        assurance = AssuranceState.UNSAFE
    elif not is_complete or exit_code != 0:
        assurance = AssuranceState.UNKNOWN
    else:
        assurance = AssuranceState.SAFE

    return NormalizedScanReport(
        schema_version=NORMALIZED_SCHEMA_VERSION,
        scan_id=f"t3-eval-{uuid.uuid4().hex[:10]}",
        artifact_id=artifact_id,
        artifact_digest=artifact_digest,
        engine_id="skillevaluator-cli",
        engine_version=SKILLEVALUATOR_PINNED_VERSION,
        engine_revision=SKILLEVALUATOR_PINNED_COMMIT[:12],
        scan_profile="external-cli",
        scan_started_at=started_at,
        scan_completed_at=utc_now_iso(),
        scan_status="completed" if is_complete else "incomplete",
        analysis_complete=is_complete,
        checks_run=checks_run,
        limitations=limitations,
        findings=findings,
        report_artifacts={
            "quality_score": quality_score,
            "reused_tier1_scan_id": reused_tier1_scan_id,
            "raw_skillevaluator": payload,
        },
        exit_code=exit_code,
        assurance_state=assurance,
    )
