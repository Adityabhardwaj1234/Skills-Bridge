"""Normalized verification schemas, assurance states, and pinned upstream constants for SkillBridge v2."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Any


# Pinned upstream revisions verified during Phase 2 audit
SKILLSPECTOR_PINNED_VERSION = "2.12.0"
SKILLSPECTOR_PINNED_COMMIT = "95a52d89fa16f608f0b18ccee76b0918ea4b7eef"

SKILLEVALUATOR_PINNED_VERSION = "0.5.0"
SKILLEVALUATOR_PINNED_COMMIT = "6068b3a6d8895430c0ff35c89635e58f2d99f1c2"

SKIL_PINNED_VERSION = "0.2.0"
SKIL_PINNED_COMMIT = "9016d9a21c5e1a2b5fb9c11b97100d444f7d7071"

SKILLFORTIFY_PINNED_VERSION = "0.6.0"
SKILLFORTIFY_PINNED_COMMIT = "dbb5942deae46afdb5b85440d5f5d851c197c30e"

NORMALIZED_SCHEMA_VERSION = "2.0.0"


class AssuranceState(str, Enum):
    """Three-valued assurance state (never promotes missing/incomplete evidence to SAFE)."""

    SAFE = "SAFE"
    UNSAFE = "UNSAFE"
    UNKNOWN = "UNKNOWN"


class ImportState(str, Enum):
    """Exact 13-state skill bundle import lifecycle (Section 7)."""

    DISCOVERED = "DISCOVERED"
    PREVIEWED = "PREVIEWED"
    SELECTED = "SELECTED"
    FETCHED_INTO_QUARANTINE = "FETCHED_INTO_QUARANTINE"
    ARTIFACT_VALIDATED = "ARTIFACT_VALIDATED"
    TIERED_VERIFICATION = "TIERED_VERIFICATION"
    REJECTED = "REJECTED"
    UNKNOWN = "UNKNOWN"
    APPROVED_BY_POLICY = "APPROVED_BY_POLICY"
    STAGED_TEMPORARILY = "STAGED_TEMPORARILY"
    LOADED_INTO_ACTIVE_SESSION = "LOADED_INTO_ACTIVE_SESSION"
    USED = "USED"
    SCRIPT_EXECUTED_IF_ALLOWED = "SCRIPT_EXECUTED_IF_ALLOWED"
    UNLOADED = "UNLOADED"
    TEMPORARY_FILES_REMOVED = "TEMPORARY_FILES_REMOVED"
    METADATA_AND_RESULTS_RETAINED = "METADATA_AND_RESULTS_RETAINED"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class NormalizedFinding:
    """Normalized security, quality, or capability finding across all verification engines."""

    finding_id: str
    rule_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: float  # 0.0 to 1.0 (kept separate from severity per Phase 4 spec)
    category: str
    description: str
    file_path: str = ""
    start_line: int = 1
    end_line: int | None = None
    evidence: str = ""
    remediation: str = ""
    engine_id: str = ""
    engine_revision: str = ""
    dedup_fingerprint: str = ""
    verification_status: str = "active"  # active, verified, suppressed

    def __post_init__(self) -> None:
        if not self.dedup_fingerprint:
            norm = f"{self.engine_id}:{self.rule_id}:{self.file_path}:{self.start_line}:{self.evidence[:120]}"
            self.dedup_fingerprint = hashlib.sha256(norm.encode("utf-8")).hexdigest()[:24]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DependencyEvidence:
    """Dependency record captured during verification."""

    manifest_path: str
    ecosystem: str
    package_name: str
    version_spec: str
    pinned: bool
    vulnerabilities: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CapabilityEvidence:
    """Declared vs. observed capability comparison evidence."""

    capability: str
    declared: bool
    observed: bool
    source_locations: list[str] = field(default_factory=list)
    status: str = "matched"  # matched, undeclared_observed, declared_unused

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NormalizedScanReport:
    """Versioned normalized verification report required by Phase 4."""

    schema_version: str
    scan_id: str
    artifact_id: str
    artifact_digest: str
    engine_id: str
    engine_version: str
    engine_revision: str
    scan_profile: str
    scan_started_at: str
    scan_completed_at: str
    scan_status: str  # completed, incomplete, failed, skipped, timeout
    analysis_complete: bool
    checks_run: list[str] = field(default_factory=list)
    checks_skipped: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    findings: list[NormalizedFinding] = field(default_factory=list)
    dependency_evidence: list[DependencyEvidence] = field(default_factory=list)
    capability_evidence: list[CapabilityEvidence] = field(default_factory=list)
    report_artifacts: dict[str, Any] = field(default_factory=dict)
    exit_code: int = 0
    assurance_state: AssuranceState = AssuranceState.UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["assurance_state"] = self.assurance_state.value
        return data


@dataclass
class MultiTierVerificationResult:
    """Aggregated Tier 0–3 verification result and policy gate decision for an imported bundle."""

    verification_id: str
    skill_id: str
    bundle_digest: str
    assurance_state: AssuranceState
    allowed_to_load: bool
    allowed_to_execute_scripts: bool
    policy_reason: str
    tier0_passed: bool
    tier1_report: NormalizedScanReport
    tier2_report: NormalizedScanReport
    tier3_report: NormalizedScanReport
    optional_reports: list[NormalizedScanReport] = field(default_factory=list)
    closure_digest: str = ""
    quality_score: float = 0.0
    transition_history: list[str] = field(default_factory=list)
    verified_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verification_id": self.verification_id,
            "skill_id": self.skill_id,
            "bundle_digest": self.bundle_digest,
            "assurance_state": self.assurance_state.value,
            "allowed_to_load": self.allowed_to_load,
            "allowed_to_execute_scripts": self.allowed_to_execute_scripts,
            "policy_reason": self.policy_reason,
            "tier0_passed": self.tier0_passed,
            "tier1_report": self.tier1_report.to_dict(),
            "tier2_report": self.tier2_report.to_dict(),
            "tier3_report": self.tier3_report.to_dict(),
            "optional_reports": [r.to_dict() for r in self.optional_reports],
            "closure_digest": self.closure_digest,
            "quality_score": self.quality_score,
            "transition_history": self.transition_history,
            "verified_at": self.verified_at,
        }
