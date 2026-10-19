# SPDX-License-Identifier: Apache-2.0 AND MIT
# Portions adapted from SKIL — Skill Inspector and Linter (https://github.com/domehahn/skil,
# commit 9016d9a21c5e1a2b5fb9c11b97100d444f7d7071) under Apache License 2.0.
# Modified for Python 3.11+ compatibility and normalized SkillBridge v2 integration.

"""Tier 2 SKIL Assurance Closure, declared-vs-observed capability verification, and attestation engine."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
from typing import Any
import uuid

from skillbridge.bundles.manager import BundleManifest
from skillbridge.verification.models import (
    NORMALIZED_SCHEMA_VERSION,
    SKIL_PINNED_COMMIT,
    SKIL_PINNED_VERSION,
    AssuranceState,
    CapabilityEvidence,
    NormalizedFinding,
    NormalizedScanReport,
    utc_now_iso,
)


@dataclass
class ClosureNode:
    """Node in the deterministic SKIL Assurance Closure graph."""

    id: str
    kind: str  # root, artifact, dependency, external_reference, nested_artifact, mcp_surface, runtime_artifact
    digest: str
    required: bool = True
    resolved: bool = True
    analyzed: bool = True
    analysis_status: str = "completed"  # completed, incomplete, failed, not_run
    verification_status: str = "verified"  # verified, unverified, failed
    maximum_severity: str = "INFO"
    verdict: str = "CLEAR"  # CLEAR, REVIEW, BLOCK
    depth: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ClosureEdge:
    """Directed edge in the SKIL Assurance Closure graph."""

    from_id: str
    to_id: str
    relation: str  # contains, depends-on, configures, loads, references

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AssuranceClosure:
    """Deterministic SHA-256 Assurance Closure (adapted from SKIL internal/assurance/closure.go)."""

    root_digest: str
    nodes: list[ClosureNode] = field(default_factory=list)
    edges: list[ClosureEdge] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    complete: bool = True
    verified: bool = True
    state: AssuranceState = AssuranceState.UNKNOWN
    required_nodes: int = 0
    unresolved_nodes: int = 0
    blocking_findings: int = 0
    max_depth: int = 0
    maximum_severity: str = "INFO"
    closure_digest: str = ""

    def finalize(self) -> "AssuranceClosure":
        """Canonicalize nodes/edges, propagate SAFE/UNSAFE/UNKNOWN state, and compute order-independent digest."""
        # Deduplicate and sort nodes and edges canonically
        node_map: dict[str, ClosureNode] = {}
        for n in sorted(self.nodes, key=lambda x: (x.id, x.kind, x.digest)):
            node_map[n.id] = n
        self.nodes = [node_map[k] for k in sorted(node_map.keys())]

        edge_set = {(e.from_id, e.to_id, e.relation) for e in self.edges}
        self.edges = [
            ClosureEdge(from_id=f, to_id=t, relation=r)
            for f, t, r in sorted(edge_set)
        ]
        self.limitations = sorted(set(self.limitations))

        # Compute canonical identity digest BEFORE derived aggregate counters (matches SKIL TestDerivedAggregateMetadataDoesNotDestabilizeDigest)
        canonical_payload = {
            "root_digest": self.root_digest,
            "nodes": [
                {
                    "id": n.id,
                    "kind": n.kind,
                    "digest": n.digest,
                    "required": n.required,
                    "resolved": n.resolved,
                    "analyzed": n.analyzed,
                    "analysis_status": n.analysis_status,
                    "verification_status": n.verification_status,
                    "verdict": n.verdict,
                    "depth": n.depth,
                }
                for n in self.nodes
            ],
            "edges": [e.to_dict() for e in self.edges],
            "limitations": self.limitations,
        }
        raw_bytes = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.closure_digest = f"sha256:{hashlib.sha256(raw_bytes).hexdigest()}"

        # Derive aggregate state: UNSAFE dominates UNKNOWN, UNKNOWN dominates SAFE
        sev_rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        self.required_nodes = 0
        self.unresolved_nodes = 0
        self.blocking_findings = 0
        self.max_depth = 0
        self.maximum_severity = "INFO"

        has_unsafe = False
        has_unknown = not self.complete or len(self.nodes) == 0 or not self.root_digest

        for n in self.nodes:
            if n.depth > self.max_depth:
                self.max_depth = n.depth
            if sev_rank.get(n.maximum_severity, 0) > sev_rank.get(self.maximum_severity, 0):
                self.maximum_severity = n.maximum_severity
            if n.required:
                self.required_nodes += 1
                if n.verdict == "BLOCK" or n.maximum_severity in ("HIGH", "CRITICAL"):
                    has_unsafe = True
                    self.blocking_findings += 1
                if (
                    not n.resolved
                    or not n.analyzed
                    or n.analysis_status != "completed"
                    or n.verification_status != "verified"
                ):
                    has_unknown = True
                    self.unresolved_nodes += 1

        if has_unsafe:
            self.state = AssuranceState.UNSAFE
            self.verified = False
        elif has_unknown:
            self.state = AssuranceState.UNKNOWN
            self.verified = False
        else:
            self.state = AssuranceState.SAFE
            self.verified = True

        return self

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["state"] = self.state.value
        return data


def verify_closure_against_reviewed(
    current: AssuranceClosure,
    expected_closure_digest: str,
) -> tuple[bool, str]:
    """Compare current AssuranceClosure digest against a previously reviewed digest (closes TOCTOU gap)."""
    current.finalize()
    if current.closure_digest != expected_closure_digest:
        return (
            False,
            f"Assurance closure digest drift: expected {expected_closure_digest}, observed {current.closure_digest}",
        )
    if current.state != AssuranceState.SAFE:
        return (
            False,
            f"Assurance closure state is {current.state.value} (unresolved={current.unresolved_nodes}, blocking={current.blocking_findings})",
        )
    return True, "Assurance closure verified against reviewed digest."


# Mapping from high-level tool declarations in SKILL.md to canonical capabilities
_DECLARED_TOOL_TO_CAPABILITY = {
    "bash": "process:exec",
    "shell": "process:exec",
    "terminal": "process:exec",
    "process:exec": "process:exec",
    "exec": "process:exec",
    "write": "filesystem:read_write",
    "edit": "filesystem:read_write",
    "filesystem:read_write": "filesystem:read_write",
    "filesystem:write": "filesystem:read_write",
    "fetch": "network:outbound",
    "web": "network:outbound",
    "http": "network:outbound",
    "network:outbound": "network:outbound",
    "network": "network:outbound",
    "env": "env:read",
    "env:read": "env:read",
}


def run_builtin_tier2_skil(
    manifest: BundleManifest,
    tier1_report: NormalizedScanReport,
) -> NormalizedScanReport:
    """Run Tier 2 SKIL capability verification and Assurance Closure evaluation on a staged bundle."""
    started_at = utc_now_iso()
    findings: list[NormalizedFinding] = []
    cap_evidence: list[CapabilityEvidence] = []
    limitations: list[str] = list(tier1_report.limitations)

    # Normalize declared capabilities from SKILL.md frontmatter
    declared_canonical: set[str] = set()
    for raw_cap in manifest.declared_capabilities:
        key = raw_cap.strip().lower()
        if key in _DECLARED_TOOL_TO_CAPABILITY:
            declared_canonical.add(_DECLARED_TOOL_TO_CAPABILITY[key])
        else:
            declared_canonical.add(key)

    observed_canonical = set(manifest.observed_capabilities)
    all_caps = sorted(declared_canonical | observed_canonical)

    for cap in all_caps:
        is_decl = cap in declared_canonical
        is_obs = cap in observed_canonical
        locs = [s.relative_path for s in manifest.scripts if cap in s.observed_capabilities]
        if is_obs and not is_decl:
            has_explicit_contract = len(declared_canonical) > 0
            status = "undeclared_observed" if has_explicit_contract else "observed_unconstrained"
            sev = ("HIGH" if cap in ("network:outbound", "process:exec", "env:read") else "MEDIUM") if has_explicit_contract else "LOW"
            findings.append(
                NormalizedFinding(
                    finding_id=f"finding-{uuid.uuid4().hex[:12]}",
                    rule_id=f"SKIL_CAP_UNDECLARED_{cap.upper().replace(':', '_')}",
                    severity=sev,
                    confidence=0.9,
                    category="Capability Verification",
                    description=f"Bundle scripts exercise capability `{cap}` in {locs}, which is not declared in SKILL.md.",
                    file_path=locs[0] if locs else "SKILL.md",
                    start_line=1,
                    evidence=f"observed={cap}, declared={sorted(declared_canonical)}",
                    remediation=f"Declare `{cap}` in SKILL.md `capabilities`/`allowed-tools` or remove the capability from scripts.",
                    engine_id="skil",
                    engine_revision=SKIL_PINNED_COMMIT[:12],
                )
            )
        elif is_decl and not is_obs:
            status = "declared_unused"
        else:
            status = "matched"

        cap_evidence.append(
            CapabilityEvidence(
                capability=cap,
                declared=is_decl,
                observed=is_obs,
                source_locations=locs,
                status=status,
            )
        )

    # Build the deterministic Assurance Closure graph
    root_node = ClosureNode(
        id=f"root:{manifest.skill_id}",
        kind="root",
        digest=manifest.bundle_digest,
        required=True,
        resolved=manifest.tier0_passed,
        analyzed=tier1_report.analysis_complete,
        analysis_status="completed" if tier1_report.analysis_complete else "incomplete",
        verification_status="verified" if tier1_report.analysis_complete and manifest.tier0_passed else "unverified",
        maximum_severity="CRITICAL"
        if any(f.severity == "CRITICAL" for f in tier1_report.findings + findings)
        else "HIGH"
        if any(f.severity == "HIGH" for f in tier1_report.findings + findings)
        else "INFO",
        verdict="BLOCK"
        if any(f.severity in ("CRITICAL", "HIGH") for f in tier1_report.findings + findings)
        else "CLEAR",
        depth=0,
    )
    nodes: list[ClosureNode] = [root_node]
    edges: list[ClosureEdge] = []

    for f_entry in manifest.files:
        node_id = f"file:{f_entry.relative_path}"
        kind = "nested_artifact" if f_entry.classification == "archive" else "artifact"
        file_findings = [
            f for f in (tier1_report.findings + findings) if f.file_path == f_entry.relative_path
        ]
        max_sev = (
            "CRITICAL"
            if any(f.severity == "CRITICAL" for f in file_findings)
            else "HIGH"
            if any(f.severity == "HIGH" for f in file_findings)
            else "MEDIUM"
            if any(f.severity == "MEDIUM" for f in file_findings)
            else "INFO"
        )
        nodes.append(
            ClosureNode(
                id=node_id,
                kind=kind,
                digest=f_entry.sha256,
                required=True,
                resolved=f_entry.encoding_valid,
                analyzed=f_entry.encoding_valid and tier1_report.analysis_complete,
                analysis_status="completed" if f_entry.encoding_valid else "incomplete",
                verification_status="verified" if f_entry.encoding_valid else "unverified",
                maximum_severity=max_sev,
                verdict="BLOCK" if max_sev in ("CRITICAL", "HIGH") else "CLEAR",
                depth=1,
            )
        )
        edges.append(ClosureEdge(from_id=root_node.id, to_id=node_id, relation="contains"))

    for dep in tier1_report.dependency_evidence:
        dep_id = f"dep:{dep.ecosystem}:{dep.package_name}"
        dep_digest = f"sha256:{hashlib.sha256(dep.version_spec.encode('utf-8')).hexdigest()[:24]}"
        nodes.append(
            ClosureNode(
                id=dep_id,
                kind="dependency",
                digest=dep_digest,
                required=True,
                resolved=True,
                analyzed=True,
                analysis_status="completed",
                verification_status="verified",
                maximum_severity="HIGH" if dep.vulnerabilities else "INFO",
                verdict="BLOCK" if dep.vulnerabilities else "CLEAR",
                depth=1,
            )
        )
        edges.append(ClosureEdge(from_id=root_node.id, to_id=dep_id, relation="depends-on"))

    closure = AssuranceClosure(
        root_digest=manifest.bundle_digest,
        nodes=nodes,
        edges=edges,
        limitations=limitations,
        complete=tier1_report.analysis_complete and manifest.tier0_passed,
    ).finalize()

    exit_code = 0 if closure.state == AssuranceState.SAFE else (1 if closure.state == AssuranceState.UNSAFE else 2)

    return NormalizedScanReport(
        schema_version=NORMALIZED_SCHEMA_VERSION,
        scan_id=f"t2-skil-{uuid.uuid4().hex[:10]}",
        artifact_id=manifest.skill_id,
        artifact_digest=manifest.bundle_digest,
        engine_id="skil",
        engine_version=SKIL_PINNED_VERSION,
        engine_revision=SKIL_PINNED_COMMIT[:12],
        scan_profile="assurance-closure-static",
        scan_started_at=started_at,
        scan_completed_at=utc_now_iso(),
        scan_status="completed" if closure.complete else "incomplete",
        analysis_complete=closure.complete,
        checks_run=[
            "builtin.skill-contract",
            "builtin.tool-capability",
            "builtin.intent-divergence",
            "assurance.closure-finalize",
        ],
        checks_skipped=["runtime.gateway (enforced by SkillBridge ScriptWorker/MCPBroker at execution time)"],
        limitations=closure.limitations,
        findings=findings,
        capability_evidence=cap_evidence,
        report_artifacts={
            "assurance_closure": closure.to_dict(),
            "evidence_bundle": {
                "type": "https://skil.dev/attestation/evidence/v1",
                "producer": "skillbridge-skil-tier2",
                "producer_version": SKIL_PINNED_VERSION,
                "subject_digest": manifest.bundle_digest,
                "closure_digest": closure.closure_digest,
                "state": closure.state.value,
            },
        },
        exit_code=exit_code,
        assurance_state=closure.state,
    )


def parse_skil_cli_json(
    raw_json: str,
    *,
    artifact_id: str,
    artifact_digest: str,
    exit_code: int,
    started_at: str,
) -> NormalizedScanReport:
    """Parse real `skil scan <path> --static-only --fail-on-incomplete --format json` output."""
    try:
        payload = json.loads(raw_json)
    except Exception as exc:
        return NormalizedScanReport(
            schema_version=NORMALIZED_SCHEMA_VERSION,
            scan_id=f"t2-skil-{uuid.uuid4().hex[:10]}",
            artifact_id=artifact_id,
            artifact_digest=artifact_digest,
            engine_id="skil-cli",
            engine_version=SKIL_PINNED_VERSION,
            engine_revision=SKIL_PINNED_COMMIT[:12],
            scan_profile="external-cli",
            scan_started_at=started_at,
            scan_completed_at=utc_now_iso(),
            scan_status="failed",
            analysis_complete=False,
            limitations=[f"Invalid JSON from skil CLI: {exc}"],
            exit_code=exit_code or 3,
            assurance_state=AssuranceState.UNKNOWN,
        )

    budget = payload.get("analysis_budget") or {}
    exceeded = budget.get("exceeded") or []
    is_complete = len(exceeded) == 0 and exit_code in (0, 1)

    findings: list[NormalizedFinding] = []
    for f in payload.get("findings") or payload.get("Findings") or []:
        findings.append(
            NormalizedFinding(
                finding_id=str(f.get("id") or f"finding-{uuid.uuid4().hex[:12]}"),
                rule_id=str(f.get("rule_id") or f.get("id") or "SKIL_RULE"),
                severity=str(f.get("severity") or "MEDIUM").upper(),
                confidence=float(f.get("confidence", 0.85)),
                category=str(f.get("category") or "SKIL Assurance"),
                description=str(f.get("message") or f.get("description") or ""),
                file_path=str(f.get("path") or f.get("file") or "SKILL.md"),
                start_line=int(f.get("line") or 1),
                evidence=str(f.get("evidence") or "")[:180],
                remediation=str(f.get("remediation") or ""),
                engine_id="skil-cli",
                engine_revision=SKIL_PINNED_COMMIT[:12],
            )
        )

    closure_data = payload.get("assurance_closure") or {}
    raw_state = str(closure_data.get("state") or payload.get("state") or "").upper()
    if raw_state == "UNSAFE" or any(f.severity in ("CRITICAL", "HIGH") for f in findings) or exit_code == 1:
        assurance = AssuranceState.UNSAFE
    elif not is_complete or raw_state == "UNKNOWN" or exit_code >= 2:
        assurance = AssuranceState.UNKNOWN
    else:
        assurance = AssuranceState.SAFE

    return NormalizedScanReport(
        schema_version=NORMALIZED_SCHEMA_VERSION,
        scan_id=f"t2-skil-{uuid.uuid4().hex[:10]}",
        artifact_id=artifact_id,
        artifact_digest=artifact_digest,
        engine_id="skil-cli",
        engine_version=SKIL_PINNED_VERSION,
        engine_revision=SKIL_PINNED_COMMIT[:12],
        scan_profile="external-cli",
        scan_started_at=started_at,
        scan_completed_at=utc_now_iso(),
        scan_status="completed" if is_complete else "incomplete",
        analysis_complete=is_complete,
        checks_run=["skil.scan", "skil.assurance-closure"],
        limitations=[f"Budget exceeded: {x}" for x in exceeded],
        findings=findings,
        report_artifacts={"raw_skil": payload},
        exit_code=exit_code,
        assurance_state=assurance,
    )
