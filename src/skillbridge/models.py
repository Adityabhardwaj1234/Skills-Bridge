"""Normalized data models for SkillBridge extensions, security scans, preflight, runtime loading, and installers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


class ExtensionType(str, Enum):
    SKILL = "skill"
    MCP_SERVER = "mcp_server"
    AGENT = "agent"
    TOOLSET = "toolset"


class TrustLevel(str, Enum):
    BUILTIN = "builtin"
    TRUSTED = "trusted"
    COMMUNITY = "community"
    AGENT_CREATED = "agent-created"
    UNTRUSTED = "untrusted"


class SecurityVerdict(str, Enum):
    SAFE = "SAFE"
    CAUTION = "CAUTION"
    DANGEROUS = "DANGEROUS"
    UNKNOWN = "UNKNOWN"


class PreflightState(str, Enum):
    CREATED = "CREATED"
    PREFLIGHT_STARTED = "PREFLIGHT_STARTED"
    SEARCH_LOCAL_AND_APPROVED_CATALOGS = "SEARCH_LOCAL_AND_APPROVED_CATALOGS"
    PREVIEW_TOP_CANDIDATES = "PREVIEW_TOP_CANDIDATES"
    COMPARE_RELEVANCE_COMPATIBILITY_AND_RISK = "COMPARE_RELEVANCE_COMPATIBILITY_AND_RISK"
    SELECT_BEST_MATCH_OR_EXPLICIT_NO_MATCH = "SELECT_BEST_MATCH_OR_EXPLICIT_NO_MATCH"
    LOAD_SELECTED_SKILL_IF_APPROPRIATE = "LOAD_SELECTED_SKILL_IF_APPROPRIATE"
    EXECUTE_TASK = "EXECUTE_TASK"
    VERIFY_RESULT_AND_RECORD_OUTCOME = "VERIFY_RESULT_AND_RECORD_OUTCOME"
    RELEASE_TEMPORARY_RUNTIME_REFERENCES = "RELEASE_TEMPORARY_RUNTIME_REFERENCES"


@dataclass
class SecurityFinding:
    """Structured security finding for a specific file and line."""
    pattern_id: str
    severity: str       # "critical" | "high" | "medium" | "low"
    category: str       # "injection" | "exfiltration" | "destructive" | "persistence" | "obfuscation" | "supply_chain" | "traversal" | "privilege_escalation" | "credential_exposure" | "structural" | "network"
    file: str
    line: int
    match: str
    reason: str
    remediation: str = "Inspect and remove suspicious pattern before approving installation."

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityAssessment:
    """Complete security scan assessment for an extension."""
    extension_id: str
    name: str
    source: str
    trust_level: str
    verdict: str        # SecurityVerdict value: SAFE, CAUTION, DANGEROUS, UNKNOWN
    findings: List[SecurityFinding] = field(default_factory=list)
    ast_findings: List[Dict[str, Any]] = field(default_factory=list)
    content_hash: str = ""
    scanned_at: str = field(default_factory=utc_now_iso)
    scanner_version: str = "skillbridge-guard-v1"
    allowed: Optional[bool] = None
    policy_reason: str = ""
    quarantine_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DependencySpec:
    """Runtime, executable, or package dependency requirement."""
    kind: str           # "executable" | "python_package" | "node_package" | "env_var" | "os"
    name: str
    version_constraint: str = ""
    required: bool = True
    secret: bool = False
    description: str = ""


@dataclass
class MCPTransportSpec:
    """Normalized MCP server transport specification."""
    transport_type: str                 # "stdio" | "http" | "sse"
    command: Optional[str] = None
    args: List[str] = field(default_factory=list)
    url: Optional[str] = None
    env: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    auth_type: str = "none"             # "none" | "api_key" | "oauth"
    oauth_config: Dict[str, Any] = field(default_factory=dict)
    cwd: Optional[str] = None
    timeout_ms: int = 10000


@dataclass
class ExtensionRecord:
    """Unified normalized model representing a Skill, MCP Server, Agent, or Toolset."""
    extension_id: str                   # e.g., "official/software-development/github" or "skills-sh/vercel/ai/agent-skills"
    name: str                           # e.g., "github"
    display_name: str
    extension_type: str                 # ExtensionType value: "skill" | "mcp_server" | "agent" | "toolset"
    description: str
    source_provider: str                # "local", "hermes-official", "hermes-index", "github", "skills.sh", "clawhub", "lobehub", "browse-sh", "well-known", "mcp-registry"
    canonical_uri: str = ""
    repo: str = ""
    source_path: str = ""
    version_or_revision: str = "latest"
    content_hash: str = ""
    trust_level: str = "community"
    security_verdict: str = "UNKNOWN"
    tags: List[str] = field(default_factory=list)
    task_categories: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=lambda: ["linux", "darwin", "win32"])
    compatible_clients: List[str] = field(default_factory=lambda: ["opencode", "claude-code", "hermes"])
    dependencies: List[DependencySpec] = field(default_factory=list)
    mcp_transport: Optional[MCPTransportSpec] = None
    install_targets: List[str] = field(default_factory=lambda: ["opencode", "claude-code", "hermes"])
    popularity_signals: Dict[str, Any] = field(default_factory=dict)
    outcome_stats: Dict[str, Any] = field(default_factory=dict)
    extra_metadata: Dict[str, Any] = field(default_factory=dict)
    cached_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExtensionBundle:
    """In-memory downloaded or local file bundle for an extension."""
    extension_id: str
    name: str
    extension_type: str
    source_provider: str
    trust_level: str
    files: Dict[str, str | bytes] = field(default_factory=dict)
    record: Optional[ExtensionRecord] = None
    content_hash: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CandidatePreview:
    """Detailed non-executing preview and comparison assessment of a candidate extension."""
    extension_id: str
    name: str
    extension_type: str
    source_provider: str
    trust_level: str
    description: str
    frontmatter: Dict[str, Any] = field(default_factory=dict)
    body_excerpt: str = ""
    full_body_chars: int = 0
    estimated_tokens: int = 0
    referenced_files: List[str] = field(default_factory=list)
    available_files: List[str] = field(default_factory=list)
    missing_references: List[str] = field(default_factory=list)
    scripts_detected: List[str] = field(default_factory=list)
    dependencies: List[DependencySpec] = field(default_factory=list)
    missing_dependencies: List[str] = field(default_factory=list)
    compatible_platforms: List[str] = field(default_factory=list)
    compatible_clients: List[str] = field(default_factory=list)
    platform_compatible: bool = True
    security: Optional[SecurityAssessment] = None
    relevance_score: float = 0.0
    quality_score: float = 0.0
    compatibility_score: float = 0.0
    security_score: float = 0.0
    outcome_score: float = 0.0
    popularity_bonus: float = 0.0
    total_score: float = 0.0
    score_breakdown: Dict[str, float] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)
    provenance_uri: str = ""
    content_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PreflightDecision:
    """Auditable mandatory preflight record for a task."""
    decision_id: str
    session_id: str
    task_query: str
    task_category: str
    state: str
    state_history: List[str] = field(default_factory=list)
    sources_searched: List[str] = field(default_factory=list)
    source_status: Dict[str, str] = field(default_factory=dict)
    candidate_ids: List[str] = field(default_factory=list)
    previews_inspected: List[CandidatePreview] = field(default_factory=list)
    selected_ids: List[str] = field(default_factory=list)
    no_match: bool = False
    selection_reason: str = ""
    rejection_reasons: Dict[str, str] = field(default_factory=dict)
    security_summary: Dict[str, str] = field(default_factory=dict)
    compatibility_checks: Dict[str, bool] = field(default_factory=dict)
    runtime_loaded: bool = False
    loaded_handles: List[str] = field(default_factory=list)
    elapsed_ms: float = 0.0
    created_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RuntimeSkillHandle:
    """Temporary just-in-time loaded skill payload held in session runtime memory."""
    handle_id: str
    session_id: str
    decision_id: str
    extension_id: str
    name: str
    source_provider: str
    trust_level: str
    content_hash: str
    provenance_uri: str
    skill_md_body: str
    frontmatter: Dict[str, Any] = field(default_factory=dict)
    loaded_references: Dict[str, str] = field(default_factory=dict)
    total_bytes: int = 0
    estimated_tokens: int = 0
    dedup_stub: bool = False
    loaded_at: str = field(default_factory=utc_now_iso)
    released_at: Optional[str] = None
    active: bool = True
    context_isolation_note: str = (
        "Unloading releases Python runtime references and session buffers so subsequent tasks do not inherit "
        "this skill. It does not zeroize OS process RAM or erase tokens already sent to an LLM's active "
        "conversation history; use subagent/session isolation for strict LLM context separation."
    )

    def to_dict(self, include_body: bool = True) -> Dict[str, Any]:
        data = asdict(self)
        if not include_body:
            data["skill_md_body"] = f"<{len(self.skill_md_body)} chars omitted>"
            data["loaded_references"] = {k: f"<{len(v)} chars>" for k, v in self.loaded_references.items()}
        return data


@dataclass
class InstallPlan:
    """Planned installation or configuration modification for a native client."""
    plan_id: str
    extension_id: str
    extension_name: str
    extension_type: str
    target_client: str                  # "opencode" | "claude-code" | "hermes"
    scope: str                          # "user" | "project"
    dry_run: bool = True
    requires_approval: bool = False
    approved: bool = False
    blocked: bool = False
    block_reason: str = ""
    security_assessment: Optional[SecurityAssessment] = None
    dependency_checks: List[Dict[str, Any]] = field(default_factory=list)
    missing_dependencies: List[str] = field(default_factory=list)
    planned_file_writes: List[Dict[str, Any]] = field(default_factory=list)
    planned_config_diff: str = ""
    backup_dir: str = ""
    unpreserved_fields: List[str] = field(default_factory=list)
    status: str = "planned"             # "planned" | "applied" | "rolled_back" | "blocked" | "failed"
    created_at: str = field(default_factory=utc_now_iso)
    applied_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TaskOutcome:
    """Recorded task outcome used for persistent suitability learning."""
    outcome_id: str
    decision_id: str
    session_id: str
    extension_id: str
    task_category: str
    success: bool
    tests_passed: bool = True
    regression_detected: bool = False
    human_override: Optional[str] = None
    latency_ms: float = 0.0
    notes: str = ""
    recorded_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
