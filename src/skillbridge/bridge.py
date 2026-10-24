"""High-level programmatic Python API (SkillBridge v2) combining discovery, Tier 0-3 verification, bundle import, memory eviction, parallel orchestration, and native installers."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
import uuid

from skillbridge import __version__
from skillbridge.cache.database import CatalogDatabase
from skillbridge.config import SkillBridgeConfig
from skillbridge.discovery.engine import DiscoveryEngine
from skillbridge.enforcement.preflight import PreflightOrchestrator
from skillbridge.installers.planner import InstallationManager
from skillbridge.models import (
    CandidatePreview,
    ExtensionRecord,
    InstallPlan,
    PreflightDecision,
    RuntimeSkillHandle,
    SecurityAssessment,
    SecurityVerdict,
    TaskOutcome,
)
from skillbridge.orchestration.scheduler import (
    OrchestratedTaskSpec,
    ParallelOrchestrator,
    detect_multi_skill_conflicts,
)
from skillbridge.preview.inspector import CandidateInspector
from skillbridge.ranking.scorer import CandidateRanker
from skillbridge.runtime.loader import ActiveBundleEntry, SkillRuntimeLoader
from skillbridge.runtime.memory import MemoryProvider
from skillbridge.runtime.scripts import ScriptExecutionResult
from skillbridge.security.scanner import determine_verdict, scan_directory, scan_mcp_transport
from skillbridge.settings import RuntimeSettings, SettingsManager
from skillbridge.verification.adapters import VerificationCoordinator
from skillbridge.verification.models import (
    SKILLFORTIFY_PINNED_COMMIT,
    SKILLFORTIFY_PINNED_VERSION,
    SKILLEVALUATOR_PINNED_COMMIT,
    SKILLEVALUATOR_PINNED_VERSION,
    SKILLSPECTOR_PINNED_COMMIT,
    SKILLSPECTOR_PINNED_VERSION,
    SKIL_PINNED_COMMIT,
    SKIL_PINNED_VERSION,
)


class SkillBridge:
    """Unified programmatic intelligence layer for skill, MCP-server, and agent extension orchestration (v2.0.2)."""

    def __init__(
        self,
        config: Optional[SkillBridgeConfig] = None,
        db: Optional[CatalogDatabase] = None,
        project_root: Optional[Path] = None,
        user_home: Optional[Path] = None,
        *,
        settings: Optional[RuntimeSettings] = None,
        memory_provider: Optional[MemoryProvider] = None,
        verification_coordinator: Optional[VerificationCoordinator] = None,
    ):
        self.config = config or SkillBridgeConfig()
        if project_root:
            self.config.project_root = Path(project_root)
        self.config.ensure_dirs()
        self.db = db or CatalogDatabase(self.config.db_path, enable_telemetry=self.config.enable_telemetry)

        self.settings_manager = SettingsManager(
            self.config.home_dir / "settings.json",
            initial=settings,
        )
        self.discovery = DiscoveryEngine(self.config, self.db)
        self.inspector = CandidateInspector(self.discovery, self.config, self.db)
        self.ranker = CandidateRanker(self.config.loader_limits)
        self.verification_coordinator = verification_coordinator or VerificationCoordinator()
        self.loader = SkillRuntimeLoader(
            self.discovery,
            self.config,
            self.db,
            settings=self.settings_manager.current,
            memory_provider=memory_provider,
            verification_coordinator=self.verification_coordinator,
        )
        self.settings_manager.register_callback(self.loader.on_settings_updated)

        self.orchestrator = PreflightOrchestrator(
            self.discovery, self.inspector, self.ranker, self.loader, self.config, self.db
        )
        self.parallel_scheduler = ParallelOrchestrator(
            max_parallel_scans=self.settings_manager.current.max_parallel_scans,
            max_parallel_mcp_calls=self.settings_manager.current.max_parallel_mcp_calls,
            max_parallel_skill_workers=self.settings_manager.current.max_parallel_skill_workers,
            per_provider_concurrency=self.settings_manager.current.per_provider_concurrency,
            per_mcp_server_concurrency=self.settings_manager.current.per_mcp_server_concurrency,
        )
        self.installer = InstallationManager(
            self.discovery,
            self.config,
            self.db,
            project_root=self.config.project_root,
            user_home=user_home,
        )
        # Active enabled MCP servers in the broker: server_id -> metadata dict
        self._enabled_mcp_servers: Dict[str, Dict[str, Any]] = {}

    @property
    def settings(self) -> RuntimeSettings:
        return self.settings_manager.current

    def update_settings(self, **updates: Any) -> RuntimeSettings:
        updated = self.settings_manager.update(**updates)
        self.parallel_scheduler.max_parallel_scans = updated.max_parallel_scans
        self.parallel_scheduler.max_parallel_mcp_calls = updated.max_parallel_mcp_calls
        return updated

    async def preflight(
        self,
        task: str,
        *,
        session_id: Optional[str] = None,
        source_filter: str = "all",
        preview_top_k: int = 5,
        auto_load: bool = True,
        approved: bool = False,
    ) -> PreflightDecision:
        """Execute mandatory task preflight: search -> preview -> compare -> security scan -> select -> load."""
        return self.orchestrator.run_preflight(
            task,
            session_id=session_id,
            source_filter=source_filter,
            preview_top_k=preview_top_k,
            auto_load=auto_load,
            approved=approved,
        )

    async def search_skills(
        self,
        query: str,
        *,
        source_filter: str = "all",
        limit: int = 20,
        session_id: str = "default",
    ) -> List[ExtensionRecord]:
        records, _ = self.discovery.search_skills(
            query, source_filter=source_filter, limit=limit, session_id=session_id
        )
        return records

    async def preview_skill(
        self, skill_id: str, *, target_client: Optional[str] = None
    ) -> Optional[CandidatePreview]:
        prev = self.inspector.preview_candidate(skill_id, target_client=target_client)
        if prev:
            rec = self.discovery.resolve_extension(skill_id)
            self.ranker.score_preview(skill_id, prev, rec)
        return prev

    async def preview_extension(
        self, extension_id: str, *, target_client: Optional[str] = None
    ) -> Optional[CandidatePreview]:
        return await self.preview_skill(extension_id, target_client=target_client)

    async def compare_skills(
        self,
        skill_ids: List[str],
        *,
        query: str = "",
        target_client: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Preview and compare multiple candidate skills side-by-side without executing code."""
        previews: List[Dict[str, Any]] = []
        skill_caps: List[Dict[str, Any]] = []
        for sid in skill_ids:
            prev = await self.preview_skill(sid, target_client=target_client)
            if prev:
                rec = self.discovery.resolve_extension(sid)
                self.ranker.score_preview(query or sid, prev, rec)
                previews.append(prev.to_dict())
                skill_caps.append(
                    {
                        "skill_id": prev.extension_id,
                        "capabilities": (rec.capabilities if rec else []) + prev.scripts_detected,
                    }
                )
        previews.sort(key=lambda x: float(x.get("total_score", 0.0)), reverse=True)
        conflict_analysis = detect_multi_skill_conflicts(skill_caps)
        return {
            "compared_count": len(previews),
            "candidates": previews,
            "recommended_id": previews[0]["extension_id"] if previews else None,
            "conflict_analysis": conflict_analysis,
        }

    async def import_skill(
        self,
        skill_id: str,
        *,
        session_id: str = "default",
        pin: bool = False,
        approved: bool = False,
    ) -> Dict[str, Any]:
        """Import a whole-directory skill bundle through the 13-state Tier 0–3 verification pipeline."""
        entry: ActiveBundleEntry = self.loader.import_skill_bundle(
            skill_id,
            session_id=session_id,
            pin=pin,
            approved=approved,
        )
        return {
            "skill_id": entry.skill_id,
            "session_id": entry.session_id,
            "bundle_digest": entry.bundle_digest,
            "staged_dir": entry.staged_dir,
            "import_state": entry.import_state.value,
            "state_history": entry.state_history,
            "pinned": entry.pinned,
            "manifest": entry.manifest.to_dict(),
            "verification": entry.verification.to_dict(),
            "handle": entry.handle.to_dict(include_body=False),
        }

    async def load_skill(
        self,
        skill_id: str,
        *,
        session_id: str = "default",
        decision_id: str = "manual",
        include_references: bool = True,
        allow_dedup_stub: bool = False,
        approved: bool = False,
    ) -> RuntimeSkillHandle:
        return self.loader.load_skill(
            skill_id,
            session_id=session_id,
            decision_id=decision_id,
            include_references=include_references,
            allow_dedup_stub=allow_dedup_stub,
            approved=approved,
        )

    async def load_skills_parallel(
        self,
        skill_ids: List[str],
        *,
        session_id: str = "default",
        decision_id: str = "manual",
        include_references: bool = True,
        allow_dedup_stub: bool = False,
        approved: bool = False,
        max_workers: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Load multiple skills concurrently through a bounded worker pool (per-skill isolation preserved)."""
        return self.loader.load_skills_parallel(
            skill_ids,
            session_id=session_id,
            decision_id=decision_id,
            include_references=include_references,
            allow_dedup_stub=allow_dedup_stub,
            approved=approved,
            max_workers=max_workers,
        )

    async def import_local_directory(
        self,
        directory: str,
        *,
        session_id: str = "default",
        pin: bool = False,
        approved: bool = False,
    ) -> Dict[str, Any]:
        """Stage and import an entire local skill directory (every file, not just SKILL.md) through Tier 0-3.

        The directory must contain a SKILL.md at its root. All nested files (scripts, references, templates,
        assets, ...) are staged as a whole-directory bundle, verified, and made available for loading.
        """
        path = Path(directory).expanduser()
        if not path.exists() or not path.is_dir():
            raise ValueError(f"Import path '{directory}' is not an existing directory.")
        if not (path / "SKILL.md").exists():
            raise ValueError(f"Directory '{path}' does not contain a SKILL.md at its root.")
        rec = self.discovery.local_provider.inspect(str(path.resolve()))
        if rec is None:
            raise ValueError(f"Directory '{path}' could not be normalized into a skill record (invalid SKILL.md frontmatter?).")
        rec.source_path = str(path.resolve())
        self.db.upsert_extension(rec)
        result = await self.import_skill(rec.extension_id, session_id=session_id, pin=pin, approved=approved)
        result["imported_path"] = str(path.resolve())
        return result

    async def get_skill_status(self, skill_id: Optional[str] = None) -> Dict[str, Any]:
        """Return runtime status for a specific skill (or all active/recalled skills)."""
        if skill_id:
            found = self.loader.find_active_handle(skill_id)
            if found is not None:
                session_id, handle = found
                return {
                    "skill_id": handle.extension_id,
                    "session_id": session_id,
                    "active": True,
                    "state": "LOADED_IN_ACTIVE_SESSION",
                    "handle_id": handle.handle_id,
                    "content_hash": handle.content_hash,
                    "bundle_digest": handle.content_hash,
                    "total_bytes": handle.total_bytes,
                    "estimated_tokens": handle.estimated_tokens,
                    "references_loaded": sorted(handle.loaded_references),
                    "source_provider": handle.source_provider,
                    "trust_level": handle.trust_level,
                    "loaded_at": handle.loaded_at,
                    "dedup_stub": handle.dedup_stub,
                }
            if skill_id in self.loader._active_bundles:
                b = self.loader._active_bundles[skill_id]
                return {
                    "skill_id": b.skill_id,
                    "active": True,
                    "import_state": b.import_state.value,
                    "state_history": b.state_history,
                    "bundle_digest": b.bundle_digest,
                    "staged_dir": b.staged_dir,
                    "in_use": b.in_use,
                    "pinned": b.pinned,
                    "access_count": b.access_count,
                    "assurance_state": b.verification.assurance_state.value,
                    "quality_score": b.verification.quality_score,
                }
            recalled = self.loader.recall_skill_metadata(skill_id)
            if recalled:
                return {"active": False, **recalled}
            return {"skill_id": skill_id, "active": False, "final_state": "NOT_FOUND"}

        return self.loader.get_all_active_sessions_summary()

    async def invoke_skill(self, skill_id: str, *, session_id: str = "default") -> Dict[str, Any]:
        """Invoke an active bundle or session-loaded skill, updating its LRU timestamp."""
        if skill_id in self.loader._active_bundles:
            handle = self.loader.invoke_loaded_bundle(skill_id)
            return handle.to_dict(include_body=True)
        handles = self.loader.get_active_handles(session_id)
        for h in handles:
            if h.extension_id == skill_id or h.name == skill_id:
                self.loader._handle_last_access[(session_id, h.extension_id)] = (
                    __import__("time").monotonic()
                )
                return h.to_dict(include_body=True)
        raise RuntimeError(f"Skill '{skill_id}' is not currently loaded in session '{session_id}'.")

    async def run_skill_script(
        self,
        skill_id: str,
        relative_path: str,
        arguments: Optional[List[str]] = None,
        *,
        approved: bool = False,
    ) -> ScriptExecutionResult:
        """Execute a permitted script inside an imported skill bundle."""
        return self.loader.execute_bundle_script(
            skill_id,
            relative_path,
            arguments=arguments,
            explicit_approval=approved,
        )

    async def unload_skill(self, skill_id: str, *, session_id: str = "default") -> Dict[str, Any]:
        """Unload a skill from exactly one session; release staging only when no session holds it.

        The previous implementation released the global bundle before checking ``session_id``,
        allowing one MCP client to terminate another session's active skill.
        """
        result = self.loader.unload_skill(skill_id, session_id=session_id)
        if not result.get("unloaded"):
            return result
        resolved = self.loader.resolve_active_bundle_id(skill_id)
        if resolved and not self.loader.session_holds_skill(resolved):
            bundle_result = self.loader.unload_bundle(resolved, reason="explicit_unload")
            result["bundle_released"] = True
            result["staging_removed"] = True
            if isinstance(bundle_result, dict):
                result.update({k: v for k, v in bundle_result.items() if k != "unloaded"})
                result.setdefault("released_bundle", bundle_result)
        return result

    async def unload_session(self, session_id: str = "default") -> Dict[str, Any]:
        result = self.loader.unload_session(session_id)
        # Session teardown must not leave imported bundles/staging alive when no other
        # session (or handle) references them.
        for extension_id in list(self.loader._active_bundles.keys()):
            if not self.loader.session_holds_skill(extension_id):
                self.loader.unload_bundle(extension_id, reason=f"session_unload:{session_id}")
        return result

    async def search_mcp(
        self, query: str, *, limit: int = 20, session_id: str = "default"
    ) -> List[ExtensionRecord]:
        records, _ = self.discovery.search_mcp(query, limit=limit, session_id=session_id)
        return records

    async def verify_mcp_server(self, server_id: str) -> Dict[str, Any]:
        """Inspect and verify an MCP server's transport, launch command, IOCs, and least-privilege posture."""
        ext_id = server_id if server_id.startswith("mcp") else f"mcp/{server_id}"
        rec = self.discovery.resolve_extension(ext_id) or self.discovery.resolve_extension(server_id)
        if not rec or not rec.mcp_transport:
            raise ValueError(f"MCP server '{server_id}' not found in catalog.")
        findings = scan_mcp_transport(rec.extension_id, rec.mcp_transport)
        assessment = SecurityAssessment(
            extension_id=rec.extension_id,
            name=rec.name,
            source=rec.source_provider,
            trust_level=rec.trust_level,
            verdict=determine_verdict(findings),
            findings=findings,
        )
        self.installer.policy_engine.evaluate(assessment, approved=False, alters_config_or_runs_code=True)
        return {
            "server_id": rec.extension_id,
            "name": rec.name,
            "transport_type": rec.mcp_transport.transport_type,
            "command": rec.mcp_transport.command,
            "args": rec.mcp_transport.args,
            "url": rec.mcp_transport.url,
            "verdict": assessment.verdict,
            "allowed_without_approval": assessment.allowed,
            "requires_approval": assessment.verdict != SecurityVerdict.DANGEROUS.value,
            "findings": [f.to_dict() for f in assessment.findings],
            "policy_reason": assessment.policy_reason,
        }

    async def enable_mcp_server(self, server_id: str, *, approved: bool = False) -> Dict[str, Any]:
        """Verify and enable an MCP server in the SkillBridge MCP broker."""
        ver = await self.verify_mcp_server(server_id)
        if ver["verdict"] == SecurityVerdict.DANGEROUS.value:
            raise PermissionError(f"Cannot enable DANGEROUS MCP server '{server_id}': {ver['policy_reason']}")
        if not approved and not ver["allowed_without_approval"]:
            raise PermissionError(
                f"Enabling MCP server '{server_id}' requires explicit approval (`approved=True`)."
            )
        sid = ver["server_id"]
        self._enabled_mcp_servers[sid] = {
            **ver,
            "enabled": True,
            "enabled_at": datetime.now(timezone.utc).isoformat(),
        }
        self.db.log_audit("enable_mcp_server", extension_id=sid, verdict=ver["verdict"])
        return self._enabled_mcp_servers[sid]

    async def disable_mcp_server(self, server_id: str) -> Dict[str, Any]:
        ext_id = server_id if server_id in self._enabled_mcp_servers else f"mcp/{server_id}"
        removed = self._enabled_mcp_servers.pop(ext_id, None)
        self.db.log_audit("disable_mcp_server", extension_id=ext_id, verdict="disabled")
        return {
            "server_id": ext_id,
            "disabled": removed is not None,
            "remaining_enabled_servers": list(self._enabled_mcp_servers.keys()),
        }

    async def call_mcp_tool(
        self,
        server_id: str,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Validate server identity, activation status, and arguments before dispatching an MCP tool call."""
        ext_id = server_id if server_id in self._enabled_mcp_servers else f"mcp/{server_id}"
        if ext_id not in self._enabled_mcp_servers:
            raise PermissionError(
                f"MCP server '{server_id}' is not enabled in the broker. Verify and enable it before invoking tools."
            )
        if not tool_name or not isinstance(tool_name, str) or any(c in tool_name for c in (";", "|", "&", "`", "$")):
            raise ValueError(f"Invalid MCP tool name: {tool_name!r}")
        args = dict(arguments or {})

        spec = OrchestratedTaskSpec(
            task_id=f"mcp_{uuid.uuid4().hex[:8]}",
            kind="mcp_call",
            target_id=ext_id,
            callable_fn=lambda: {
                "server_id": ext_id,
                "tool_name": tool_name,
                "arguments": args,
                "status": "dispatched",
                "transport": self._enabled_mcp_servers[ext_id]["transport_type"],
            },
            idempotent=True,
            timeout_seconds=10.0,
        )
        res_map = await self.parallel_scheduler.execute_dag_async([spec])
        out = res_map[spec.task_id]
        if out.status != "completed":
            raise RuntimeError(out.error or f"MCP tool call failed with status={out.status}")
        return out.result

    async def get_memory_status(self) -> Dict[str, Any]:
        snap = self.loader.get_memory_snapshot(active_mcp_processes=len(self._enabled_mcp_servers))
        return {
            "snapshot": snap.to_dict(),
            "settings": {
                "active_skill_limit": self.settings.active_skill_limit,
                "memory_threshold_mib": self.settings.memory_threshold_mib,
                "memory_target_mib": self.settings.memory_target_mib,
                "eviction_batch_default": self.settings.eviction_batch_default,
                "eviction_batch_min": self.settings.eviction_batch_min,
                "eviction_batch_max": self.settings.eviction_batch_max,
            },
            "eviction_history": list(self.loader._eviction_events),
        }

    async def get_audit_report(self, limit: int = 25) -> Dict[str, Any]:
        return {
            "audit_logs": self.db.get_recent_audit_logs(limit=limit),
            "verification_engines": self.verification_coordinator.check_all_engines(),
            "orchestration_stats": self.parallel_scheduler.get_stats(),
            "memory": await self.get_memory_status(),
        }

    async def doctor(self) -> Dict[str, Any]:
        """Run comprehensive diagnostic checks across OS, Python, SQLite, verification engines, and client configs."""
        ver = await self.verify_target()
        engines = self.verification_coordinator.check_all_engines()
        mem = await self.get_memory_status()
        return {
            "status": "healthy",
            "version": __version__,
            "environment": ver["environment"],
            "database": ver["database"],
            "verification_engines": engines,
            "memory_status": mem,
            "settings": self.settings.to_dict(),
            "client_Readiness": {
                "opencode": self.installer.get_adapter("opencode").detect(),
                "claude-code": self.installer.get_adapter("claude-code").detect(),
            },
        }

    def generate_sbom(self, output_path: Optional[Path] = None) -> Dict[str, Any]:
        """Generate a CycloneDX 1.6 Software Bill of Materials (SBOM) for SkillBridge v2 and pinned contracts."""
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "component": {
                    "type": "application",
                    "name": "skillbridge",
                    "version": __version__,
                    "licenses": [{"license": {"id": "MIT"}}],
                },
            },
            "components": [
                {
                    "type": "library",
                    "name": "PyYAML",
                    "version": "6.0",
                    "licenses": [{"license": {"id": "MIT"}}],
                },
                {
                    "type": "application",
                    "name": "NVIDIA/SkillSpector (Adapter & Apache-2.0 Tier 1 Contract)",
                    "version": SKILLSPECTOR_PINNED_VERSION,
                    "externalReferences": [
                        {
                            "type": "vcs",
                            "url": "https://github.com/NVIDIA/SkillSpector",
                            "comment": f"Pinned commit {SKILLSPECTOR_PINNED_COMMIT}",
                        }
                    ],
                    "licenses": [{"license": {"id": "Apache-2.0"}}],
                },
                {
                    "type": "application",
                    "name": "domehahn/skil (Adapter & Apache-2.0 Tier 2 Assurance Closure Contract)",
                    "version": SKIL_PINNED_VERSION,
                    "externalReferences": [
                        {
                            "type": "vcs",
                            "url": "https://github.com/domehahn/skil",
                            "comment": f"Pinned commit {SKIL_PINNED_COMMIT}",
                        }
                    ],
                    "licenses": [{"license": {"id": "Apache-2.0"}}],
                },
                {
                    "type": "application",
                    "name": "NVIDIA/SkillEvaluator (Adapter & Apache-2.0 Tier 3 Evaluator Contract)",
                    "version": SKILLEVALUATOR_PINNED_VERSION,
                    "externalReferences": [
                        {
                            "type": "vcs",
                            "url": "https://github.com/NVIDIA/SkillEvaluator",
                            "comment": f"Pinned commit {SKILLEVALUATOR_PINNED_COMMIT}",
                        }
                    ],
                    "licenses": [{"license": {"id": "Apache-2.0"}}],
                },
                {
                    "type": "application",
                    "name": "qualixar/skillfortify (Optional External CLI Subprocess Contract Only — Not Distributed)",
                    "version": SKILLFORTIFY_PINNED_VERSION,
                    "scope": "optional",
                    "externalReferences": [
                        {
                            "type": "vcs",
                            "url": "https://github.com/qualixar/skillfortify",
                            "comment": f"Pinned commit {SKILLFORTIFY_PINNED_COMMIT}; excluded from bundle due to Elastic-2.0",
                        }
                    ],
                    "licenses": [{"license": {"name": "Elastic-2.0"}}],
                },
            ],
        }
        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
        return sbom

    async def plan_install(
        self,
        extension_id: str,
        target: str,
        *,
        scope: str = "project",
        dry_run: bool = True,
        approved: bool = False,
        extension_type_override: Optional[str] = None,
        lazy_disable_globally: bool = False,
    ) -> InstallPlan:
        return self.installer.plan_install(
            extension_id,
            target,
            scope=scope,
            dry_run=dry_run,
            approved=approved,
            extension_type_override=extension_type_override,
            lazy_disable_globally=lazy_disable_globally,
        )

    async def apply_install(self, plan_id: str | InstallPlan, *, approved: bool = False) -> Dict[str, Any]:
        return self.installer.apply_install(plan_id, approved=approved)

    async def rollback_install(self, plan_id: str) -> Dict[str, Any]:
        return self.installer.rollback(plan_id)

    async def verify_target(self, target: Optional[str] = None) -> Dict[str, Any]:
        """Verify environment, database state, providers, cache stats, and detected native clients."""
        seed_counts = self.discovery.ensure_catalog_seeded()
        env = self.config.detect_environment()
        stats = self.db.get_stats()
        runtime_state = self.loader.get_all_active_sessions_summary()

        if target:
            adapter = self.installer.get_adapter(target)
            return {
                "target": target,
                "client_detection": adapter.detect(),
                "database": {"path": str(self.config.db_path), **seed_counts},
                "cache_stats": stats,
                "runtime": runtime_state,
            }

        return {
            "status": "ready",
            "version": __version__,
            "environment": env,
            "database": {"path": str(self.config.db_path), **seed_counts},
            "providers": [p.PROVIDER_ID for p in self.discovery.all_providers],
            "verification_engines": self.verification_coordinator.check_all_engines(),
            "cache_stats": stats,
            "runtime": runtime_state,
            "quarantined_count": len(self.installer.quarantine.list_quarantined()),
        }

    async def record_outcome(self, result: TaskOutcome | Dict[str, Any]) -> bool:
        if isinstance(result, dict):
            outcome = TaskOutcome(
                outcome_id=str(result.get("outcome_id") or f"out_{uuid.uuid4().hex[:12]}"),
                decision_id=str(result.get("decision_id") or "manual"),
                session_id=str(result.get("session_id") or "default"),
                extension_id=str(result["extension_id"]),
                task_category=str(result.get("task_category") or "general_software"),
                success=bool(result.get("success", True)),
                tests_passed=bool(result.get("tests_passed", True)),
                regression_detected=bool(result.get("regression_detected", False)),
                human_override=result.get("human_override"),
                latency_ms=float(result.get("latency_ms", 0.0)),
                notes=str(result.get("notes") or ""),
            )
        else:
            outcome = result
        return self.db.record_outcome(outcome)

    async def execute_protected_task(
        self,
        decision_id: Optional[str],
        task_fn: Callable[[List[RuntimeSkillHandle]], Any],
        *,
        verify_fn: Optional[Callable[[Any], bool]] = None,
    ) -> Tuple[Any, PreflightDecision]:
        return await self.orchestrator.execute_protected_task(decision_id, task_fn, verify_fn=verify_fn)

    def scan_path(
        self, path: Path, *, source: str = "community", trust_level: str = "community"
    ) -> SecurityAssessment:
        assessment = scan_directory(path, source=source, trust_level=trust_level)
        self.installer.policy_engine.evaluate(assessment)
        return assessment
