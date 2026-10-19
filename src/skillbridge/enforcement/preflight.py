"""Mandatory preflight orchestrator and protected task execution wrapper."""

from __future__ import annotations

import inspect
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from skillbridge.cache.database import CatalogDatabase
from skillbridge.config import SkillBridgeConfig
from skillbridge.discovery.engine import DiscoveryEngine
from skillbridge.enforcement.state_machine import (
    PreflightEnforcementError,
    TaskLifecycleStateMachine,
)
from skillbridge.models import (
    CandidatePreview,
    ExtensionRecord,
    PreflightDecision,
    PreflightState,
    RuntimeSkillHandle,
    TaskOutcome,
)
from skillbridge.preview.inspector import CandidateInspector
from skillbridge.ranking.scorer import CandidateRanker, classify_task_query
from skillbridge.runtime.loader import SkillLoadError, SkillRuntimeLoader


class PreflightOrchestrator:
    """Enforces mandatory skill discovery, candidate preview, comparison, selection, loading, and cleanup."""

    def __init__(
        self,
        discovery: DiscoveryEngine,
        inspector: CandidateInspector,
        ranker: CandidateRanker,
        loader: SkillRuntimeLoader,
        config: Optional[SkillBridgeConfig] = None,
        db: Optional[CatalogDatabase] = None,
    ):
        self.discovery = discovery
        self.inspector = inspector
        self.ranker = ranker
        self.loader = loader
        self.config = config or discovery.config
        self.db = db or discovery.db

        self._lock = threading.RLock()
        self._state_machines: Dict[str, TaskLifecycleStateMachine] = {}
        self._decisions: Dict[str, PreflightDecision] = {}

    def get_state_machine(self, decision_id: str) -> Optional[TaskLifecycleStateMachine]:
        with self._lock:
            return self._state_machines.get(decision_id)

    def get_decision(self, decision_id: str) -> Optional[PreflightDecision]:
        with self._lock:
            return self._decisions.get(decision_id)

    def run_preflight(
        self,
        task_query: str,
        *,
        session_id: Optional[str] = None,
        source_filter: str = "all",
        preview_top_k: int = 5,
        auto_load: bool = True,
        approved: bool = False,
    ) -> PreflightDecision:
        """Run the mandatory SkillBridge preflight workflow for a user task."""
        start = time.perf_counter()
        sid = session_id or f"sess_{uuid.uuid4().hex[:10]}"
        decision_id = f"pf_{uuid.uuid4().hex[:12]}"
        sm = TaskLifecycleStateMachine(decision_id=decision_id, session_id=sid)

        with self._lock:
            self._state_machines[decision_id] = sm

        # Step 1: PREFLIGHT_STARTED
        sm.transition(PreflightState.PREFLIGHT_STARTED)
        task_category = classify_task_query(task_query)

        # Step 2: SEARCH_LOCAL_AND_APPROVED_CATALOGS
        sm.transition(PreflightState.SEARCH_LOCAL_AND_APPROVED_CATALOGS)
        candidates, source_status = self.discovery.search_skills(
            task_query,
            source_filter=source_filter,
            limit=max(15, preview_top_k * 3),
            session_id=sid,
        )
        sm.candidates_found_count = len(candidates)
        records_by_id: Dict[str, ExtensionRecord] = {c.extension_id: c for c in candidates}

        previews: List[CandidatePreview] = []
        if candidates:
            # Step 3: PREVIEW_TOP_CANDIDATES
            sm.transition(PreflightState.PREVIEW_TOP_CANDIDATES)
            for cand in candidates[:preview_top_k]:
                prev = self.inspector.preview_candidate(cand)
                if prev is not None:
                    previews.append(prev)
            sm.previews_count = len(previews)

            # Step 4: COMPARE_RELEVANCE_COMPATIBILITY_AND_RISK
            sm.transition(PreflightState.COMPARE_RELEVANCE_COMPATIBILITY_AND_RISK)
            ranked_previews, selected_ids, rejection_reasons, selection_reason = self.ranker.rank_and_select(
                task_query,
                previews,
                records_by_id=records_by_id,
                approved=approved,
            )
        else:
            ranked_previews = []
            selected_ids = []
            rejection_reasons = {}
            selection_reason = "NO_MATCH: No candidate skills found in local or remote catalogs."

        # Step 5: SELECT_BEST_MATCH_OR_EXPLICIT_NO_MATCH
        sm.selected_ids = selected_ids
        sm.no_match = len(selected_ids) == 0
        sm.transition(PreflightState.SELECT_BEST_MATCH_OR_EXPLICIT_NO_MATCH)

        # Step 6: LOAD_SELECTED_SKILL_IF_APPROPRIATE
        loaded_handles: List[str] = []
        runtime_loaded = False
        if selected_ids and auto_load:
            sm.transition(PreflightState.LOAD_SELECTED_SKILL_IF_APPROPRIATE)
            batch = self.loader.load_skills_parallel(
                selected_ids,
                session_id=sid,
                decision_id=decision_id,
                approved=approved,
            )
            for item in batch["loaded"]:
                loaded_handles.append(item["handle_id"])
                sm.loaded_ids.append(item["extension_id"])
            for failure in batch["failed"]:
                rejection_reasons[failure["extension_id"]] = f"Runtime load rejected: {failure['error']}"
            runtime_loaded = batch["loaded_count"] > 0
            if not runtime_loaded:
                # All selected candidates failed runtime load (e.g. requires approval); fall back to NO_MATCH
                sm.selected_ids = []
                sm.no_match = True
                selected_ids = []
                selection_reason = "NO_MATCH: Selected candidate(s) could not be loaded without explicit approval."

        sec_summary = {
            p.extension_id: (p.security.verdict if p.security else "UNKNOWN")
            for p in ranked_previews
        }
        compat_checks = {
            p.extension_id: p.platform_compatible and not bool(p.missing_dependencies)
            for p in ranked_previews
        }

        elapsed_ms = round((time.perf_counter() - start) * 1000.0, 2)
        decision = PreflightDecision(
            decision_id=decision_id,
            session_id=sid,
            task_query=task_query,
            task_category=task_category,
            state=sm.state.value,
            state_history=list(sm.history),
            sources_searched=list(source_status.keys()),
            source_status=source_status,
            candidate_ids=[c.extension_id for c in candidates],
            previews_inspected=ranked_previews,
            selected_ids=selected_ids,
            no_match=sm.no_match,
            selection_reason=selection_reason,
            rejection_reasons=rejection_reasons,
            security_summary=sec_summary,
            compatibility_checks=compat_checks,
            runtime_loaded=runtime_loaded,
            loaded_handles=loaded_handles,
            elapsed_ms=elapsed_ms,
        )

        with self._lock:
            self._decisions[decision_id] = decision

        self.db.record_preflight(decision)
        self.db.log_audit(
            "preflight_decision",
            session_id=sid,
            extension_id=",".join(selected_ids) if selected_ids else "NO_MATCH",
            verdict="MATCH" if selected_ids else "NO_MATCH",
            elapsed_ms=elapsed_ms,
            details={
                "decision_id": decision_id,
                "category": task_category,
                "candidates_count": len(candidates),
                "previews_count": len(ranked_previews),
                "selected_ids": selected_ids,
            },
        )
        return decision

    async def execute_protected_task(
        self,
        decision_id: Optional[str],
        task_fn: Callable[[List[RuntimeSkillHandle]], Any],
        *,
        verify_fn: Optional[Callable[[Any], bool]] = None,
    ) -> Tuple[Any, PreflightDecision]:
        """Protected execution gate: rejects execution if preflight has not completed, runs task,
        records outcome, and deterministically releases temporary runtime references in a finally block.
        """
        if not decision_id:
            raise PreflightEnforcementError(
                "Protected execution blocked: missing decision_id. Every task must call preflight() first."
            )
        sm = self.get_state_machine(decision_id)
        decision = self.get_decision(decision_id)
        if sm is None or decision is None:
            raise PreflightEnforcementError(
                f"Protected execution blocked: unknown or expired preflight decision_id '{decision_id}'."
            )

        start = time.perf_counter()

        try:
            # Deferred loading path: preflight may have run with auto_load=False. Load selected skills
            # just-in-time here through the bounded parallel worker pool, then assert the execution gate.
            if not sm.no_match and sm.selected_ids and not sm.loaded_ids:
                sm.transition(PreflightState.LOAD_SELECTED_SKILL_IF_APPROPRIATE)
                batch = self.loader.load_skills_parallel(
                    sm.selected_ids,
                    session_id=decision.session_id,
                    decision_id=decision_id,
                )
                for item in batch["loaded"]:
                    decision.loaded_handles.append(item["handle_id"])
                    sm.loaded_ids.append(item["extension_id"])
                if batch["loaded_count"]:
                    decision.runtime_loaded = True
                if not batch["loaded_count"]:
                    errors = "; ".join(f"{f['extension_id']}: {f['error']}" for f in batch["failed"])
                    raise PreflightEnforcementError(
                        f"Protected execution blocked: selected skill(s) {sm.selected_ids} failed to load: {errors}"
                    )

            sm.assert_can_execute()

            sm.transition(PreflightState.EXECUTE_TASK)
            active_handles = self.loader.get_active_handles(decision.session_id)

            res = task_fn(active_handles)
            if inspect.isawaitable(res):
                res = await res

            sm.transition(PreflightState.VERIFY_RESULT_AND_RECORD_OUTCOME)
            passed = verify_fn(res) if verify_fn else True
            elapsed_ms = round((time.perf_counter() - start) * 1000.0, 2)

            for ext_id in decision.selected_ids:
                self.db.record_outcome(
                    TaskOutcome(
                        outcome_id=f"out_{uuid.uuid4().hex[:12]}",
                        decision_id=decision_id,
                        session_id=decision.session_id,
                        extension_id=ext_id,
                        task_category=decision.task_category,
                        success=bool(passed),
                        tests_passed=bool(passed),
                        regression_detected=not bool(passed),
                        latency_ms=elapsed_ms,
                    )
                )
            return res, decision
        finally:
            # Always release temporary runtime references even on exception, timeout, or cancellation
            self.loader.unload_session(decision.session_id)
            if sm.state != PreflightState.RELEASE_TEMPORARY_RUNTIME_REFERENCES:
                sm.transition(PreflightState.RELEASE_TEMPORARY_RUNTIME_REFERENCES)
            decision.state = sm.state.value
            decision.state_history = list(sm.history)
            self.db.record_preflight(decision)
