"""State machine and enforcement gate for mandatory SkillBridge task preflight."""

from __future__ import annotations

from typing import Dict, List, Set

from skillbridge.models import PreflightState


class PreflightEnforcementError(RuntimeError):
    """Raised when substantive task execution or skill loading violates mandatory preflight rules."""


class PreflightTransitionError(PreflightEnforcementError):
    """Raised when an illegal state transition is attempted in the task lifecycle state machine."""


LEGAL_TRANSITIONS: Dict[PreflightState, Set[PreflightState]] = {
    PreflightState.CREATED: {
        PreflightState.PREFLIGHT_STARTED,
    },
    PreflightState.PREFLIGHT_STARTED: {
        PreflightState.SEARCH_LOCAL_AND_APPROVED_CATALOGS,
        PreflightState.RELEASE_TEMPORARY_RUNTIME_REFERENCES,
    },
    PreflightState.SEARCH_LOCAL_AND_APPROVED_CATALOGS: {
        PreflightState.PREVIEW_TOP_CANDIDATES,
        PreflightState.SELECT_BEST_MATCH_OR_EXPLICIT_NO_MATCH,  # Allowed only when 0 candidates exist across all catalogs
        PreflightState.RELEASE_TEMPORARY_RUNTIME_REFERENCES,
    },
    PreflightState.PREVIEW_TOP_CANDIDATES: {
        PreflightState.COMPARE_RELEVANCE_COMPATIBILITY_AND_RISK,
        PreflightState.RELEASE_TEMPORARY_RUNTIME_REFERENCES,
    },
    PreflightState.COMPARE_RELEVANCE_COMPATIBILITY_AND_RISK: {
        PreflightState.SELECT_BEST_MATCH_OR_EXPLICIT_NO_MATCH,
        PreflightState.RELEASE_TEMPORARY_RUNTIME_REFERENCES,
    },
    PreflightState.SELECT_BEST_MATCH_OR_EXPLICIT_NO_MATCH: {
        PreflightState.LOAD_SELECTED_SKILL_IF_APPROPRIATE,
        PreflightState.EXECUTE_TASK,  # Allowed directly when explicit NO_MATCH was selected
        PreflightState.RELEASE_TEMPORARY_RUNTIME_REFERENCES,
    },
    PreflightState.LOAD_SELECTED_SKILL_IF_APPROPRIATE: {
        PreflightState.EXECUTE_TASK,
        PreflightState.RELEASE_TEMPORARY_RUNTIME_REFERENCES,
    },
    PreflightState.EXECUTE_TASK: {
        PreflightState.VERIFY_RESULT_AND_RECORD_OUTCOME,
        PreflightState.RELEASE_TEMPORARY_RUNTIME_REFERENCES,
    },
    PreflightState.VERIFY_RESULT_AND_RECORD_OUTCOME: {
        PreflightState.RELEASE_TEMPORARY_RUNTIME_REFERENCES,
    },
    PreflightState.RELEASE_TEMPORARY_RUNTIME_REFERENCES: set(),
}


class TaskLifecycleStateMachine:
    """Enforces the mandatory preflight and cleanup state machine for a single task execution."""

    def __init__(self, decision_id: str, session_id: str):
        self.decision_id = decision_id
        self.session_id = session_id
        self.state: PreflightState = PreflightState.CREATED
        self.history: List[str] = [PreflightState.CREATED.value]
        self.candidates_found_count: int = 0
        self.previews_count: int = 0
        self.selected_ids: List[str] = []
        self.no_match: bool = False
        self.loaded_ids: List[str] = []

    def transition(self, next_state: PreflightState) -> None:
        allowed = LEGAL_TRANSITIONS.get(self.state, set())
        if next_state not in allowed:
            raise PreflightTransitionError(
                f"Illegal state transition for decision '{self.decision_id}': "
                f"cannot move from {self.state.value} to {next_state.value}. "
                f"Allowed transitions: {[s.value for s in allowed]}"
            )
        if (
            self.state == PreflightState.SEARCH_LOCAL_AND_APPROVED_CATALOGS
            and next_state == PreflightState.SELECT_BEST_MATCH_OR_EXPLICIT_NO_MATCH
            and self.candidates_found_count > 0
        ):
            raise PreflightEnforcementError(
                f"Cannot skip PREVIEW_TOP_CANDIDATES when {self.candidates_found_count} candidate(s) were found."
            )
        if (
            self.state == PreflightState.SELECT_BEST_MATCH_OR_EXPLICIT_NO_MATCH
            and next_state == PreflightState.EXECUTE_TASK
            and not self.no_match
            and self.selected_ids
            and not self.loaded_ids
        ):
            raise PreflightEnforcementError(
                "Selected skill(s) must pass through LOAD_SELECTED_SKILL_IF_APPROPRIATE before EXECUTE_TASK."
            )
        self.state = next_state
        self.history.append(next_state.value)

    def assert_can_execute(self) -> None:
        """Verify that mandatory discovery, preview, comparison, and selection have completed."""
        if self.state not in (
            PreflightState.SELECT_BEST_MATCH_OR_EXPLICIT_NO_MATCH,
            PreflightState.LOAD_SELECTED_SKILL_IF_APPROPRIATE,
            PreflightState.EXECUTE_TASK,
        ):
            raise PreflightEnforcementError(
                f"Protected execution rejected: task '{self.decision_id}' is in state '{self.state.value}' "
                "and has not completed mandatory preflight discovery and selection."
            )
        if not self.no_match and self.selected_ids and not self.loaded_ids and self.state != PreflightState.EXECUTE_TASK:
            raise PreflightEnforcementError(
                f"Protected execution rejected: selected skill(s) {self.selected_ids} have not been loaded."
            )
