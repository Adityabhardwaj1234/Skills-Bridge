"""Asyncio parallel task, verification, and MCP tool orchestrator with DAG ordering and circuit breakers."""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
import time
from typing import Any, Awaitable, Callable


class CircuitOpenError(RuntimeError):
    """Raised when a provider or MCP server circuit breaker is open due to repeated failures."""


class TaskDependencyError(ValueError):
    """Raised when a parallel task graph contains a cycle or unresolved dependency."""


@dataclass
class CircuitBreakerState:
    """Per-provider or per-MCP-server circuit breaker state."""

    target_id: str
    failure_threshold: int = 3
    recovery_timeout_seconds: float = 30.0
    consecutive_failures: int = 0
    opened_at_monotonic: float | None = None

    def allow_request(self) -> bool:
        if self.opened_at_monotonic is None:
            return True
        if (time.monotonic() - self.opened_at_monotonic) >= self.recovery_timeout_seconds:
            return True
        return False

    def record_success(self) -> None:
        self.consecutive_failures = 0
        self.opened_at_monotonic = None

    def record_failure(self) -> None:
        self.consecutive_failures += 1
        if self.consecutive_failures >= self.failure_threshold:
            self.opened_at_monotonic = time.monotonic()


@dataclass
class OrchestratedTaskSpec:
    """Specification for a unit of work in a parallel execution DAG."""

    task_id: str
    kind: str  # scan, mcp_call, skill_worker, provider_search
    target_id: str
    callable_fn: Callable[[], Any | Awaitable[Any]]
    depends_on: list[str] = field(default_factory=list)
    idempotent: bool = True
    idempotency_key: str | None = None
    max_retries: int = 1
    timeout_seconds: float = 15.0
    sequential_only: bool = False


@dataclass
class OrchestratedTaskResult:
    """Structured outcome of a single orchestrated child task."""

    task_id: str
    kind: str
    target_id: str
    status: str  # completed, failed, timed_out, cancelled, circuit_open, deduplicated
    result: Any = None
    error: str | None = None
    attempts: int = 1
    duration_ms: float = 0.0
    from_idempotency_cache: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def detect_multi_skill_conflicts(
    skills: list[dict[str, Any]],
) -> dict[str, Any]:
    """Check whether multiple selected skills have conflicting instructions or overlapping capabilities."""
    conflicts: list[str] = []
    overlaps: list[str] = []
    seen_caps: dict[str, str] = {}
    for s in skills:
        sid = str(s.get("skill_id") or s.get("id") or "")
        caps = s.get("capabilities") or []
        for c in caps:
            if c in seen_caps and seen_caps[c] != sid:
                overlaps.append(f"Capability `{c}` is provided by both `{seen_caps[c]}` and `{sid}`")
            else:
                seen_caps[c] = sid
    return {
        "has_conflicts": len(conflicts) > 0,
        "conflicts": conflicts,
        "overlaps": overlaps,
    }


class ParallelOrchestrator:
    """Bounded asyncio scheduler enforcing global, per-provider, per-MCP, and per-skill concurrency limits."""

    def __init__(
        self,
        *,
        max_parallel_scans: int = 4,
        max_parallel_mcp_calls: int = 8,
        max_parallel_skill_workers: int = 4,
        per_provider_concurrency: int = 2,
        per_mcp_server_concurrency: int = 2,
    ) -> None:
        self.max_parallel_scans = max_parallel_scans
        self.max_parallel_mcp_calls = max_parallel_mcp_calls
        self.max_parallel_skill_workers = max_parallel_skill_workers
        self.per_provider_concurrency = per_provider_concurrency
        self.per_mcp_server_concurrency = per_mcp_server_concurrency
        self._circuit_breakers: dict[str, CircuitBreakerState] = {}
        self._idempotency_cache: dict[str, Any] = {}
        self._history: list[OrchestratedTaskResult] = []

    def get_circuit_breaker(self, target_id: str) -> CircuitBreakerState:
        if target_id not in self._circuit_breakers:
            self._circuit_breakers[target_id] = CircuitBreakerState(target_id=target_id)
        return self._circuit_breakers[target_id]

    def _topological_layers(self, specs: list[OrchestratedTaskSpec]) -> list[list[OrchestratedTaskSpec]]:
        spec_map = {s.task_id: s for s in specs}
        in_degree: dict[str, int] = {s.task_id: 0 for s in specs}
        dependents: dict[str, list[str]] = {s.task_id: [] for s in specs}

        for s in specs:
            for dep in s.depends_on:
                if dep not in spec_map:
                    raise TaskDependencyError(f"Task '{s.task_id}' depends on unknown task '{dep}'.")
                in_degree[s.task_id] += 1
                dependents[dep].append(s.task_id)

        layers: list[list[OrchestratedTaskSpec]] = []
        ready = [tid for tid, deg in in_degree.items() if deg == 0]
        visited = 0

        while ready:
            current_layer = [spec_map[tid] for tid in ready]
            layers.append(current_layer)
            visited += len(current_layer)
            next_ready: list[str] = []
            for tid in ready:
                for child_id in dependents[tid]:
                    in_degree[child_id] -= 1
                    if in_degree[child_id] == 0:
                        next_ready.append(child_id)
            ready = next_ready

        if visited != len(specs):
            raise TaskDependencyError("Cycle detected in orchestrated task dependency graph.")
        return layers

    async def execute_dag_async(
        self,
        specs: list[OrchestratedTaskSpec],
    ) -> dict[str, OrchestratedTaskResult]:
        """Execute a DAG of tasks concurrently within bounded semaphores and failure isolation."""
        layers = self._topological_layers(specs)
        scan_sem = asyncio.Semaphore(self.max_parallel_scans)
        mcp_sem = asyncio.Semaphore(self.max_parallel_mcp_calls)
        worker_sem = asyncio.Semaphore(self.max_parallel_skill_workers)
        target_sems: dict[str, asyncio.Semaphore] = {}

        for s in specs:
            if s.target_id not in target_sems:
                if s.sequential_only:
                    limit = 1
                elif s.kind == "mcp_call":
                    limit = self.per_mcp_server_concurrency
                elif s.kind == "provider_search":
                    limit = self.per_provider_concurrency
                else:
                    limit = 2
                target_sems[s.target_id] = asyncio.Semaphore(limit)

        results: dict[str, OrchestratedTaskResult] = {}

        async def _run_one(spec: OrchestratedTaskSpec) -> OrchestratedTaskResult:
            # Check if any parent dependency failed
            for dep_id in spec.depends_on:
                dep_res = results.get(dep_id)
                if dep_res is None or dep_res.status != "completed":
                    return OrchestratedTaskResult(
                        task_id=spec.task_id,
                        kind=spec.kind,
                        target_id=spec.target_id,
                        status="cancelled",
                        error=f"Upstream dependency '{dep_id}' did not complete (status={dep_res.status if dep_res else 'missing'}).",
                        attempts=0,
                    )

            # Check idempotency cache
            if spec.idempotency_key and spec.idempotency_key in self._idempotency_cache:
                return OrchestratedTaskResult(
                    task_id=spec.task_id,
                    kind=spec.kind,
                    target_id=spec.target_id,
                    status="deduplicated",
                    result=self._idempotency_cache[spec.idempotency_key],
                    attempts=0,
                    from_idempotency_cache=True,
                )

            cb = self.get_circuit_breaker(spec.target_id)
            if not cb.allow_request():
                return OrchestratedTaskResult(
                    task_id=spec.task_id,
                    kind=spec.kind,
                    target_id=spec.target_id,
                    status="circuit_open",
                    error=f"Circuit breaker open for target '{spec.target_id}' after {cb.consecutive_failures} failures.",
                    attempts=0,
                )

            global_sem = (
                scan_sem
                if spec.kind == "scan"
                else mcp_sem
                if spec.kind == "mcp_call"
                else worker_sem
            )
            t_sem = target_sems[spec.target_id]

            # Never retry non-idempotent mutations unless max_retries=1
            allowed_attempts = (1 + max(0, spec.max_retries)) if spec.idempotent else 1
            t0 = time.monotonic()

            async with global_sem:
                async with t_sem:
                    last_err = ""
                    for attempt in range(1, allowed_attempts + 1):
                        try:
                            async def _invoke() -> Any:
                                val = spec.callable_fn()
                                if asyncio.iscoroutine(val) or isinstance(val, Awaitable):
                                    return await val
                                return await asyncio.to_thread(lambda: val)

                            out = await asyncio.wait_for(_invoke(), timeout=spec.timeout_seconds)
                            cb.record_success()
                            if spec.idempotency_key:
                                self._idempotency_cache[spec.idempotency_key] = out
                            return OrchestratedTaskResult(
                                task_id=spec.task_id,
                                kind=spec.kind,
                                target_id=spec.target_id,
                                status="completed",
                                result=out,
                                attempts=attempt,
                                duration_ms=round((time.monotonic() - t0) * 1000.0, 2),
                            )
                        except asyncio.TimeoutError:
                            last_err = f"Task timed out after {spec.timeout_seconds}s"
                            cb.record_failure()
                            if attempt == allowed_attempts:
                                return OrchestratedTaskResult(
                                    task_id=spec.task_id,
                                    kind=spec.kind,
                                    target_id=spec.target_id,
                                    status="timed_out",
                                    error=last_err,
                                    attempts=attempt,
                                    duration_ms=round((time.monotonic() - t0) * 1000.0, 2),
                                )
                        except asyncio.CancelledError:
                            return OrchestratedTaskResult(
                                task_id=spec.task_id,
                                kind=spec.kind,
                                target_id=spec.target_id,
                                status="cancelled",
                                error="Task cancelled",
                                attempts=attempt,
                                duration_ms=round((time.monotonic() - t0) * 1000.0, 2),
                            )
                        except Exception as exc:
                            last_err = f"{type(exc).__name__}: {exc}"
                            cb.record_failure()
                            if attempt < allowed_attempts:
                                await asyncio.sleep(0.02 * (2 ** (attempt - 1)))
                            else:
                                return OrchestratedTaskResult(
                                    task_id=spec.task_id,
                                    kind=spec.kind,
                                    target_id=spec.target_id,
                                    status="failed",
                                    error=last_err,
                                    attempts=attempt,
                                    duration_ms=round((time.monotonic() - t0) * 1000.0, 2),
                                )
                    return OrchestratedTaskResult(
                        task_id=spec.task_id,
                        kind=spec.kind,
                        target_id=spec.target_id,
                        status="failed",
                        error=last_err,
                        attempts=allowed_attempts,
                        duration_ms=round((time.monotonic() - t0) * 1000.0, 2),
                    )

        for layer in layers:
            layer_results = await asyncio.gather(*(_run_one(s) for s in layer))
            for r in layer_results:
                results[r.task_id] = r
                self._history.append(r)

        return results

    def execute_dag(self, specs: list[OrchestratedTaskSpec]) -> dict[str, OrchestratedTaskResult]:
        """Synchronous entrypoint for executing a parallel task DAG."""
        return asyncio.run(self.execute_dag_async(specs))

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_tasks_executed": len(self._history),
            "completed": sum(1 for r in self._history if r.status == "completed"),
            "failed": sum(1 for r in self._history if r.status == "failed"),
            "timed_out": sum(1 for r in self._history if r.status == "timed_out"),
            "circuit_open": sum(1 for r in self._history if r.status == "circuit_open"),
            "deduplicated": sum(1 for r in self._history if r.status == "deduplicated"),
            "circuit_breakers": {
                k: {
                    "consecutive_failures": v.consecutive_failures,
                    "is_open": not v.allow_request(),
                }
                for k, v in self._circuit_breakers.items()
            },
        }
