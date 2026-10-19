# Parallel Execution, Concurrency & Fault Isolation (`docs/concurrency.md`)

## 1. Bounded Asyncio Scheduler (`ParallelOrchestrator`)

Implemented in `src/skillbridge/orchestration/scheduler.py`, `ParallelOrchestrator` coordinates concurrent verification scans, provider searches, skill script workers, and MCP tool calls using `asyncio` semaphores and topological DAG layers:

- **Global Concurrency Defaults (`RuntimeSettings`)**:
  - `max_parallel_scans = 4`
  - `max_parallel_mcp_calls = 8`
  - `max_parallel_skill_workers = 8`
- **Parallel Batch Loading**:
  - `SkillRuntimeLoader.load_skills_parallel()` runs one task per skill in a bounded `ThreadPoolExecutor` (default `LoaderLimits.max_parallel_workers = 8`).
  - Each skill gets independent staging, verification, and failure isolation; one bad bundle never aborts the batch.
  - Exposed as CLI `load-batch`, MCP `load_skills_batch`, and `SkillBridge.load_skills_parallel()`.
- **Target-Scoped Semaphores**:
  - `per_provider_concurrency = 2`
  - `per_mcp_server_concurrency = 2`
  - `sequential_only = True` forces a semaphore of `1` for MCP servers or tools that do not support concurrent requests.

---

## 2. DAG Dependency Ordering & Cycle Detection

Tasks are submitted as `OrchestratedTaskSpec` items with optional `depends_on: list[str]` edges:
1. `_topological_layers()` computes in-degrees and groups independent tasks into parallel execution waves.
2. If a dependency cycle or unknown task ID is present, `TaskDependencyError` is raised before any task starts.
3. If an upstream task fails, times out, or is cancelled, dependent downstream tasks are automatically marked `status="cancelled"` with an explicit upstream failure reason instead of running on corrupted or missing inputs.

---

## 3. Retries, Idempotency Keys & Circuit Breakers

1. **Idempotent Retry Discipline**:
   - Retries with exponential backoff (`20ms * 2^(attempt-1)`) are only executed when `spec.idempotent == True`.
   - Non-idempotent mutations (`idempotent=False`) are never retried automatically.
2. **Idempotency Key Deduplication**:
   - When `idempotency_key` is supplied, completed results are cached by key so duplicate calls in the same workflow return `status="deduplicated"` (`from_idempotency_cache=True`) without re-executing the tool.
3. **Per-Target Circuit Breakers (`CircuitBreakerState`)**:
   - After `failure_threshold = 3` consecutive failures or timeouts on a provider or MCP server, the circuit opens for `recovery_timeout_seconds = 30.0s`, failing fast with `status="circuit_open"` to prevent cascading stalls.
