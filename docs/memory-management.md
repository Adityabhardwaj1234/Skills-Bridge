# Memory Monitoring & Automatic Eviction (`docs/memory-management.md`)

## 1. Measurement Semantics

SkillBridge treats memory management as a first-class service (`src/skillbridge/runtime/memory.py` and `src/skillbridge/runtime/loader.py`):
- **Default Memory Threshold (`memory_threshold_mib`)**: `250.0 MiB`
- **Default Lower Watermark (`memory_target_mib`)**: `210.0 MiB`
- **Default Active Skill Cap (`active_skill_limit`)**: `25` simultaneously active skills
- **Default Eviction Batch Size (`eviction_batch_default`)**: `7` skills (bounded by `eviction_batch_min=5` and `eviction_batch_max=10`)

### What Is Measured
`SystemMemoryProvider` measures:
1. **SkillBridge Service RSS**: Uses `psutil.Process().memory_info().rss` when installed, or parses `/proc/self/status` (`VmRSS`) and `resource.getrusage(RUSAGE_SELF)` on Linux/macOS.
2. **Child-Process Tree RSS**: Sums RSS across all descendant worker and local MCP subprocesses (`psutil.Process().children(recursive=True)` or `ps -eo pid,ppid,rss`).
3. **Loaded Instruction Payload Bytes**: Exact UTF-8 byte sum of all active `SKILL.md` bodies and loaded reference files across sessions.
4. **Temporary Bundle Storage Bytes**: Disk usage of materialized bundles under `active_staging/`.

For deterministic unit testing of threshold and watermark edge cases, `FakeMemoryProvider` (`src/skillbridge/runtime/memory.py`) allows tests to configure exact base RSS and per-skill memory increments.

---

## 2. Automatic Batch Eviction Algorithm

Whenever a skill is imported or loaded—or when `memory_threshold_mib` / `active_skill_limit` is updated via `SettingsManager`—`check_and_handle_memory_pressure()` executes:

1. **Threshold Check**: Measures `total_process_tree_mib`. If `< 250.0 MiB`, no eviction is needed.
2. **Candidate Filtering**: Identifies all active skills where `pinned == False` and `in_use == False`. Actively executing scripts (`in_use=True`) and user-pinned skills (`pinned=True`) are never evicted.
3. **LRU Ordering**: Sorts eligible candidates by `last_accessed_monotonic` ascending (least-recently-used first).
4. **Batch Eviction (5–10 Skills, Default 7)**:
   - Evicts `min(batch_size, len(eligible))` skills (`7` by default; if fewer than `5` eligible skills exist, evicts all eligible skills immediately rather than waiting for a full batch).
   - For each evicted skill, clears in-memory strings/dictionaries, deletes unshared temporary staging files, retains source recall metadata in `_retained_import_history`, and triggers `gc.collect()`.
5. **Watermark Loop (`210.0 MiB`)**: Re-measures `total_process_tree_mib` after each batch and repeats until memory is `<= 210.0 MiB` or no eligible skills remain.
6. **Genuine Unrelieved Pressure Reporting**: If memory remains above `250.0 MiB` because all remaining memory is held by `pinned`/`in_use` skills or external child processes, sets `genuine_unrelieved_pressure = True` and logs a `memory_pressure_eviction` audit warning.

---

## 3. Honest Technical Limitations

1. **CPython Heap & Arena Retention**: Releasing Python object references and calling `gc.collect()` frees Python heap objects for reuse and removes temporary staging files from disk, but the CPython allocator (`pymalloc` / `glibc malloc`) may not immediately return every freed arena page to the OS kernel (`VmRSS`).
2. **Agent Conversation Context Window**: Unloading a skill from SkillBridge removes its runtime handle and temporary files, preventing future tasks from loading it unnecessarily, but **cannot erase text already transmitted into an external LLM's conversation history**. Use isolated subagents (`.opencode/agents/` or `.claude/agents/`) when strict context-window isolation is required.
