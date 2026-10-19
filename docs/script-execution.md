# Script Discovery, Dependency Management & Execution Policy (`docs/script-execution.md`)

## 1. Strict Separation: Loading vs. Staging vs. Execution

SkillBridge never uses Python's `import` statement to load or inspect skill scripts.
1. **Discovery & Preview**: Statically parses scripts using `ast.parse()` and regexes without executing any code or `setup.py` hooks.
2. **Staging**: Copies verified files into a `0o700` session-scoped temporary directory (`active_staging/<session>/<skill>/`) preserving relative paths.
3. **Execution (`ScriptExecutionManager.run_script`)**: Runs only when explicitly invoked via `skillbridge run-script <skill-id> <relative-path>` or MCP `run_skill_script`.

## 2. Pre-Execution Validation Gates

Before spawning a worker process (`src/skillbridge/runtime/scripts.py`), SkillBridge verifies:
1. **TOCTOU Digest Check**: Recomputes the staged bundle's SHA-256 tree digest and verifies it matches `verification.bundle_digest`. Any post-scan file modification raises `ScriptExecutionBlockedError`.
2. **Assurance Gate**: Requires `verification.assurance_state == AssuranceState.SAFE`.
3. **Explicit Approval Gate**: Requires `allow_untrusted_script_execution=True` or explicit `--approve` (`approved=True`).
4. **Path Containment**: Resolves `relative_script_path` and verifies `target_script.relative_to(staged_bundle_dir)`.
5. **Capability Gate**: If the script was observed using `network:outbound` and `script_network_access=False` (the default), execution is blocked before the process starts.

## 3. Worker Subprocess Isolation Controls

- **No Shell Interpolation**: Invoked with `subprocess.Popen(cmd_list, shell=False, stdin=DEVNULL, start_new_session=True)`.
- **Secret-Free Environment**: Inherits only a minimal environment (`PATH`, `HOME`/`TMPDIR` pointed to a disposable per-invocation work dir, `PYTHONNOUSERSITE=1`, `PYTHONDONTWRITEBYTECODE=1`). All API keys, tokens, and user environment variables are stripped.
- **Socket Guard for Python Workers**: When `script_network_access=False`, Python workers run in `-I` isolated mode with `socket.socket` and `socket.create_connection` monkeypatched to raise `PermissionError` on any outbound socket attempt, plus loopback dead-end proxy variables (`HTTP_PROXY=http://127.0.0.1:0`).
- **Timeout & Process-Tree Cleanup**: Enforces `script_timeout_seconds` (default `15.0s`), killing the entire process group (`os.killpg(pgid, SIGKILL)`) on timeout and wiping the disposable work directory in a `finally` block.
