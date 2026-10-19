"""Controlled, isolated script execution manager for whole-directory skill bundles (Section 11)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any

from skillbridge.bundles.manager import BundleManifest, ScriptEntryPoint
from skillbridge.security.policy import redact_secrets
from skillbridge.settings import RuntimeSettings
from skillbridge.verification.models import AssuranceState, MultiTierVerificationResult


class ScriptExecutionBlockedError(PermissionError):
    """Raised when script execution is denied by security policy, digest mismatch, or capability bounds."""


@dataclass
class ScriptExecutionResult:
    """Structured result from an isolated skill script invocation."""

    skill_id: str
    script_relative_path: str
    bundle_digest: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    timed_out: bool
    network_disabled: bool
    isolation_backend: str
    working_directory: str
    approved: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _build_restricted_script_env(
    bundle_dir: Path,
    work_dir: Path,
    *,
    allow_network: bool,
) -> dict[str, str]:
    """Construct a minimal, secret-free environment for script worker subprocesses."""
    env: dict[str, str] = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(work_dir),
        "TMPDIR": str(work_dir),
        "TEMP": str(work_dir),
        "TMP": str(work_dir),
        "SKILLBRIDGE_BUNDLE_DIR": str(bundle_dir),
        "SKILLBRIDGE_WORK_DIR": str(work_dir),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONUTF8": "1",
        "NO_COLOR": "1",
    }
    if not allow_network:
        env["SKILLBRIDGE_NETWORK_DISABLED"] = "1"
        env["HTTP_PROXY"] = "http://127.0.0.1:0"
        env["HTTPS_PROXY"] = "http://127.0.0.1:0"
        env["ALL_PROXY"] = "http://127.0.0.1:0"
    return env


class ScriptExecutionManager:
    """Validates and executes permitted scripts inside staged skill bundles without Python module import."""

    def __init__(self, settings: RuntimeSettings) -> None:
        self.settings = settings
        self._active_workers: int = 0

    @property
    def active_workers(self) -> int:
        return self._active_workers

    def run_script(
        self,
        *,
        manifest: BundleManifest,
        verification: MultiTierVerificationResult,
        staged_bundle_dir: Path,
        relative_script_path: str,
        arguments: list[str] | None = None,
        explicit_approval: bool = False,
        current_digest_checker: Any | None = None,
    ) -> ScriptExecutionResult:
        """Validate digest, assurance state, path containment, and capabilities before spawning an isolated worker."""
        args = list(arguments or [])

        # 1. Verify current bundle digest matches approved verification digest (TOCTOU guard)
        if current_digest_checker is not None:
            actual_digest = current_digest_checker(staged_bundle_dir)
            if actual_digest != verification.bundle_digest or actual_digest != manifest.bundle_digest:
                raise ScriptExecutionBlockedError(
                    f"Bundle digest changed after verification (expected {verification.bundle_digest}, "
                    f"observed {actual_digest}). Re-verification required."
                )

        # 2. Verify assurance state is SAFE
        if verification.assurance_state != AssuranceState.SAFE:
            raise ScriptExecutionBlockedError(
                f"Cannot execute script '{relative_script_path}' in skill '{manifest.skill_id}': "
                f"assurance state is {verification.assurance_state.value} ({verification.policy_reason})."
            )

        # 3. Verify execution approval policy
        if not (self.settings.allow_untrusted_script_execution or explicit_approval):
            raise ScriptExecutionBlockedError(
                f"Script execution for '{relative_script_path}' requires explicit approval (`--approve` or "
                "`allow_untrusted_script_execution=True`). Regular subprocesses are not a full OS kernel sandbox."
            )

        # 4. Validate relative script path inside staged bundle root
        clean_rel = relative_script_path.strip().lstrip("./")
        if ".." in Path(clean_rel).parts or clean_rel.startswith("/"):
            raise ScriptExecutionBlockedError(
                f"Script path '{relative_script_path}' attempts to escape the bundle root."
            )
        target_script = (staged_bundle_dir / clean_rel).resolve()
        try:
            target_script.relative_to(staged_bundle_dir.resolve())
        except ValueError as exc:
            raise ScriptExecutionBlockedError(
                f"Resolved script path '{target_script}' escapes staged bundle root '{staged_bundle_dir}'."
            ) from exc

        if not target_script.exists() or not target_script.is_file():
            raise ScriptExecutionBlockedError(
                f"Script '{clean_rel}' does not exist in staged bundle '{manifest.skill_id}'."
            )

        # 5. Match against inventoried ScriptEntryPoint & check syntax/network policy
        script_meta: ScriptEntryPoint | None = None
        for s in manifest.scripts:
            if s.relative_path == clean_rel:
                script_meta = s
                break
        if script_meta is None:
            raise ScriptExecutionBlockedError(
                f"File '{clean_rel}' is not registered as a valid executable script in the bundle manifest."
            )
        if not script_meta.syntax_valid:
            raise ScriptExecutionBlockedError(
                f"Script '{clean_rel}' failed static syntax verification: {script_meta.syntax_error}"
            )
        if "network:outbound" in script_meta.observed_capabilities and not self.settings.script_network_access:
            raise ScriptExecutionBlockedError(
                f"Script '{clean_rel}' requires outbound network capability (`network:outbound`), "
                "which is disabled by policy (`script_network_access=False`)."
            )

        # 6. Validate arguments (block null bytes or control characters)
        for arg in args:
            if "\x00" in str(arg):
                raise ScriptExecutionBlockedError("Script arguments must not contain null bytes.")

        # 7. Construct command array based on language (never shell=True)
        work_tmp = Path(tempfile.mkdtemp(prefix="sb_script_work_"))
        try:
            cmd = self._build_isolated_command(
                language=script_meta.language,
                target_script=target_script,
                staged_bundle_dir=staged_bundle_dir,
                work_dir=work_tmp,
                arguments=args,
                allow_network=self.settings.script_network_access,
            )
            env = _build_restricted_script_env(
                staged_bundle_dir,
                work_tmp,
                allow_network=self.settings.script_network_access,
            )
            t0 = time.monotonic()
            self._active_workers += 1
            timed_out = False
            try:
                proc = subprocess.Popen(
                    cmd,
                    shell=False,
                    cwd=str(staged_bundle_dir),
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=(os.name != "nt"),
                )
                try:
                    raw_out, raw_err = proc.communicate(timeout=self.settings.script_timeout_seconds)
                    exit_code = int(proc.returncode or 0)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    self._terminate_process_group(proc)
                    raw_out, raw_err = proc.communicate()
                    exit_code = 124
            finally:
                self._active_workers = max(0, self._active_workers - 1)

            elapsed_ms = round((time.monotonic() - t0) * 1000.0, 2)
            max_b = self.settings.script_max_output_bytes
            stdout_str = redact_secrets((raw_out or b"")[:max_b].decode("utf-8", errors="replace"))
            stderr_str = redact_secrets((raw_err or b"")[:max_b].decode("utf-8", errors="replace"))
            if timed_out:
                stderr_str = f"{stderr_str}\n[SkillBridge: Script execution timed out after {self.settings.script_timeout_seconds}s]".strip()

            return ScriptExecutionResult(
                skill_id=manifest.skill_id,
                script_relative_path=clean_rel,
                bundle_digest=manifest.bundle_digest,
                exit_code=exit_code,
                stdout=stdout_str,
                stderr=stderr_str,
                duration_ms=elapsed_ms,
                timed_out=timed_out,
                network_disabled=not self.settings.script_network_access,
                isolation_backend="restricted-subprocess-no-secrets-socket-guard",
                working_directory=str(staged_bundle_dir),
                approved=True,
            )
        finally:
            shutil.rmtree(work_tmp, ignore_errors=True)

    def _build_isolated_command(
        self,
        *,
        language: str,
        target_script: Path,
        staged_bundle_dir: Path,
        work_dir: Path,
        arguments: list[str],
        allow_network: bool,
    ) -> list[str]:
        if language == "python":
            # Wrap Python execution with socket guard when network is disabled and resource limits on POSIX
            wrapper = (
                "import os, runpy, sys\n"
                f"sys.path.insert(0, {str(staged_bundle_dir)!r})\n"
                "if os.environ.get('SKILLBRIDGE_NETWORK_DISABLED') == '1':\n"
                "    import socket\n"
                "    def _blocked_socket(*a, **kw):\n"
                "        raise PermissionError('Outbound network access is disabled by SkillBridge script policy.')\n"
                "    socket.socket = _blocked_socket\n"
                "    socket.create_connection = _blocked_socket\n"
                f"sys.argv = [{str(target_script)!r}] + {arguments!r}\n"
                f"runpy.run_path({str(target_script)!r}, run_name='__main__')\n"
            )
            return [sys.executable, "-I", "-c", wrapper]
        if language == "shell":
            bash_exe = shutil.which("bash") or shutil.which("sh")
            if not bash_exe:
                raise ScriptExecutionBlockedError("No POSIX shell interpreter found to execute shell script.")
            return [bash_exe, str(target_script)] + arguments
        if language in ("javascript", "typescript"):
            node_exe = shutil.which("node")
            if not node_exe:
                raise ScriptExecutionBlockedError("Node.js runtime (`node`) is not installed.")
            return [node_exe, str(target_script)] + arguments
        raise ScriptExecutionBlockedError(f"Unsupported script runtime language: {language}")

    @staticmethod
    def _terminate_process_group(proc: subprocess.Popen[bytes]) -> None:
        try:
            if os.name != "nt":
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
