"""Verification Engine Adapter System (SkillSpector, SKIL, SkillEvaluator, OptionalSkillFortify) and Coordinator."""

from __future__ import annotations

from abc import ABC, abstractmethod
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any
import uuid

from skillbridge.bundles.manager import BundleManifest
from skillbridge.security.policy import redact_secrets
from skillbridge.settings import RuntimeSettings
from skillbridge.verification.models import (
    NORMALIZED_SCHEMA_VERSION,
    SKILLFORTIFY_PINNED_COMMIT,
    SKILLFORTIFY_PINNED_VERSION,
    SKILLEVALUATOR_PINNED_COMMIT,
    SKILLEVALUATOR_PINNED_VERSION,
    SKILLSPECTOR_PINNED_COMMIT,
    SKILLSPECTOR_PINNED_VERSION,
    SKIL_PINNED_COMMIT,
    SKIL_PINNED_VERSION,
    AssuranceState,
    CapabilityEvidence,
    MultiTierVerificationResult,
    NormalizedFinding,
    NormalizedScanReport,
    utc_now_iso,
)
from skillbridge.verification.tier1_skillspector import (
    parse_skillspector_cli_json,
    run_builtin_tier1_skillspector,
)
from skillbridge.verification.tier2_skil import (
    parse_skil_cli_json,
    run_builtin_tier2_skil,
)
from skillbridge.verification.tier3_evaluator import (
    parse_skillevaluator_cli_json,
    run_builtin_tier3_evaluator,
)


def _sanitized_subprocess_env() -> dict[str, str]:
    """Return a minimal environment dictionary with all credentials/tokens stripped."""
    safe_keys = {"PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "TEMP", "TMP", "LANG", "LC_ALL", "PYTHONPATH"}
    env: dict[str, str] = {}
    for k, v in os.environ.items():
        if k in safe_keys and not any(s in k.upper() for s in ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")):
            env[k] = v
    env["PYTHONUTF8"] = "1"
    env["NO_COLOR"] = "1"
    return env


class VerificationEngineAdapter(ABC):
    """Typed internal contract implemented by all four verification engine adapters."""

    engine_id: str
    pinned_version: str
    pinned_commit: str
    executable_name: str
    license_id: str

    def __init__(self, executable_override: str | None = None, timeout_seconds: float = 30.0) -> None:
        self.executable_override = executable_override
        self.timeout_seconds = timeout_seconds

    def resolve_executable(self) -> str | None:
        if self.executable_override:
            p = Path(self.executable_override)
            if p.exists() and os.access(p, os.X_OK):
                return str(p)
            found = shutil.which(self.executable_override)
            if found:
                return found
            return None
        return shutil.which(self.executable_name)

    def is_installed(self) -> bool:
        return self.resolve_executable() is not None

    def get_installed_version(self) -> str | None:
        exe = self.resolve_executable()
        if not exe:
            return None
        try:
            proc = subprocess.run(
                [exe, "--version"],
                shell=False,
                capture_output=True,
                text=True,
                timeout=5.0,
                env=_sanitized_subprocess_env(),
            )
            out = (proc.stdout or proc.stderr or "").strip()
            return out.splitlines()[0][:80] if out else "installed"
        except Exception:
            return None

    def check_prerequisites(self) -> dict[str, Any]:
        exe = self.resolve_executable()
        ver = self.get_installed_version() if exe else None
        return {
            "engine_id": self.engine_id,
            "executable_name": self.executable_name,
            "resolved_executable": exe,
            "installed": exe is not None,
            "installed_version": ver,
            "pinned_version": self.pinned_version,
            "pinned_commit": self.pinned_commit,
            "license": self.license_id,
        }

    @abstractmethod
    def build_command(self, exe: str, target_path: Path) -> list[str]:
        """Return validated argument list (never shell string)."""

    def execute_subprocess(
        self,
        target_path: Path,
        *,
        max_output_bytes: int = 2 * 1024 * 1024,
    ) -> tuple[int, str, str, bool]:
        """Run the external CLI with shell=False, timeout, minimal env, and bounded output."""
        exe = self.resolve_executable()
        if not exe:
            return 127, "", f"Executable '{self.executable_name}' is not installed on PATH.", False
        cmd = self.build_command(exe, target_path)
        try:
            proc = subprocess.run(
                cmd,
                shell=False,
                cwd=str(target_path.parent),
                env=_sanitized_subprocess_env(),
                capture_output=True,
                timeout=self.timeout_seconds,
            )
            stdout = (proc.stdout or b"")[:max_output_bytes].decode("utf-8", errors="replace")
            stderr = (proc.stderr or b"")[:max_output_bytes].decode("utf-8", errors="replace")
            return proc.returncode, redact_secrets(stdout), redact_secrets(stderr), False
        except subprocess.TimeoutExpired as exc:
            out = (exc.stdout or b"")[:max_output_bytes].decode("utf-8", errors="replace") if exc.stdout else ""
            return 124, redact_secrets(out), f"Subprocess timed out after {self.timeout_seconds}s", True
        except OSError as exc:
            return 126, "", f"Subprocess execution failed: {exc}", False


class SkillSpectorAdapter(VerificationEngineAdapter):
    """Tier 1 NVIDIA SkillSpector adapter (Apache-2.0)."""

    engine_id = "skillspector"
    pinned_version = SKILLSPECTOR_PINNED_VERSION
    pinned_commit = SKILLSPECTOR_PINNED_COMMIT
    executable_name = "skillspector"
    license_id = "Apache-2.0"

    def build_command(self, exe: str, target_path: Path) -> list[str]:
        return [exe, "scan", str(target_path), "--format", "json", "--no-llm"]

    def scan(
        self,
        manifest: BundleManifest,
        *,
        require_external_binary: bool = False,
    ) -> NormalizedScanReport:
        started_at = utc_now_iso()
        target = Path(manifest.staged_path)
        if self.is_installed():
            code, stdout, stderr, timed_out = self.execute_subprocess(target)
            if timed_out or code >= 2 or not stdout.strip():
                return NormalizedScanReport(
                    schema_version=NORMALIZED_SCHEMA_VERSION,
                    scan_id=f"t1-spector-{uuid.uuid4().hex[:10]}",
                    artifact_id=manifest.skill_id,
                    artifact_digest=manifest.bundle_digest,
                    engine_id="skillspector-cli",
                    engine_version=self.pinned_version,
                    engine_revision=self.pinned_commit[:12],
                    scan_profile="external-cli",
                    scan_started_at=started_at,
                    scan_completed_at=utc_now_iso(),
                    scan_status="timeout" if timed_out else "failed",
                    analysis_complete=False,
                    limitations=[stderr or f"skillspector exited with code {code}"],
                    exit_code=code,
                    assurance_state=AssuranceState.UNKNOWN,
                )
            return parse_skillspector_cli_json(
                stdout,
                artifact_id=manifest.skill_id,
                artifact_digest=manifest.bundle_digest,
                exit_code=code,
                started_at=started_at,
            )

        if require_external_binary:
            return NormalizedScanReport(
                schema_version=NORMALIZED_SCHEMA_VERSION,
                scan_id=f"t1-spector-{uuid.uuid4().hex[:10]}",
                artifact_id=manifest.skill_id,
                artifact_digest=manifest.bundle_digest,
                engine_id="skillspector-cli",
                engine_version=self.pinned_version,
                engine_revision=self.pinned_commit[:12],
                scan_profile="external-cli-required",
                scan_started_at=started_at,
                scan_completed_at=utc_now_iso(),
                scan_status="skipped",
                analysis_complete=False,
                limitations=[
                    "External skillspector binary required by policy (`require_external_scanner_binaries=True`) "
                    "but not found on PATH."
                ],
                exit_code=127,
                assurance_state=AssuranceState.UNKNOWN,
            )

        return run_builtin_tier1_skillspector(manifest)


class SKILAdapter(VerificationEngineAdapter):
    """Tier 2 SKIL (Skill Inspector and Linter) adapter (Apache-2.0)."""

    engine_id = "skil"
    pinned_version = SKIL_PINNED_VERSION
    pinned_commit = SKIL_PINNED_COMMIT
    executable_name = "skil"
    license_id = "Apache-2.0"

    def build_command(self, exe: str, target_path: Path) -> list[str]:
        return [exe, "scan", str(target_path), "--static-only", "--fail-on-incomplete", "--format", "json"]

    def verify(
        self,
        manifest: BundleManifest,
        tier1_report: NormalizedScanReport,
        *,
        require_external_binary: bool = False,
    ) -> NormalizedScanReport:
        started_at = utc_now_iso()
        target = Path(manifest.staged_path)
        if self.is_installed():
            code, stdout, stderr, timed_out = self.execute_subprocess(target)
            if timed_out or code >= 2 or not stdout.strip():
                return NormalizedScanReport(
                    schema_version=NORMALIZED_SCHEMA_VERSION,
                    scan_id=f"t2-skil-{uuid.uuid4().hex[:10]}",
                    artifact_id=manifest.skill_id,
                    artifact_digest=manifest.bundle_digest,
                    engine_id="skil-cli",
                    engine_version=self.pinned_version,
                    engine_revision=self.pinned_commit[:12],
                    scan_profile="external-cli",
                    scan_started_at=started_at,
                    scan_completed_at=utc_now_iso(),
                    scan_status="timeout" if timed_out else "failed",
                    analysis_complete=False,
                    limitations=[stderr or f"skil exited with code {code}"],
                    exit_code=code,
                    assurance_state=AssuranceState.UNKNOWN,
                )
            return parse_skil_cli_json(
                stdout,
                artifact_id=manifest.skill_id,
                artifact_digest=manifest.bundle_digest,
                exit_code=code,
                started_at=started_at,
            )

        if require_external_binary:
            return NormalizedScanReport(
                schema_version=NORMALIZED_SCHEMA_VERSION,
                scan_id=f"t2-skil-{uuid.uuid4().hex[:10]}",
                artifact_id=manifest.skill_id,
                artifact_digest=manifest.bundle_digest,
                engine_id="skil-cli",
                engine_version=self.pinned_version,
                engine_revision=self.pinned_commit[:12],
                scan_profile="external-cli-required",
                scan_started_at=started_at,
                scan_completed_at=utc_now_iso(),
                scan_status="skipped",
                analysis_complete=False,
                limitations=[
                    "External `skil` binary required by policy (`require_external_scanner_binaries=True`) but not installed."
                ],
                exit_code=127,
                assurance_state=AssuranceState.UNKNOWN,
            )

        return run_builtin_tier2_skil(manifest, tier1_report)


class SkillEvaluatorAdapter(VerificationEngineAdapter):
    """Tier 3 NVIDIA SkillEvaluator adapter (Apache-2.0) — reuses Tier 1 SkillSpector evidence."""

    engine_id = "skillevaluator"
    pinned_version = SKILLEVALUATOR_PINNED_VERSION
    pinned_commit = SKILLEVALUATOR_PINNED_COMMIT
    executable_name = "skillevaluator"
    license_id = "Apache-2.0"

    def build_command(self, exe: str, target_path: Path) -> list[str]:
        return [exe, "validate", str(target_path), "--no-llm", "--report", "json"]

    def evaluate(
        self,
        manifest: BundleManifest,
        tier1_report: NormalizedScanReport,
        *,
        catalog_descriptions: dict[str, str] | None = None,
        require_external_binary: bool = False,
    ) -> NormalizedScanReport:
        started_at = utc_now_iso()
        target = Path(manifest.staged_path)
        if self.is_installed():
            code, stdout, stderr, timed_out = self.execute_subprocess(target)
            if timed_out or not stdout.strip():
                return NormalizedScanReport(
                    schema_version=NORMALIZED_SCHEMA_VERSION,
                    scan_id=f"t3-eval-{uuid.uuid4().hex[:10]}",
                    artifact_id=manifest.skill_id,
                    artifact_digest=manifest.bundle_digest,
                    engine_id="skillevaluator-cli",
                    engine_version=self.pinned_version,
                    engine_revision=self.pinned_commit[:12],
                    scan_profile="external-cli",
                    scan_started_at=started_at,
                    scan_completed_at=utc_now_iso(),
                    scan_status="timeout" if timed_out else "failed",
                    analysis_complete=False,
                    limitations=[stderr or f"skillevaluator exited with code {code}"],
                    exit_code=code,
                    assurance_state=AssuranceState.UNKNOWN,
                )
            return parse_skillevaluator_cli_json(
                stdout,
                artifact_id=manifest.skill_id,
                artifact_digest=manifest.bundle_digest,
                exit_code=code,
                started_at=started_at,
                reused_tier1_scan_id=tier1_report.scan_id,
            )

        if require_external_binary:
            return NormalizedScanReport(
                schema_version=NORMALIZED_SCHEMA_VERSION,
                scan_id=f"t3-eval-{uuid.uuid4().hex[:10]}",
                artifact_id=manifest.skill_id,
                artifact_digest=manifest.bundle_digest,
                engine_id="skillevaluator-cli",
                engine_version=self.pinned_version,
                engine_revision=self.pinned_commit[:12],
                scan_profile="external-cli-required",
                scan_started_at=started_at,
                scan_completed_at=utc_now_iso(),
                scan_status="skipped",
                analysis_complete=False,
                limitations=[
                    "External `skillevaluator` binary required by policy (`require_external_scanner_binaries=True`) but not installed."
                ],
                exit_code=127,
                assurance_state=AssuranceState.UNKNOWN,
            )

        return run_builtin_tier3_evaluator(
            manifest,
            tier1_report,
            catalog_descriptions=catalog_descriptions,
        )


class OptionalSkillFortifyAdapter(VerificationEngineAdapter):
    """Strictly optional, disabled-by-default subprocess adapter for externally installed SkillFortify CLI."""

    engine_id = "skillfortify"
    pinned_version = SKILLFORTIFY_PINNED_VERSION
    pinned_commit = SKILLFORTIFY_PINNED_COMMIT
    executable_name = "skillfortify"
    license_id = "Elastic-2.0 (External Optional Tool Only - Not Bundled)"

    def build_command(self, exe: str, target_path: Path) -> list[str]:
        return [exe, "scan", str(target_path), "--format", "json"]

    def scan_if_enabled(
        self,
        manifest: BundleManifest,
        *,
        enabled: bool = False,
    ) -> NormalizedScanReport:
        started_at = utc_now_iso()
        if not enabled:
            return NormalizedScanReport(
                schema_version=NORMALIZED_SCHEMA_VERSION,
                scan_id=f"opt-fortify-{uuid.uuid4().hex[:10]}",
                artifact_id=manifest.skill_id,
                artifact_digest=manifest.bundle_digest,
                engine_id="skillfortify-optional",
                engine_version=self.pinned_version,
                engine_revision=self.pinned_commit[:12],
                scan_profile="disabled-by-license-policy",
                scan_started_at=started_at,
                scan_completed_at=utc_now_iso(),
                scan_status="skipped",
                analysis_complete=False,
                checks_skipped=["skillfortify (disabled by default due to Elastic License 2.0 separation policy)"],
                limitations=["SkillFortify is disabled unless `enable_skillfortify=True` and external binary is installed."],
                exit_code=0,
                assurance_state=AssuranceState.UNKNOWN,
            )

        if not self.is_installed():
            return NormalizedScanReport(
                schema_version=NORMALIZED_SCHEMA_VERSION,
                scan_id=f"opt-fortify-{uuid.uuid4().hex[:10]}",
                artifact_id=manifest.skill_id,
                artifact_digest=manifest.bundle_digest,
                engine_id="skillfortify-optional",
                engine_version=self.pinned_version,
                engine_revision=self.pinned_commit[:12],
                scan_profile="external-cli",
                scan_started_at=started_at,
                scan_completed_at=utc_now_iso(),
                scan_status="skipped",
                analysis_complete=False,
                limitations=["`enable_skillfortify=True`, but `skillfortify` CLI was not found on PATH."],
                exit_code=127,
                assurance_state=AssuranceState.UNKNOWN,
            )

        code, stdout, stderr, timed_out = self.execute_subprocess(Path(manifest.staged_path))
        if timed_out or code >= 2 or not stdout.strip():
            return NormalizedScanReport(
                schema_version=NORMALIZED_SCHEMA_VERSION,
                scan_id=f"opt-fortify-{uuid.uuid4().hex[:10]}",
                artifact_id=manifest.skill_id,
                artifact_digest=manifest.bundle_digest,
                engine_id="skillfortify-optional",
                engine_version=self.pinned_version,
                engine_revision=self.pinned_commit[:12],
                scan_profile="external-cli",
                scan_started_at=started_at,
                scan_completed_at=utc_now_iso(),
                scan_status="timeout" if timed_out else "failed",
                analysis_complete=False,
                limitations=[stderr or f"skillfortify exited with code {code}"],
                exit_code=code,
                assurance_state=AssuranceState.UNKNOWN,
            )

        try:
            items = json.loads(stdout)
            if isinstance(items, dict):
                items = [items]
        except Exception as exc:
            return NormalizedScanReport(
                schema_version=NORMALIZED_SCHEMA_VERSION,
                scan_id=f"opt-fortify-{uuid.uuid4().hex[:10]}",
                artifact_id=manifest.skill_id,
                artifact_digest=manifest.bundle_digest,
                engine_id="skillfortify-optional",
                engine_version=self.pinned_version,
                engine_revision=self.pinned_commit[:12],
                scan_profile="external-cli",
                scan_started_at=started_at,
                scan_completed_at=utc_now_iso(),
                scan_status="failed",
                analysis_complete=False,
                limitations=[f"Invalid JSON from skillfortify CLI: {exc}"],
                exit_code=2,
                assurance_state=AssuranceState.UNKNOWN,
            )

        findings: list[NormalizedFinding] = []
        cap_ev: list[CapabilityEvidence] = []
        is_safe = True
        for entry in items:
            if not isinstance(entry, dict):
                continue
            if entry.get("is_safe") is False:
                is_safe = False
            for cap in entry.get("inferred_capabilities") or []:
                res_name = f"{cap.get('resource', 'unknown')}:{cap.get('access', 'READ')}".lower()
                cap_ev.append(
                    CapabilityEvidence(
                        capability=res_name,
                        declared=False,
                        observed=True,
                        status="observed_by_skillfortify",
                    )
                )
            for f in entry.get("findings") or []:
                findings.append(
                    NormalizedFinding(
                        finding_id=f"finding-{uuid.uuid4().hex[:12]}",
                        rule_id=str(f.get("finding_type") or f.get("attack_class") or "SKF_FINDING"),
                        severity=str(f.get("severity") or "HIGH").upper(),
                        confidence=0.85,
                        category=str(f.get("attack_class") or "Supply Chain"),
                        description=str(f.get("message") or ""),
                        file_path="SKILL.md",
                        start_line=1,
                        evidence=redact_secrets(str(f.get("evidence") or "")),
                        remediation="Review capability mismatch reported by external SkillFortify CLI.",
                        engine_id="skillfortify-optional",
                        engine_revision=self.pinned_commit[:12],
                    )
                )

        assurance = AssuranceState.UNSAFE if (not is_safe or code == 1) else AssuranceState.SAFE
        return NormalizedScanReport(
            schema_version=NORMALIZED_SCHEMA_VERSION,
            scan_id=f"opt-fortify-{uuid.uuid4().hex[:10]}",
            artifact_id=manifest.skill_id,
            artifact_digest=manifest.bundle_digest,
            engine_id="skillfortify-optional",
            engine_version=self.pinned_version,
            engine_revision=self.pinned_commit[:12],
            scan_profile="external-cli",
            scan_started_at=started_at,
            scan_completed_at=utc_now_iso(),
            scan_status="completed",
            analysis_complete=True,
            checks_run=["skillfortify.scan"],
            findings=findings,
            capability_evidence=cap_ev,
            report_artifacts={"raw_skillfortify": items},
            exit_code=code,
            assurance_state=assurance,
        )


class VerificationCoordinator:
    """Orchestrates Tier 0, Tier 1 (SkillSpector), Tier 2 (SKIL), Tier 3 (SkillEvaluator), and Optional SkillFortify."""

    def __init__(
        self,
        *,
        skillspector_exe: str | None = None,
        skil_exe: str | None = None,
        skillevaluator_exe: str | None = None,
        skillfortify_exe: str | None = None,
    ) -> None:
        self.skillspector = SkillSpectorAdapter(executable_override=skillspector_exe)
        self.skil = SKILAdapter(executable_override=skil_exe)
        self.skillevaluator = SkillEvaluatorAdapter(executable_override=skillevaluator_exe)
        self.skillfortify = OptionalSkillFortifyAdapter(executable_override=skillfortify_exe)

    def check_all_engines(self) -> dict[str, dict[str, Any]]:
        return {
            "skillspector": self.skillspector.check_prerequisites(),
            "skil": self.skil.check_prerequisites(),
            "skillevaluator": self.skillevaluator.check_prerequisites(),
            "skillfortify": self.skillfortify.check_prerequisites(),
        }

    def verify_bundle(
        self,
        manifest: BundleManifest,
        settings: RuntimeSettings,
        *,
        catalog_descriptions: dict[str, str] | None = None,
    ) -> MultiTierVerificationResult:
        """Execute Tiers 1–3 on a staged bundle and apply fail-closed policy gating."""
        req_ext = settings.require_external_scanner_binaries

        tier1 = self.skillspector.scan(manifest, require_external_binary=req_ext)
        tier2 = self.skil.verify(manifest, tier1, require_external_binary=req_ext)
        tier3 = self.skillevaluator.evaluate(
            manifest,
            tier1,
            catalog_descriptions=catalog_descriptions,
            require_external_binary=req_ext,
        )

        optional_reports: list[NormalizedScanReport] = []
        if settings.enable_skillfortify:
            opt_rep = self.skillfortify.scan_if_enabled(manifest, enabled=True)
            optional_reports.append(opt_rep)

        states = [tier1.assurance_state, tier2.assurance_state, tier3.assurance_state]
        for opt in optional_reports:
            if opt.scan_status != "skipped":
                states.append(opt.assurance_state)

        if not manifest.tier0_passed or AssuranceState.UNSAFE in states:
            overall_state = AssuranceState.UNSAFE
        elif AssuranceState.UNKNOWN in states or not (
            tier1.analysis_complete and tier2.analysis_complete and tier3.analysis_complete
        ):
            overall_state = AssuranceState.UNKNOWN
        else:
            overall_state = AssuranceState.SAFE

        if overall_state == AssuranceState.UNSAFE:
            allowed_load = False
            allowed_scripts = False
            reason = (
                f"BLOCKED (UNSAFE): Mandatory security/capability tier identified blocking issues "
                f"(Tier0={manifest.tier0_passed}, Tier1={tier1.assurance_state.value}, "
                f"Tier2={tier2.assurance_state.value}, Tier3={tier3.assurance_state.value})."
            )
        elif overall_state == AssuranceState.UNKNOWN:
            if not settings.security_fail_closed and settings.load_unknown_extensions and not manifest.has_executable_scripts:
                allowed_load = True
                allowed_scripts = False
                reason = "ALLOWED (RESTRICTED READ-ONLY): Assurance is UNKNOWN, permitted only for non-executable instructions by explicit override."
            else:
                allowed_load = False
                allowed_scripts = False
                reason = (
                    "BLOCKED (FAIL-CLOSED ON UNKNOWN): Required verification evidence is incomplete or UNKNOWN "
                    f"(Tier1 complete={tier1.analysis_complete}, Tier2 complete={tier2.analysis_complete}, "
                    f"Tier3 complete={tier3.analysis_complete})."
                )
        else:
            allowed_load = True
            allowed_scripts = bool(manifest.has_executable_scripts and settings.allow_untrusted_script_execution)
            reason = (
                f"APPROVED (SAFE): All mandatory verification tiers passed for digest {manifest.bundle_digest} "
                f"(scripts_permitted={allowed_scripts})."
            )

        closure_info = tier2.report_artifacts.get("assurance_closure") or {}
        closure_digest = str(closure_info.get("closure_digest") or manifest.bundle_digest)
        quality_score = float(tier3.report_artifacts.get("quality_score") or 0.0)

        return MultiTierVerificationResult(
            verification_id=f"ver-{uuid.uuid4().hex[:12]}",
            skill_id=manifest.skill_id,
            bundle_digest=manifest.bundle_digest,
            assurance_state=overall_state,
            allowed_to_load=allowed_load,
            allowed_to_execute_scripts=allowed_scripts,
            policy_reason=reason,
            tier0_passed=manifest.tier0_passed,
            tier1_report=tier1,
            tier2_report=tier2,
            tier3_report=tier3,
            optional_reports=optional_reports,
            closure_digest=closure_digest,
            quality_score=quality_score,
        )
