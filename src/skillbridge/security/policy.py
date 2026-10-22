"""Trust policy engine and quarantine manager for SkillBridge."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Dict, Optional, Tuple

from skillbridge.config import SecurityPolicyConfig
from skillbridge.discovery.normalizer import is_link_like, validate_bundle_rel_path, validate_skill_name
from skillbridge.models import ExtensionBundle, SecurityAssessment, SecurityVerdict, TrustLevel, utc_now_iso

# Policy matrix: (SAFE, CAUTION, DANGEROUS, UNKNOWN)
# Values: "allow" | "ask" | "block"
POLICY_MATRIX: Dict[str, Dict[str, str]] = {
    TrustLevel.BUILTIN.value: {
        SecurityVerdict.SAFE.value: "allow",
        SecurityVerdict.CAUTION.value: "allow",
        SecurityVerdict.DANGEROUS.value: "block",
        SecurityVerdict.UNKNOWN.value: "ask",
    },
    TrustLevel.TRUSTED.value: {
        SecurityVerdict.SAFE.value: "allow",
        SecurityVerdict.CAUTION.value: "allow",
        SecurityVerdict.DANGEROUS.value: "block",
        SecurityVerdict.UNKNOWN.value: "ask",
    },
    TrustLevel.COMMUNITY.value: {
        SecurityVerdict.SAFE.value: "allow",
        SecurityVerdict.CAUTION.value: "ask",
        SecurityVerdict.DANGEROUS.value: "block",
        SecurityVerdict.UNKNOWN.value: "block",
    },
    TrustLevel.AGENT_CREATED.value: {
        SecurityVerdict.SAFE.value: "allow",
        SecurityVerdict.CAUTION.value: "ask",
        SecurityVerdict.DANGEROUS.value: "block",
        SecurityVerdict.UNKNOWN.value: "ask",
    },
    TrustLevel.UNTRUSTED.value: {
        SecurityVerdict.SAFE.value: "ask",
        SecurityVerdict.CAUTION.value: "block",
        SecurityVerdict.DANGEROUS.value: "block",
        SecurityVerdict.UNKNOWN.value: "block",
    },
}

SECRET_REDACT_RE = re.compile(
    r"(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,}|sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|Bearer\s+[A-Za-z0-9._\-]{16,})"
)


def redact_secrets(text: str) -> str:
    """Redact recognizable API keys, tokens, and Authorization Bearer secrets from strings."""
    if not text:
        return ""
    return SECRET_REDACT_RE.sub("[REDACTED_CREDENTIAL]", text)


class TrustPolicyEngine:
    """Evaluates security assessments against configurable trust policies.

    Hard rule: DANGEROUS extensions from community/untrusted sources are NEVER allowed, even with force/approve.
    Exception: builtin (vendored/curated) extensions with a DANGEROUS verdict may only be loaded when the
    operator explicitly approves them AND `allow_builtin_dangerous_override` is enabled; otherwise they are blocked.
    """

    def __init__(self, config: Optional[SecurityPolicyConfig] = None):
        self.config = config or SecurityPolicyConfig()

    def resolve_trust_level(self, source_provider: str, repo: str = "", identifier: str = "") -> str:
        if source_provider in ("hermes-bundled", "hermes-official", "builtin"):
            return TrustLevel.BUILTIN.value
        for trusted_repo in self.config.trusted_repos:
            tr_lower = trusted_repo.lower()
            if repo.lower() == tr_lower or identifier.lower().startswith(f"{tr_lower}/"):
                return TrustLevel.TRUSTED.value
        if source_provider in ("opencode-user", "opencode-project", "claude-user", "claude-project", "hermes-local"):
            return TrustLevel.TRUSTED.value
        return TrustLevel.COMMUNITY.value

    def evaluate(
        self,
        assessment: SecurityAssessment,
        *,
        approved: bool = False,
        force: bool = False,
         alters_config_or_runs_code: bool = False,
    ) -> Tuple[bool, bool, str]:
        """Return (allowed, requires_approval, reason).

        Hard rule: DANGEROUS community/untrusted extensions are NEVER allowed, even with force=True or approved=True.
        Builtin DANGEROUS extensions remain blocked unless explicitly approved by the operator.
        """
        verdict = assessment.verdict.upper()
        trust = assessment.trust_level.lower()
        n_findings = len(assessment.findings)

        if verdict == SecurityVerdict.DANGEROUS.value:
            if (
                trust == TrustLevel.BUILTIN.value
                and (approved or force)
                and self.config.allow_builtin_dangerous_override
            ):
                reason = (
                    f"ALLOWED_WITH_APPROVAL: builtin source '{assessment.extension_id}' has DANGEROUS verdict "
                    f"({n_findings} finding(s)) and was explicitly approved by the operator "
                    "(allow_builtin_dangerous_override=True)."
                )
                assessment.allowed = True
                assessment.policy_reason = reason
                return True, False, reason
            reason = (
                f"BLOCKED: Verdict is DANGEROUS ({n_findings} finding(s), including critical policy violations). "
                "DANGEROUS extensions cannot be overridden by --approve or --force."
            )
            assessment.allowed = False
            assessment.policy_reason = reason
            return False, False, reason

        if verdict == SecurityVerdict.UNKNOWN.value and trust not in (TrustLevel.BUILTIN.value, TrustLevel.TRUSTED.value):
            reason = "BLOCKED: Verdict is UNKNOWN (insufficient evidence to establish trust for community/external source)."
            assessment.allowed = False
            assessment.policy_reason = reason
            return False, False, reason

        matrix_row = POLICY_MATRIX.get(trust, POLICY_MATRIX[TrustLevel.COMMUNITY.value])
        base_action = matrix_row.get(verdict, "block")

        if alters_config_or_runs_code and trust in (TrustLevel.COMMUNITY.value, TrustLevel.UNTRUSTED.value):
            if not approved:
                reason = (
                    f"REQUIRES_APPROVAL: Community extension '{assessment.extension_id}' alters client config or contains "
                    f"executable scripts/commands (verdict={verdict}). Pass explicit approval to proceed."
                )
                assessment.allowed = None
                assessment.policy_reason = reason
                return False, True, reason

        if base_action == "allow":
            if verdict == SecurityVerdict.CAUTION.value and not self.config.allow_trusted_caution and not (approved or force):
                reason = f"REQUIRES_APPROVAL: {trust} extension has CAUTION verdict ({n_findings} finding(s))."
                assessment.allowed = None
                assessment.policy_reason = reason
                return False, True, reason
            reason = f"ALLOWED: {trust} source with {verdict} verdict ({n_findings} finding(s))."
            assessment.allowed = True
            assessment.policy_reason = reason
            return True, False, reason

        if base_action == "ask":
            if approved or force:
                reason = f"ALLOWED_WITH_APPROVAL: Explicit approval granted for {trust} source with {verdict} verdict ({n_findings} finding(s))."
                assessment.allowed = True
                assessment.policy_reason = reason
                return True, False, reason
            reason = f"REQUIRES_APPROVAL: {trust} source with {verdict} verdict ({n_findings} finding(s)) requires explicit approval."
            assessment.allowed = None
            assessment.policy_reason = reason
            return False, True, reason

        reason = f"BLOCKED: Policy forbids {trust} extension with {verdict} verdict ({n_findings} finding(s))."
        assessment.allowed = False
        assessment.policy_reason = reason
        return False, False, reason


class QuarantineManager:
    """Manages quarantined extension bundles and scan reports."""

    def __init__(self, quarantine_root: Path):
        self.quarantine_root = Path(quarantine_root)
        if is_link_like(self.quarantine_root):
            raise ValueError(
                f"Quarantine root '{self.quarantine_root}' is a symlink/junction; refusing to use it."
            )
        self.quarantine_root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _remove_quarantine_dir(path: Path) -> None:
        """Remove a quarantine directory without following a planted link/reparse point."""
        if is_link_like(path):
            try:
                path.unlink()
                return
            except OSError:
                try:
                    path.rmdir()
                    return
                except OSError:
                    pass
        try:
            if path.is_file():
                path.unlink()
                return
        except OSError:
            pass
        if path.exists():
            shutil.rmtree(path)

    def quarantine_bundle(self, bundle: ExtensionBundle, assessment: SecurityAssessment) -> Path:
        """Stage a rejected or pending bundle in the isolated quarantine directory with its scan report."""
        safe_name = validate_skill_name(bundle.name or "quarantined-extension")
        short_hash = (assessment.content_hash or "nohash").replace("sha256:", "")[:12]
        q_dir = self.quarantine_root / f"{safe_name}-{short_hash}"
        self._remove_quarantine_dir(q_dir)
        q_dir.mkdir(parents=True, exist_ok=True)

        files_dir = q_dir / "bundle"
        files_dir.mkdir(parents=True, exist_ok=True)
        for rel_path, content in bundle.files.items():
            try:
                safe_rel = validate_bundle_rel_path(rel_path)
            except ValueError:
                continue
            dest = files_dir.joinpath(*safe_rel.split("/"))
            dest.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                dest.write_bytes(content)
            else:
                dest.write_text(content, encoding="utf-8", newline="")

        assessment.quarantine_path = str(q_dir)
        report_file = q_dir / "security_assessment.json"
        report_file.write_text(json.dumps(assessment.to_dict(), indent=2) + "\n", encoding="utf-8")
        return q_dir

    def quarantine_staged_bundle(
        self,
        manifest: object,
        verification: Dict[str, object],
        *,
        reason: str = "",
    ) -> Path:
        """Persist a blocked staged bundle plus its verification result under the home quarantine dir.

        Only files enumerated in the manifest are copied, and each source is checked for
        links/reparse points and containment. This keeps blocked-but-dangerous content available
        for operator review without executing or following it.
        """
        skill_id = str(getattr(manifest, "skill_id", "quarantined-extension"))
        name = str(getattr(manifest, "name", "") or skill_id.split("/")[-1])
        digest = str(getattr(manifest, "bundle_digest", "nohash")).replace("sha256:", "")[:12]
        try:
            safe_name = validate_skill_name(name)
        except ValueError:
            safe_name = "quarantined-extension"
        q_dir = self.quarantine_root / f"{safe_name}-{digest}"
        self._remove_quarantine_dir(q_dir)
        bundle_dir = q_dir / "bundle"
        bundle_dir.mkdir(parents=True, exist_ok=True)
        staged = Path(str(getattr(manifest, "staged_path", "")))
        copied = 0
        if staged.is_dir():
            for entry in getattr(manifest, "files", []):
                rel = str(getattr(entry, "relative_path", ""))
                try:
                    safe_rel = validate_bundle_rel_path(rel)
                except ValueError:
                    continue
                src = staged.joinpath(*safe_rel.split("/"))
                if not src.is_file() or is_link_like(src):
                    continue
                dest = bundle_dir.joinpath(*safe_rel.split("/"))
                dest.parent.mkdir(parents=True, exist_ok=True)
                if not dest.resolve().is_relative_to(bundle_dir.resolve()):
                    continue
                try:
                    shutil.copy2(src, dest)
                    copied += 1
                except OSError:
                    continue
        report = {
            "skill_id": skill_id,
            "name": name,
            "bundle_digest": getattr(manifest, "bundle_digest", ""),
            "reason": reason,
            "quarantined_at": utc_now_iso(),
            "files_copied": copied,
            "verification": verification,
        }
        (q_dir / "verification.json").write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")
        return q_dir

    def list_quarantined(self) -> list[dict]:
        items = []
        if not self.quarantine_root.exists():
            return items
        for entry in sorted(self.quarantine_root.iterdir()):
            if is_link_like(entry) or not entry.is_dir():
                continue
            for report_name in ("security_assessment.json", "verification.json"):
                report_file = entry / report_name
                if not report_file.is_file():
                    continue
                try:
                    data = json.loads(report_file.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    break
                if report_name == "verification.json":
                    verification = data.get("verification", {})
                    data.setdefault("verdict", verification.get("assurance_state", "UNKNOWN"))
                    data.setdefault("extension_id", data.get("skill_id", entry.name))
                items.append(data)
                break
        return items


def format_security_report(assessment: SecurityAssessment) -> str:
    """Format a human-readable security report for CLI output."""
    lines = [
        f"Security Scan Report: {assessment.extension_id}",
        f"  Source / Trust : {assessment.source} ({assessment.trust_level})",
        f"  Content Hash   : {assessment.content_hash or 'n/a'}",
        f"  Scanner        : {assessment.scanner_version}",
        f"  Verdict        : {assessment.verdict}",
    ]
    if assessment.findings:
        lines.append(f"  Findings ({len(assessment.findings)}):")
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for f in sorted(assessment.findings, key=lambda x: (order.get(x.severity, 4), x.file, x.line)):
            lines.append(
                f"    [{f.severity.upper():8s}] {f.category:18s} {f.file}:{f.line} -> {f.reason}"
            )
            lines.append(f"               Match: {redact_secrets(f.match)[:80]}")
    else:
        lines.append("  Findings       : None (0 policy violations detected)")

    if assessment.ast_findings:
        lines.append(f"  AST Audit Hints ({len(assessment.ast_findings)}):")
        for af in assessment.ast_findings[:10]:
            lines.append(f"    [AST:{af['severity'].upper()}] {af['file']}:{af['line']} {af['pattern_id']} - {af['reason']}")

    if assessment.policy_reason:
        lines.append(f"  Policy Decision: {assessment.policy_reason}")
    if assessment.quarantine_path:
        lines.append(f"  Quarantined At : {assessment.quarantine_path}")
    return "\n".join(lines)
