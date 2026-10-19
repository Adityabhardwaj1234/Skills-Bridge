# SPDX-License-Identifier: Apache-2.0 AND MIT
# Portions adapted from NVIDIA SkillSpector (https://github.com/NVIDIA/SkillSpector,
# commit 95a52d89fa16f608f0b18ccee76b0918ea4b7eef) under Apache License 2.0.
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# Modified for Python 3.11+ compatibility and normalized SkillBridge v2 integration.

"""Tier 1 deterministic security scanner and NVIDIA SkillSpector contract parser."""

from __future__ import annotations

import ast
import json
from pathlib import Path
import re
from typing import Any
import uuid

from skillbridge.bundles.manager import BundleManifest
from skillbridge.security.policy import redact_secrets
from skillbridge.security.scanner import scan_directory
from skillbridge.verification.models import (
    NORMALIZED_SCHEMA_VERSION,
    SKILLSPECTOR_PINNED_COMMIT,
    SKILLSPECTOR_PINNED_VERSION,
    AssuranceState,
    DependencyEvidence,
    NormalizedFinding,
    NormalizedScanReport,
    utc_now_iso,
)

_WILDCARD_GRANTS = {"*", "all", "any", "mcp:*", "*:*"}

_RECONSTRUCTED_INJECTION_PATTERNS = [
    (
        "AE6",
        "HIGH",
        "Obfuscated newline-split instruction concealing behavior from user",
        re.compile(
            r"never\s+warn\s+the\s+user|do\s+not\s+tell\s+the\s+user|ignore\s+all\s+previous\s+instructions",
            re.I,
        ),
    ),
]

_CONFUSABLE_CHARS = set("\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0456\u03b1\u03bf\u03c1")


class _LexicalTaintTracker(ast.NodeVisitor):
    """Lexical-scope taint and callable-alias analyzer (TT1-TT6 & SKIL CallableIdentity)."""

    def __init__(self, rel_path: str, source_lines: list[str]) -> None:
        self.rel_path = rel_path
        self.source_lines = source_lines
        self.findings: list[NormalizedFinding] = []
        self._func_returns_taint: dict[str, bool] = {}
        self._func_params: dict[str, list[str]] = {}
        self._func_sink_params: dict[str, set[int]] = {}
        self._scope_stack: list[dict[str, str]] = [{}]
        self._alias_stack: list[dict[str, str]] = [{}]

    def _current_taint(self) -> dict[str, str]:
        return self._scope_stack[-1]

    def _current_aliases(self) -> dict[str, str]:
        return self._alias_stack[-1]

    def _expr_taint_source(self, node: ast.AST | None) -> str | None:
        if node is None:
            return None
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in self._current_taint():
                return self._current_taint()[sub.id]
            if isinstance(sub, ast.Attribute):
                if isinstance(sub.value, ast.Name) and sub.value.id == "os" and sub.attr == "environ":
                    return "env_var(os.environ)"
            if isinstance(sub, ast.Call):
                call_name = self._resolve_call_identity(sub.func)
                if call_name in ("os.getenv", "os.environ.get"):
                    return f"env_var({call_name})"
                if call_name in ("open", "pathlib.Path.read_text", "Path.read_text"):
                    src_seg = self._line_snippet(getattr(sub, "lineno", 1))
                    if any(s in src_seg for s in (".ssh", ".aws", ".env", "passwd", "credentials", "token", "secret")):
                        return f"credential_file({call_name})"
                if call_name in self._func_returns_taint and self._func_returns_taint[call_name]:
                    return f"tainted_return({call_name})"
        return None

    def _resolve_call_identity(self, func_node: ast.AST) -> str:
        raw = ""
        if isinstance(func_node, ast.Name):
            raw = func_node.id
        elif isinstance(func_node, ast.Attribute):
            parts: list[str] = [func_node.attr]
            curr = func_node.value
            while isinstance(curr, ast.Attribute):
                parts.append(curr.attr)
                curr = curr.value
            if isinstance(curr, ast.Name):
                base = self._current_aliases().get(curr.id, curr.id)
                parts.append(base)
            raw = ".".join(reversed(parts))
        return self._current_aliases().get(raw, raw)

    def _line_snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return redact_secrets(self.source_lines[lineno - 1].strip()[:180])
        return ""

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.asname:
                self._current_aliases()[alias.asname] = alias.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        for alias in node.names:
            bound = alias.asname or alias.name
            self._current_aliases()[bound] = f"{mod}.{alias.name}" if mod else alias.name

    def visit_Assign(self, node: ast.Assign) -> None:
        alias_target: str | None = None
        if isinstance(node.value, (ast.Name, ast.Attribute)):
            resolved = self._resolve_call_identity(node.value)
            if any(
                resolved.startswith(prefix)
                for prefix in ("subprocess.", "os.system", "os.popen", "eval", "exec", "urllib.", "requests.", "httpx.")
            ):
                alias_target = resolved

        taint_src = self._expr_taint_source(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if alias_target:
                    self._current_aliases()[target.id] = alias_target
                else:
                    self._current_aliases().pop(target.id, None)

                if taint_src:
                    self._current_taint()[target.id] = taint_src
                else:
                    self._current_taint().pop(target.id, None)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._scope_stack.append(dict(self._current_taint()))
        self._alias_stack.append(dict(self._current_aliases()))
        params = [a.arg for a in node.args.args]
        self._func_params[node.name] = params
        for idx, p_name in enumerate(params):
            self._current_taint()[p_name] = f"__param__:{idx}:{p_name}"

        for stmt in node.body:
            self.visit(stmt)
            if isinstance(stmt, ast.Return):
                ret_taint = self._expr_taint_source(stmt.value)
                if ret_taint and not ret_taint.startswith("__param__:"):
                    self._func_returns_taint[node.name] = True

        self._scope_stack.pop()
        self._alias_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        call_id = self._resolve_call_identity(node.func)
        lineno = getattr(node, "lineno", 1)

        if call_id in ("subprocess.run", "subprocess.Popen", "subprocess.call", "os.system", "os.popen"):
            has_shell_true = any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            ) or call_id in ("os.system", "os.popen")
            if has_shell_true:
                self.findings.append(
                    NormalizedFinding(
                        finding_id=f"finding-{uuid.uuid4().hex[:12]}",
                        rule_id="BA1_ALIAS_SHELL_EXEC",
                        severity="HIGH",
                        confidence=0.9,
                        category="Behavioral AST",
                        description=f"Resolved callable `{call_id}` executes shell commands (`shell=True` or `os.system`).",
                        file_path=self.rel_path,
                        start_line=lineno,
                        evidence=self._line_snippet(lineno),
                        remediation="Invoke subprocesses with argument lists and shell=False.",
                        engine_id="skillspector",
                        engine_revision=SKILLSPECTOR_PINNED_COMMIT[:12],
                    )
                )

        is_net_sink = any(
            s in call_id
            for s in (
                "urlopen",
                "requests.post",
                "requests.get",
                "requests.put",
                "httpx.post",
                "httpx.get",
                "socket.sendall",
            )
        )
        is_exec_sink = call_id in ("eval", "exec", "os.system", "subprocess.run", "subprocess.Popen")

        for idx, arg in enumerate(node.args):
            taint = self._expr_taint_source(arg)
            if not taint:
                continue
            if taint.startswith("__param__:"):
                parts = taint.split(":")
                param_idx = int(parts[1])
                for fn_name, fn_params in self._func_params.items():
                    if param_idx < len(fn_params) and fn_params[param_idx] == parts[2]:
                        self._func_sink_params.setdefault(fn_name, set()).add(param_idx)
                continue

            if is_net_sink:
                self.findings.append(
                    NormalizedFinding(
                        finding_id=f"finding-{uuid.uuid4().hex[:12]}",
                        rule_id="TT1",
                        severity="CRITICAL",
                        confidence=0.95,
                        category="Behavioral Taint Tracking",
                        description=f"Tainted data from `{taint}` flows into outbound network sink `{call_id}`.",
                        file_path=self.rel_path,
                        start_line=lineno,
                        evidence=self._line_snippet(lineno),
                        remediation="Do not transmit environment secrets or credential files over network sockets.",
                        engine_id="skillspector",
                        engine_revision=SKILLSPECTOR_PINNED_COMMIT[:12],
                    )
                )
            elif is_exec_sink:
                self.findings.append(
                    NormalizedFinding(
                        finding_id=f"finding-{uuid.uuid4().hex[:12]}",
                        rule_id="TT2",
                        severity="HIGH",
                        confidence=0.9,
                        category="Behavioral Taint Tracking",
                        description=f"Tainted data from `{taint}` flows into execution sink `{call_id}`.",
                        file_path=self.rel_path,
                        start_line=lineno,
                        evidence=self._line_snippet(lineno),
                        remediation="Validate and sanitize inputs before passing to execution sinks.",
                        engine_id="skillspector",
                        engine_revision=SKILLSPECTOR_PINNED_COMMIT[:12],
                    )
                )
            elif call_id in self._func_sink_params and idx in self._func_sink_params[call_id]:
                self.findings.append(
                    NormalizedFinding(
                        finding_id=f"finding-{uuid.uuid4().hex[:12]}",
                        rule_id="TT3",
                        severity="CRITICAL",
                        confidence=0.92,
                        category="Behavioral Taint Tracking",
                        description=f"Tainted data from `{taint}` passed via helper function `{call_id}()` into sink.",
                        file_path=self.rel_path,
                        start_line=lineno,
                        evidence=self._line_snippet(lineno),
                        remediation="Remove inter-procedural credential exfiltration flow.",
                        engine_id="skillspector",
                        engine_revision=SKILLSPECTOR_PINNED_COMMIT[:12],
                    )
                )

        self.generic_visit(node)


def run_builtin_tier1_skillspector(manifest: BundleManifest) -> NormalizedScanReport:
    """Run the built-in Apache-2.0 SkillSpector-compatible Tier 1 analyzer suite on a staged bundle."""
    started_at = utc_now_iso()
    staged_root = Path(manifest.staged_path)
    findings: list[NormalizedFinding] = []
    checks_run = [
        "artifact_integrity",
        "static_patterns_prompt_injection",
        "static_patterns_data_exfiltration",
        "static_patterns_privilege_escalation",
        "static_patterns_supply_chain",
        "behavioral_ast",
        "behavioral_taint_tracking",
        "unicode_confusables_and_reconstruction",
        "mcp_least_privilege",
        "mcp_tool_poisoning",
    ]
    checks_skipped: list[str] = ["semantic_llm_analyzers (--no-llm static-only profile)"]
    limitations: list[str] = []
    analysis_complete = True

    if not manifest.tier0_passed:
        for v in manifest.tier0_violations:
            if "unsupported_primary_content" in v or "encoding" in v or "Missing required SKILL.md" in v:
                analysis_complete = False
                limitations.append(v)
            findings.append(
                NormalizedFinding(
                    finding_id=f"finding-{uuid.uuid4().hex[:12]}",
                    rule_id="AI1_BUNDLE_INTEGRITY",
                    severity="CRITICAL",
                    confidence=1.0,
                    category="Artifact Integrity",
                    description=v,
                    file_path="SKILL.md",
                    start_line=1,
                    evidence=v[:180],
                    remediation="Ensure bundle contains valid UTF-8 SKILL.md and no path traversal or symlinks.",
                    engine_id="skillspector",
                    engine_revision=SKILLSPECTOR_PINNED_COMMIT[:12],
                )
            )

    is_builtin = manifest.source_provider in ("hermes-bundled", "hermes-official", "builtin")
    sec_assessment = scan_directory(
        staged_root,
        source=manifest.source_provider,
        trust_level="builtin" if is_builtin else "community",
    )
    for f in sec_assessment.findings:
        sev_upper = str(f.severity).upper()
        # SkillSpector contextual triage: standard Authorization header without POST body in builtin/official skill
        if (
            is_builtin
            and str(f.pattern_id) == "env_exfil_curl"
            and "Authorization:" in str(f.match)
            and not any(flag in str(f.match) for flag in ("-d ", "--data", "-F ", "webhook.site", "ngrok"))
        ):
            sev_upper = "MEDIUM"
        elif is_builtin and sev_upper == "HIGH" and str(f.file).startswith("references/"):
            sev_upper = "LOW"
        findings.append(
            NormalizedFinding(
                finding_id=f"finding-{uuid.uuid4().hex[:12]}",
                rule_id=str(f.pattern_id).upper(),
                severity=sev_upper,
                confidence=0.9 if str(f.severity).upper() in ("CRITICAL", "HIGH") else 0.7,
                category=str(f.category),
                description=str(f.reason),
                file_path=str(f.file),
                start_line=int(f.line or 1),
                evidence=redact_secrets(str(f.match)),
                remediation=str(f.remediation or "Review and remove unsafe pattern before importing bundle."),
                engine_id="skillspector",
                engine_revision=SKILLSPECTOR_PINNED_COMMIT[:12],
            )
        )

    for file_entry in manifest.files:
        fpath = staged_root / file_entry.relative_path
        if not fpath.exists() or not file_entry.encoding_valid:
            if not file_entry.encoding_valid:
                analysis_complete = False
                limitations.append(f"Uninterpretable encoding in {file_entry.relative_path}")
            continue
        if file_entry.classification in ("binary", "archive"):
            continue

        text = fpath.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()

        single_word_lines = [ln.strip() for ln in lines if ln.strip() and len(ln.strip().split()) <= 2]
        if len(single_word_lines) >= 4:
            reconstructed = " ".join(single_word_lines)
            for rule_id, sev, desc, pat in _RECONSTRUCTED_INJECTION_PATTERNS:
                m = pat.search(reconstructed)
                if m:
                    findings.append(
                        NormalizedFinding(
                            finding_id=f"finding-{uuid.uuid4().hex[:12]}",
                            rule_id=rule_id,
                            severity=sev,
                            confidence=0.85,
                            category="Obfuscated Instruction Reconstruction",
                            description=desc,
                            file_path=file_entry.relative_path,
                            start_line=1,
                            evidence=redact_secrets(m.group(0)),
                            remediation="Remove newline-split obfuscated prompt instructions.",
                            engine_id="skillspector",
                            engine_revision=SKILLSPECTOR_PINNED_COMMIT[:12],
                        )
                    )

        for idx, ln in enumerate(lines, start=1):
            if any(ch in _CONFUSABLE_CHARS for ch in ln):
                findings.append(
                    NormalizedFinding(
                        finding_id=f"finding-{uuid.uuid4().hex[:12]}",
                        rule_id="UC1_UNICODE_CONFUSABLE",
                        severity="MEDIUM",
                        confidence=0.75,
                        category="Unicode Confusables",
                        description="Line contains Cyrillic/Greek homoglyph characters that can spoof identifiers.",
                        file_path=file_entry.relative_path,
                        start_line=idx,
                        evidence=redact_secrets(ln.strip()[:140]),
                        remediation="Replace homoglyph characters with standard ASCII.",
                        engine_id="skillspector",
                        engine_revision=SKILLSPECTOR_PINNED_COMMIT[:12],
                    )
                )

        if file_entry.classification == "python":
            try:
                tree = ast.parse(text)
                tracker = _LexicalTaintTracker(file_entry.relative_path, lines)
                tracker.visit(tree)
                findings.extend(tracker.findings)
            except SyntaxError as exc:
                analysis_complete = False
                limitations.append(f"Python syntax error in {file_entry.relative_path}: {exc}")

    for cap in manifest.declared_capabilities:
        cap_lower = cap.strip().lower()
        if cap_lower in _WILDCARD_GRANTS:
            findings.append(
                NormalizedFinding(
                    finding_id=f"finding-{uuid.uuid4().hex[:12]}",
                    rule_id="LP1_WILDCARD_GRANT",
                    severity="HIGH",
                    confidence=0.95,
                    category="MCP Least Privilege",
                    description=f"Skill declares overly broad wildcard tool grant `{cap}` (violates B.3.1 least privilege).",
                    file_path="SKILL.md",
                    start_line=1,
                    evidence=f"allowed-tools: {cap}",
                    remediation="Specify only the exact minimal tools required by the skill.",
                    engine_id="skillspector",
                    engine_revision=SKILLSPECTOR_PINNED_COMMIT[:12],
                )
            )

    dep_evidence: list[DependencyEvidence] = []
    for rel_manifest, pkgs in manifest.declared_dependencies.items():
        eco = "pypi" if rel_manifest.endswith(("requirements.txt", "pyproject.toml")) else "npm"
        for pkg in pkgs:
            pinned = "==" in pkg or re.search(r"@\d+\.\d+\.\d+", pkg) is not None
            dep_evidence.append(
                DependencyEvidence(
                    manifest_path=rel_manifest,
                    ecosystem=eco,
                    package_name=pkg.split("=")[0].split(">")[0].split("<")[0].split("@")[0].strip(),
                    version_spec=pkg,
                    pinned=pinned,
                )
            )

    deduped: dict[str, NormalizedFinding] = {}
    for f in findings:
        deduped.setdefault(f.dedup_fingerprint, f)
    final_findings = list(deduped.values())

    has_blocking = any(f.severity == "CRITICAL" for f in final_findings) or (
        not is_builtin and any(f.severity == "HIGH" for f in final_findings)
    )
    if has_blocking:
        assurance = AssuranceState.UNSAFE
        exit_code = 1
    elif not analysis_complete:
        assurance = AssuranceState.UNKNOWN
        exit_code = 2
    else:
        assurance = AssuranceState.SAFE
        exit_code = 0

    return NormalizedScanReport(
        schema_version=NORMALIZED_SCHEMA_VERSION,
        scan_id=f"t1-spector-{uuid.uuid4().hex[:10]}",
        artifact_id=manifest.skill_id,
        artifact_digest=manifest.bundle_digest,
        engine_id="skillspector",
        engine_version=SKILLSPECTOR_PINNED_VERSION,
        engine_revision=SKILLSPECTOR_PINNED_COMMIT[:12],
        scan_profile="static-no-llm",
        scan_started_at=started_at,
        scan_completed_at=utc_now_iso(),
        scan_status="completed" if analysis_complete else "incomplete",
        analysis_complete=analysis_complete,
        checks_run=checks_run,
        checks_skipped=checks_skipped,
        limitations=limitations,
        findings=final_findings,
        dependency_evidence=dep_evidence,
        report_artifacts={
            "risk_assessment": {
                "score": min(
                    100,
                    sum(40 if f.severity == "CRITICAL" else 25 if f.severity == "HIGH" else 10 for f in final_findings),
                ),
                "recommendation": assurance.value,
            },
            "analysis_completeness": {
                "total_components": manifest.total_files,
                "scanned_components": manifest.total_files if analysis_complete else max(0, manifest.total_files - 1),
                "is_complete": analysis_complete,
                "status": "complete" if analysis_complete else "incomplete",
            },
        },
        exit_code=exit_code,
        assurance_state=assurance,
    )


def parse_skillspector_cli_json(
    raw_json: str,
    *,
    artifact_id: str,
    artifact_digest: str,
    exit_code: int,
    started_at: str,
) -> NormalizedScanReport:
    """Parse real NVIDIA SkillSpector CLI JSON output (`skillspector scan <path> --format json`)."""
    try:
        payload = json.loads(raw_json)
    except Exception as exc:
        return NormalizedScanReport(
            schema_version=NORMALIZED_SCHEMA_VERSION,
            scan_id=f"t1-spector-{uuid.uuid4().hex[:10]}",
            artifact_id=artifact_id,
            artifact_digest=artifact_digest,
            engine_id="skillspector-cli",
            engine_version=SKILLSPECTOR_PINNED_VERSION,
            engine_revision=SKILLSPECTOR_PINNED_COMMIT[:12],
            scan_profile="external-cli",
            scan_started_at=started_at,
            scan_completed_at=utc_now_iso(),
            scan_status="failed",
            analysis_complete=False,
            limitations=[f"Invalid JSON from skillspector CLI: {exc}"],
            exit_code=exit_code or 2,
            assurance_state=AssuranceState.UNKNOWN,
        )

    completeness = payload.get("analysis_completeness", {})
    is_complete = bool(completeness.get("is_complete", payload.get("execution_successful", False)))
    if exit_code not in (0, 1):
        is_complete = False

    meta = payload.get("metadata", {})
    version = str(meta.get("skillspector_version") or SKILLSPECTOR_PINNED_VERSION)

    checks_run: list[str] = []
    checks_skipped: list[str] = []
    limitations: list[str] = []
    for st in completeness.get("analyzer_statuses", []):
        aid = str(st.get("analyzer_id", "unknown"))
        status = str(st.get("status", ""))
        if status == "completed":
            checks_run.append(aid)
        elif status in ("not_applicable", "skipped"):
            checks_skipped.append(f"{aid} ({st.get('reason_code', status)})")
        else:
            is_complete = False
            limitations.append(f"Analyzer {aid} status={status}: {st.get('message', '')}")

    for exc_row in completeness.get("ledger_exceptions", []):
        limitations.append(f"Ledger exception ({exc_row.get('reason')}): {exc_row.get('path', '')}")

    findings: list[NormalizedFinding] = []
    for issue in payload.get("issues", []):
        loc = issue.get("location") or {}
        findings.append(
            NormalizedFinding(
                finding_id=str(issue.get("finding_id") or f"finding-{uuid.uuid4().hex[:12]}"),
                rule_id=str(issue.get("id") or "UNKNOWN"),
                severity=str(issue.get("severity") or "MEDIUM").upper(),
                confidence=float(issue.get("confidence", 0.5)),
                category=str(issue.get("category") or "Security"),
                description=str(issue.get("explanation") or issue.get("pattern") or ""),
                file_path=str(loc.get("file") or ""),
                start_line=int(loc.get("start_line") or 1),
                end_line=loc.get("end_line"),
                evidence=redact_secrets(str(issue.get("code_snippet") or issue.get("finding") or "")),
                remediation=str(issue.get("remediation") or ""),
                engine_id="skillspector-cli",
                engine_revision=version,
                dedup_fingerprint=str(issue.get("match_fingerprint") or ""),
            )
        )

    risk = payload.get("risk_assessment") or {}
    rec = str(risk.get("recommendation") or "").upper()
    has_high = any(f.severity in ("CRITICAL", "HIGH") for f in findings) or rec in ("DANGEROUS", "BLOCK", "UNSAFE")

    if has_high or exit_code == 1:
        assurance = AssuranceState.UNSAFE
    elif not is_complete or exit_code >= 2:
        assurance = AssuranceState.UNKNOWN
    else:
        assurance = AssuranceState.SAFE

    return NormalizedScanReport(
        schema_version=NORMALIZED_SCHEMA_VERSION,
        scan_id=f"t1-spector-{uuid.uuid4().hex[:10]}",
        artifact_id=artifact_id,
        artifact_digest=artifact_digest,
        engine_id="skillspector-cli",
        engine_version=version,
        engine_revision=SKILLSPECTOR_PINNED_COMMIT[:12],
        scan_profile="external-cli",
        scan_started_at=started_at,
        scan_completed_at=utc_now_iso(),
        scan_status="completed" if is_complete else "incomplete",
        analysis_complete=is_complete,
        checks_run=checks_run,
        checks_skipped=checks_skipped,
        limitations=limitations,
        findings=findings,
        report_artifacts={"raw_skillspector": payload},
        exit_code=exit_code,
        assurance_state=assurance,
    )
