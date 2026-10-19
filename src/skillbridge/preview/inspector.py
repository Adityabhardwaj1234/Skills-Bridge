"""Non-executing candidate preview and deep inspection engine."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from skillbridge.cache.database import CatalogDatabase
from skillbridge.config import SkillBridgeConfig
from skillbridge.discovery.engine import DiscoveryEngine
from skillbridge.discovery.normalizer import (
    extract_referenced_support_paths,
    parse_skill_md,
    validate_skill_frontmatter,
)
from skillbridge.models import (
    CandidatePreview,
    DependencySpec,
    ExtensionBundle,
    ExtensionRecord,
    ExtensionType,
    SecurityVerdict,
)
from skillbridge.security.policy import QuarantineManager, TrustPolicyEngine
from skillbridge.security.scanner import SCANNER_VERSION, scan_bundle


class CandidateInspector:
    """Inspects and previews extension candidates without executing any code."""

    def __init__(
        self,
        discovery: DiscoveryEngine,
        config: Optional[SkillBridgeConfig] = None,
        db: Optional[CatalogDatabase] = None,
    ):
        self.discovery = discovery
        self.config = config or discovery.config
        self.db = db or discovery.db
        self.policy_engine = TrustPolicyEngine(self.config.security_policy)
        self.quarantine = QuarantineManager(self.config.quarantine_dir)

    def _check_missing_dependencies(self, deps: List[DependencySpec]) -> List[str]:
        missing: List[str] = []
        for dep in deps:
            if not dep.required:
                continue
            if dep.kind == "executable":
                if shutil.which(dep.name) is None:
                    missing.append(f"executable:{dep.name}")
            elif dep.kind == "env_var":
                if not os.environ.get(dep.name):
                    missing.append(f"env:{dep.name}")
            elif dep.kind == "python_package":
                import importlib.util

                pkg_mod = dep.name.split("[")[0].split("=")[0].split(">")[0].split("<")[0].strip().replace("-", "_")
                if importlib.util.find_spec(pkg_mod) is None:
                    missing.append(f"python_package:{dep.name}")
        return missing

    def preview_candidate(
        self,
        extension_id_or_record: str | ExtensionRecord,
        *,
        target_client: Optional[str] = None,
    ) -> Optional[CandidatePreview]:
        """Perform a complete, non-executing preview of a skill, agent, or MCP server candidate."""
        if isinstance(extension_id_or_record, ExtensionRecord):
            rec = extension_id_or_record
            ext_id = rec.extension_id
        else:
            ext_id = extension_id_or_record
            rec = self.discovery.resolve_extension(ext_id)

        bundle = self.discovery.fetch_bundle(ext_id)
        if not rec and not bundle:
            return None
        if not rec and bundle:
            rec = bundle.record or ExtensionRecord(
                extension_id=bundle.extension_id,
                name=bundle.name,
                display_name=bundle.name,
                extension_type=bundle.extension_type,
                description="Discovered extension bundle",
                source_provider=bundle.source_provider,
                trust_level=bundle.trust_level,
                content_hash=bundle.content_hash,
            )

        assert rec is not None
        limitations: List[str] = []
        frontmatter: Dict[str, Any] = {}
        body_excerpt = ""
        full_body_chars = 0
        estimated_tokens = 0
        referenced_files: List[str] = []
        available_files: List[str] = []
        missing_references: List[str] = []
        scripts_detected: List[str] = []
        c_hash = rec.content_hash

        if bundle:
            c_hash = bundle.content_hash or rec.content_hash
            available_files = sorted(bundle.files.keys())
            for f_path in available_files:
                if Path(f_path).suffix.lower() in (".py", ".sh", ".bash", ".js", ".ts", ".ps1", ".rb"):
                    scripts_detected.append(f_path)

            if "SKILL.md" in bundle.files:
                raw_md = bundle.files["SKILL.md"]
                md_text = raw_md.decode("utf-8-sig", errors="replace") if isinstance(raw_md, bytes) else raw_md
                frontmatter, body = parse_skill_md(md_text)
                full_body_chars = len(md_text)
                estimated_tokens = max(1, full_body_chars // 4)
                body_excerpt = body[:600].strip()

                fm_issues = validate_skill_frontmatter(frontmatter)
                for issue in fm_issues:
                    limitations.append(f"Frontmatter note: {issue}")

                refs = extract_referenced_support_paths(md_text)
                if refs is None:
                    limitations.append("Suspicious path traversal detected in SKILL.md relative links")
                else:
                    referenced_files = sorted(refs)
                    for ref in referenced_files:
                        if ref not in bundle.files:
                            missing_references.append(ref)
                        else:
                            ref_content = bundle.files[ref]
                            ref_len = len(ref_content)
                            estimated_tokens += ref_len // 4
                    if missing_references:
                        limitations.append(f"Missing {len(missing_references)} referenced support file(s): {', '.join(missing_references[:5])}")
            elif rec.extension_type == ExtensionType.MCP_SERVER.value:
                full_body_chars = len(rec.description)
                estimated_tokens = 250  # Typical MCP tool schema overhead
                body_excerpt = rec.description
        else:
            # Metadata-only catalog entry (upstream content not fetched / offline)
            full_body_chars = len(rec.description)
            estimated_tokens = max(50, len(rec.description) // 3)
            body_excerpt = rec.description
            limitations.append(
                "Full SKILL.md bundle not available locally/offline; preview constructed from catalog metadata."
            )

        # Security scan (content-hash cached in SQLite)
        security = self.db.get_cached_security_scan(rec.extension_id, c_hash, SCANNER_VERSION) if c_hash else None
        if security is None:
            if bundle:
                security = scan_bundle(bundle)
                alters_or_code = bool(scripts_detected) or rec.extension_type == ExtensionType.MCP_SERVER.value
                self.policy_engine.evaluate(security, alters_config_or_runs_code=alters_or_code)
                if security.verdict == SecurityVerdict.DANGEROUS.value:
                    self.quarantine.quarantine_bundle(bundle, security)
                self.db.save_security_scan(security)
            else:
                from skillbridge.models import SecurityAssessment

                security = SecurityAssessment(
                    extension_id=rec.extension_id,
                    name=rec.name,
                    source=rec.source_provider,
                    trust_level=rec.trust_level,
                    verdict=SecurityVerdict.SAFE.value if rec.trust_level == "builtin" else SecurityVerdict.UNKNOWN.value,
                    content_hash=c_hash,
                    policy_reason="Metadata-only entry (full bundle not fetched)",
                )

        current_platform = sys.platform
        platform_compatible = (
            not rec.platforms
            or current_platform in rec.platforms
            or any(current_platform.startswith(p) for p in rec.platforms)
        )
        if not platform_compatible:
            limitations.append(f"Incompatible with current platform '{current_platform}' (supports: {rec.platforms})")

        if target_client and target_client not in rec.compatible_clients:
            limitations.append(f"Target client '{target_client}' not in compatible_clients {rec.compatible_clients}")

        missing_deps = self._check_missing_dependencies(rec.dependencies)
        if missing_deps:
            limitations.append(f"Unresolved dependencies: {', '.join(missing_deps)}")

        return CandidatePreview(
            extension_id=rec.extension_id,
            name=rec.name,
            extension_type=rec.extension_type,
            source_provider=rec.source_provider,
            trust_level=rec.trust_level,
            description=rec.description,
            frontmatter=frontmatter,
            body_excerpt=body_excerpt,
            full_body_chars=full_body_chars,
            estimated_tokens=estimated_tokens,
            referenced_files=referenced_files,
            available_files=available_files,
            missing_references=missing_references,
            scripts_detected=scripts_detected,
            dependencies=rec.dependencies,
            missing_dependencies=missing_deps,
            compatible_platforms=rec.platforms,
            compatible_clients=rec.compatible_clients,
            platform_compatible=platform_compatible,
            security=security,
            limitations=limitations,
            provenance_uri=rec.canonical_uri or rec.source_path,
            content_hash=c_hash,
        )
