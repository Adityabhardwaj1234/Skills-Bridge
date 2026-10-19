"""Dependency inspector, installation planner, atomic deployer, and rollback manager."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from skillbridge.adapters.clients import (
    ClaudeCodeAdapter,
    ClientAdapter,
    OpenCodeAdapter,
    atomic_write_text,
)
from skillbridge.cache.database import CatalogDatabase
from skillbridge.config import SkillBridgeConfig
from skillbridge.discovery.engine import DiscoveryEngine
from skillbridge.models import (
    DependencySpec,
    ExtensionBundle,
    ExtensionRecord,
    ExtensionType,
    InstallPlan,
    SecurityVerdict,
    utc_now_iso,
)
from skillbridge.security.policy import (
    QuarantineManager,
    TrustPolicyEngine,
    redact_secrets,
)
from skillbridge.security.scanner import SCANNER_VERSION, scan_bundle


class DependencyInspector:
    """Inspects runtime executables, Python packages, environment variables, and OS compatibility safely.

    Never executes package-provided scripts to discover behavior; uses subprocess argument arrays with timeouts
    only for standard toolchain version checks (`python`, `node`, `npm`, `git`, `uv`).
    """

    SAFE_VERSION_PROBES = {"python", "python3", "pip", "node", "npm", "npx", "uv", "uvx", "git", "gh", "opencode", "claude"}

    def inspect_dependencies(self, dependencies: List[DependencySpec], platforms: Optional[List[str]] = None) -> Tuple[List[Dict[str, Any]], List[str]]:
        results: List[Dict[str, Any]] = []
        missing: List[str] = []

        # 1. Check OS platform
        if platforms:
            os_ok = sys.platform in platforms or any(sys.platform.startswith(p) for p in platforms)
            results.append(
                {
                    "kind": "os",
                    "name": sys.platform,
                    "required": True,
                    "satisfied": os_ok,
                    "details": f"Current={sys.platform}, Supported={platforms}",
                }
            )
            if not os_ok:
                missing.append(f"os:{sys.platform} (requires {platforms})")

        for dep in dependencies:
            if dep.kind == "executable":
                exe_path = shutil.which(dep.name)
                ver_info = ""
                if exe_path and dep.name in self.SAFE_VERSION_PROBES:
                    try:
                        proc = subprocess.run(
                            [exe_path, "--version"],
                            capture_output=True,
                            text=True,
                            timeout=3.0,
                            shell=False,
                            check=False,
                        )
                        ver_info = redact_secrets((proc.stdout or proc.stderr or "").splitlines()[0].strip()) if (proc.stdout or proc.stderr) else ""
                    except (OSError, subprocess.SubprocessError):
                        ver_info = "found"
                satisfied = exe_path is not None
                results.append(
                    {
                        "kind": "executable",
                        "name": dep.name,
                        "required": dep.required,
                        "satisfied": satisfied,
                        "installed_version": ver_info,
                        "path": exe_path,
                    }
                )
                if dep.required and not satisfied:
                    missing.append(f"executable:{dep.name}")

            elif dep.kind == "python_package":
                pkg_base = dep.name.split("[")[0].split("=")[0].split(">")[0].split("<")[0].strip()
                installed_ver = None
                try:
                    installed_ver = importlib.metadata.version(pkg_base)
                except importlib.metadata.PackageNotFoundError:
                    spec = importlib.util.find_spec(pkg_base.replace("-", "_"))
                    if spec is not None:
                        installed_ver = "installed"
                satisfied = installed_ver is not None
                results.append(
                    {
                        "kind": "python_package",
                        "name": dep.name,
                        "required": dep.required,
                        "satisfied": satisfied,
                        "installed_version": installed_ver,
                    }
                )
                if dep.required and not satisfied:
                    missing.append(f"python_package:{dep.name}")

            elif dep.kind == "env_var":
                present = bool(os.environ.get(dep.name))
                results.append(
                    {
                        "kind": "env_var",
                        "name": dep.name,
                        "required": dep.required,
                        "satisfied": present,
                        "secret": dep.secret,
                        "details": "set (redacted)" if present else "unset (will use env reference in config)",
                    }
                )
                # Note: missing env vars are noted for post-install configuration, not hard runtime blockers for planning
                if dep.required and not present:
                    missing.append(f"env:{dep.name}")

        return results, missing


class InstallationManager:
    """Plans, previews, applies, verifies, and rolls back extensions across OpenCode and Claude Code."""

    def __init__(
        self,
        discovery: DiscoveryEngine,
        config: Optional[SkillBridgeConfig] = None,
        db: Optional[CatalogDatabase] = None,
        project_root: Optional[Path] = None,
        user_home: Optional[Path] = None,
    ):
        self.discovery = discovery
        self.config = config or discovery.config
        self.db = db or discovery.db
        self.policy_engine = TrustPolicyEngine(self.config.security_policy)
        self.quarantine = QuarantineManager(self.config.quarantine_dir)
        self.dep_inspector = DependencyInspector()

        self.project_root = Path(project_root or self.config.project_root)
        self.user_home = Path(user_home or Path.home())

        self.adapters: Dict[str, ClientAdapter] = {
            "opencode": OpenCodeAdapter(self.config, project_root=self.project_root, user_home=self.user_home),
            "claude-code": ClaudeCodeAdapter(self.config, project_root=self.project_root, user_home=self.user_home),
        }

    def get_adapter(self, target_client: str) -> ClientAdapter:
        key = target_client.strip().lower()
        if key not in self.adapters:
            raise ValueError(f"Unsupported target client '{target_client}'. Supported: {list(self.adapters.keys())}")
        return self.adapters[key]

    def plan_install(
        self,
        extension_id: str,
        target_client: str,
        *,
        scope: str = "project",
        dry_run: bool = True,
        approved: bool = False,
        extension_type_override: Optional[str] = None,
        lazy_disable_globally: bool = False,
    ) -> InstallPlan:
        """Create a validated installation plan with security scan, dependency check, and exact file diffs."""
        adapter = self.get_adapter(target_client)
        if scope not in ("project", "user"):
            raise ValueError(f"Invalid scope '{scope}'. Must be 'project' or 'user'.")

        rec = self.discovery.resolve_extension(extension_id)
        bundle = self.discovery.fetch_bundle(extension_id)
        if not rec and not bundle:
            raise ValueError(f"Extension '{extension_id}' could not be resolved from any catalog.")
        if not rec and bundle:
            rec = bundle.record or ExtensionRecord(
                extension_id=bundle.extension_id,
                name=bundle.name,
                display_name=bundle.name,
                extension_type=bundle.extension_type,
                description="Discovered extension",
                source_provider=bundle.source_provider,
                trust_level=bundle.trust_level,
                content_hash=bundle.content_hash,
            )
        assert rec is not None
        ext_type = extension_type_override or rec.extension_type

        # Run security scan on the bundle
        if bundle is None:
            bundle = ExtensionBundle(
                extension_id=rec.extension_id,
                name=rec.name,
                extension_type=ext_type,
                source_provider=rec.source_provider,
                trust_level=rec.trust_level,
                files={},
                record=rec,
            )

        security = scan_bundle(bundle)
        has_scripts = any(Path(k).suffix.lower() in (".py", ".sh", ".bash", ".js", ".ts") for k in bundle.files)
        alters_or_code = has_scripts or ext_type == ExtensionType.MCP_SERVER.value or scope == "user"
        allowed, requires_approval, policy_reason = self.policy_engine.evaluate(
            security,
            approved=approved,
            alters_config_or_runs_code=alters_or_code,
        )

        if security.verdict == SecurityVerdict.DANGEROUS.value:
            self.quarantine.quarantine_bundle(bundle, security)
        self.db.save_security_scan(security)

        dep_checks, missing_deps = self.dep_inspector.inspect_dependencies(rec.dependencies, rec.platforms)

        plan_id = f"plan_{uuid.uuid4().hex[:12]}"
        backup_dir = self.config.backups_dir / plan_id

        writes: List[Dict[str, Any]] = []
        diff_text = ""
        unpreserved: List[str] = []
        blocked = False
        block_reason = ""

        if security.verdict == SecurityVerdict.DANGEROUS.value or allowed is False and not requires_approval:
            blocked = True
            block_reason = policy_reason
        else:
            try:
                if ext_type == ExtensionType.SKILL.value:
                    writes, diff_text, unpreserved = adapter.plan_skill_install(bundle, scope=scope)
                elif ext_type == ExtensionType.AGENT.value:
                    writes, diff_text, unpreserved = adapter.plan_agent_install(bundle, scope=scope)
                elif ext_type == ExtensionType.MCP_SERVER.value:
                    writes, diff_text, unpreserved = adapter.plan_mcp_install(
                        rec, scope=scope, lazy_disable_globally=lazy_disable_globally
                    )
                else:
                    raise ValueError(f"Unsupported extension type '{ext_type}'")
            except ValueError as exc:
                blocked = True
                block_reason = str(exc)

        plan = InstallPlan(
            plan_id=plan_id,
            extension_id=rec.extension_id,
            extension_name=rec.name,
            extension_type=ext_type,
            target_client=adapter.CLIENT_ID,
            scope=scope,
            dry_run=dry_run,
            requires_approval=requires_approval,
            approved=approved,
            blocked=blocked,
            block_reason=block_reason if blocked else (policy_reason if requires_approval and not approved else ""),
            security_assessment=security,
            dependency_checks=dep_checks,
            missing_dependencies=missing_deps,
            planned_file_writes=writes,
            planned_config_diff=diff_text,
            backup_dir=str(backup_dir),
            unpreserved_fields=unpreserved,
            status="blocked" if blocked else "planned",
        )
        self.db.save_install_plan(plan)
        self.db.log_audit(
            "plan_install",
            provider=adapter.CLIENT_ID,
            extension_id=rec.extension_id,
            verdict=security.verdict,
            details={"plan_id": plan_id, "scope": scope, "dry_run": dry_run, "blocked": blocked},
        )
        return plan

    def apply_install(self, plan_or_id: str | InstallPlan, *, approved: bool = False, overwrite_custom: bool = False) -> Dict[str, Any]:
        """Apply a planned installation with backups, atomic writes, and post-install verification.

        Never applies a DANGEROUS or blocked plan, even if approved=True is passed.
        """
        plan = self.db.get_install_plan(plan_or_id) if isinstance(plan_or_id, str) else plan_or_id
        if plan is None:
            raise ValueError(f"Install plan '{plan_or_id}' not found.")

        if plan.security_assessment and plan.security_assessment.verdict == SecurityVerdict.DANGEROUS.value:
            raise PermissionError(
                f"Cannot apply install plan '{plan.plan_id}': extension '{plan.extension_id}' has a DANGEROUS security verdict."
            )
        if plan.blocked:
            raise PermissionError(f"Cannot apply blocked install plan '{plan.plan_id}': {plan.block_reason}")
        if plan.requires_approval and not (plan.approved or approved):
            raise PermissionError(
                f"Install plan '{plan.plan_id}' requires explicit approval (--approve / approved=True): {plan.block_reason}"
            )

        backup_root = Path(plan.backup_dir)
        backup_root.mkdir(parents=True, exist_ok=True)
        manifest_entries: List[Dict[str, Any]] = []

        try:
            for item in plan.planned_file_writes:
                target_path = Path(item["path"])
                existed = target_path.exists()
                if existed and plan.extension_type in (ExtensionType.SKILL.value, ExtensionType.AGENT.value) and not overwrite_custom:
                    # Avoid silently overwriting existing custom skill/agent files unless overwrite_custom is True
                    backup_copy = backup_root / f"file_{len(manifest_entries)}"
                    shutil.copy2(target_path, backup_copy)
                    manifest_entries.append({"target_path": str(target_path), "existed": True, "backup_file": str(backup_copy)})
                elif existed:
                    backup_copy = backup_root / f"file_{len(manifest_entries)}"
                    shutil.copy2(target_path, backup_copy)
                    manifest_entries.append({"target_path": str(target_path), "existed": True, "backup_file": str(backup_copy)})
                else:
                    manifest_entries.append({"target_path": str(target_path), "existed": False, "backup_file": None})

                atomic_write_text(target_path, item["content"])

            (backup_root / "backup_manifest.json").write_text(
                json.dumps({"plan_id": plan.plan_id, "files": manifest_entries}, indent=2) + "\n",
                encoding="utf-8",
            )

            adapter = self.get_adapter(plan.target_client)
            verification = adapter.verify_installation(plan.extension_name, plan.extension_type, scope=plan.scope)
            if not verification.get("discoverable"):
                self.rollback(plan.plan_id)
                raise RuntimeError(f"Post-install verification failed ({verification.get('reason')}); rolled back automatically.")

            plan.dry_run = False
            plan.approved = plan.approved or approved
            plan.status = "applied"
            plan.applied_at = utc_now_iso()
            self.db.save_install_plan(plan)
            self.db.log_audit(
                "apply_install",
                provider=plan.target_client,
                extension_id=plan.extension_id,
                verdict="APPLIED",
                details={"plan_id": plan.plan_id, "scope": plan.scope, "verification": verification},
            )
            return {
                "plan_id": plan.plan_id,
                "status": "applied",
                "target_client": plan.target_client,
                "scope": plan.scope,
                "files_written": [w["path"] for w in plan.planned_file_writes],
                "backup_dir": plan.backup_dir,
                "verification": verification,
            }
        except Exception:
            if (backup_root / "backup_manifest.json").exists():
                self.rollback(plan.plan_id)
            raise

    def rollback(self, plan_id: str) -> Dict[str, Any]:
        """Restore files from the transaction backup created during apply_install."""
        plan = self.db.get_install_plan(plan_id)
        if plan is None:
            raise ValueError(f"Install plan '{plan_id}' not found.")
        backup_root = Path(plan.backup_dir)
        manifest_file = backup_root / "backup_manifest.json"
        if not manifest_file.is_file():
            raise ValueError(f"No backup manifest found for plan '{plan_id}' at {manifest_file}")

        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        restored: List[str] = []
        removed: List[str] = []

        for entry in reversed(manifest.get("files", [])):
            target = Path(entry["target_path"])
            if entry.get("existed") and entry.get("backup_file"):
                b_file = Path(entry["backup_file"])
                if b_file.is_file():
                    atomic_write_text(target, b_file.read_text(encoding="utf-8"))
                    restored.append(str(target))
            else:
                if target.is_file():
                    target.unlink()
                    removed.append(str(target))
                # Clean up empty skill directory if created
                if target.parent.is_dir() and not any(target.parent.iterdir()):
                    try:
                        target.parent.rmdir()
                    except OSError:
                        pass

        plan.status = "rolled_back"
        self.db.save_install_plan(plan)
        self.db.log_audit(
            "rollback_install",
            provider=plan.target_client,
            extension_id=plan.extension_id,
            verdict="ROLLED_BACK",
            details={"plan_id": plan_id, "restored": restored, "removed": removed},
        )
        return {
            "plan_id": plan_id,
            "status": "rolled_back",
            "restored_files": restored,
            "removed_files": removed,
        }
