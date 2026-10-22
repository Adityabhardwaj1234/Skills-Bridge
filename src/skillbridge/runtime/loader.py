"""Just-in-time skill loader, 13-state bundle importer, 25-skill cap, 250 MiB memory-pressure evictor, and session isolation manager."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
import gc
import hashlib
import json
from pathlib import Path
import re
import shutil
import threading
import time
from typing import Any, AsyncIterator, Dict, Iterator, List, Optional, Set, Tuple
import uuid

from skillbridge.bundles.manager import BundleIntegrityError, BundleManifest, BundleStager
from skillbridge.cache.database import CatalogDatabase
from skillbridge.config import SkillBridgeConfig
from skillbridge.discovery.engine import DiscoveryEngine
from skillbridge.discovery.normalizer import (
    compute_bundle_content_hash,
    compute_directory_content_hash,
    extract_referenced_support_paths,
    is_link_like,
    parse_skill_md,
    validate_bundle_rel_path,
)
from skillbridge.models import (
    ExtensionBundle,
    ExtensionType,
    RuntimeSkillHandle,
    SecurityVerdict,
    utc_now_iso,
)
from skillbridge.runtime.memory import (
    FakeMemoryProvider,
    MemoryProvider,
    MemorySnapshot,
    SystemMemoryProvider,
    compute_directory_disk_bytes,
)
from skillbridge.runtime.scripts import (
    ScriptExecutionManager,
    ScriptExecutionResult,
)
from skillbridge.security.policy import QuarantineManager, TrustPolicyEngine
from skillbridge.security.scanner import SCANNER_VERSION, scan_bundle
from skillbridge.settings import RuntimeSettings
from skillbridge.verification.adapters import VerificationCoordinator
from skillbridge.verification.models import (
    AssuranceState,
    ImportState,
    MultiTierVerificationResult,
)


class SkillLoadError(RuntimeError):
    """Raised when a skill cannot be safely loaded into runtime memory."""


class SkillLoadSecurityError(SkillLoadError):
    """Raised when a skill is rejected or quarantined by the security scanner or trust policy."""


# Python/JS local module import patterns used to discover sibling helper scripts that a
# SKILL.md may not reference directly (e.g. `scripts/_raster.py` imported by `scripts/pdf_page_image.py`).
_PY_IMPORT_RE = re.compile(r"^\s*(?:from|import)\s+(?P<mod>\.?[A-Za-z_][A-Za-z0-9_.]*)", re.MULTILINE)
_JS_IMPORT_RE = re.compile(
    r"""(?:^|\s)(?:import\s+(?:[^'"]+\s+from\s+)?|require\s*\(\s*|import\s*\(\s*)['"](?P<spec>\.{1,2}/[^'"]+)['"]""",
    re.MULTILINE,
)
_JS_EXTENSIONS = (".js", ".ts", ".mjs", ".cjs", ".json")


@dataclass
class ActiveBundleEntry:
    """Tracks an imported whole-directory skill bundle in the v2 runtime registry."""

    skill_id: str
    session_id: str
    bundle_digest: str
    staged_dir: str
    manifest: BundleManifest
    verification: MultiTierVerificationResult
    handle: RuntimeSkillHandle
    import_state: ImportState
    state_history: list[str] = field(default_factory=list)
    loaded_at_monotonic: float = field(default_factory=time.monotonic)
    last_accessed_monotonic: float = field(default_factory=time.monotonic)
    access_count: int = 1
    in_use: bool = False
    pinned: bool = False

    def transition(self, next_state: ImportState) -> None:
        self.import_state = next_state
        self.state_history.append(next_state.value)

    def touch(self) -> None:
        self.last_accessed_monotonic = time.monotonic()
        self.access_count += 1


class SkillRuntimeLoader:
    """Manages just-in-time loading, 13-state bundle import, 25-skill cap, 250 MiB eviction, and unloading.

    Guarantees:
    - Session Isolation: Active skills are keyed by `session_id`; one session/task cannot read or inherit
      another session's active skill bodies.
    - Content-Hash Invalidation: Re-computes content hash on load; if a local or cached skill changed on disk,
      prior scan cache is invalidated and a fresh security scan runs before loading.
    - Bounded Payload: Enforces configurable file size, total byte budget, reference count, nesting depth,
      and file extension limits. Local helper modules imported by referenced scripts are auto-included so
      fetched bundles remain runnable.
    - Parallel Batch Loading: `load_skills_parallel` loads multiple skills concurrently through a bounded
      worker pool while preserving per-skill isolation and thread-safe session state.
    - Explicit & Automatic Unloading: `unload_skill(session_id, skill_id)` and `unload_session(session_id)` purge
      in-memory instruction bodies, reference maps, and session deduplication digests, freeing Python object references.
    """

    def __init__(
        self,
        discovery: DiscoveryEngine,
        config: Optional[SkillBridgeConfig] = None,
        db: Optional[CatalogDatabase] = None,
        *,
        settings: Optional[RuntimeSettings] = None,
        memory_provider: Optional[MemoryProvider] = None,
        verification_coordinator: Optional[VerificationCoordinator] = None,
    ):
        self.discovery = discovery
        self.config = config or discovery.config
        self.db = db or discovery.db
        self.settings = settings or RuntimeSettings()
        self.memory_provider: MemoryProvider = memory_provider or SystemMemoryProvider()
        self.coordinator = verification_coordinator or VerificationCoordinator()
        self.policy_engine = TrustPolicyEngine(self.config.security_policy)
        self.quarantine = QuarantineManager(self.config.quarantine_dir)

        import os, tempfile
        uid_tag = str(os.getuid()) if hasattr(os, "getuid") else "user"
        # Distinct --home directories must never share runtime staging, even when they have the
        # same folder name (a common case with temporary homes). Hash the resolved absolute path.
        home_key = str(self.config.home_dir.expanduser().resolve())
        home_tag = hashlib.sha256(home_key.encode("utf-8")).hexdigest()[:12]
        staging_root = (
            Path(tempfile.gettempdir())
            / f"skillbridge_runtime_{uid_tag}"
            / f"{self.config.home_dir.name}-{home_tag}"
        )
        if is_link_like(staging_root) or is_link_like(staging_root.parent):
            raise RuntimeError(
                f"Runtime staging path '{staging_root}' is a symlink/junction; refusing to write through it. "
                "Remove the link and retry."
            )
        staging_root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(staging_root, 0o700)
        except OSError:
            pass
        self._cleanup_stale_staging(staging_root)
        self.bundle_stager = BundleStager(
            quarantine_staging_dir=staging_root / "quarantine_staging",
            active_staging_dir=staging_root / "active_staging",
            max_files=self.settings.bundle_max_files,
            max_total_bytes=self.settings.bundle_max_total_bytes,
            max_single_file_bytes=self.settings.bundle_max_single_file_bytes,
            max_depth=self.settings.bundle_max_depth,
        )
        self.script_manager = ScriptExecutionManager(self.settings)

        self._lock = threading.RLock()
        # session_id -> {extension_id -> RuntimeSkillHandle}
        self._active_sessions: Dict[str, Dict[str, RuntimeSkillHandle]] = {}
        # session_id -> {(extension_id, content_hash) -> digest}
        self._session_dedup: Dict[str, Dict[Tuple[str, str], str]] = {}
        # Historical unload counter for observability verification
        self._unload_events: List[Dict[str, Any]] = []
        # v2 active bundle registry: extension_id -> ActiveBundleEntry
        self._active_bundles: Dict[str, ActiveBundleEntry] = {}
        # v2 last access timestamp for session handles: (session_id, extension_id) -> monotonic float
        self._handle_last_access: Dict[Tuple[str, str], float] = {}
        self._pinned_skills: set[str] = set()
        self._in_use_skills: set[str] = set()
        self._retained_import_history: Dict[str, Dict[str, Any]] = {}
        self._eviction_events: List[Dict[str, Any]] = []

    @staticmethod
    def _cleanup_stale_staging(staging_root: Path, max_age_seconds: int = 24 * 3600) -> None:
        """Best-effort GC for abandoned process-local staging directories."""
        now = time.time()
        for parent_name in ("active_staging", "quarantine_staging"):
            parent = staging_root / parent_name
            if not parent.is_dir() or is_link_like(parent):
                continue
            try:
                children = list(parent.iterdir())
            except OSError:
                continue
            for child in children:
                try:
                    if is_link_like(child) or not child.is_dir():
                        continue
                    if now - child.stat().st_mtime > max_age_seconds:
                        shutil.rmtree(child, ignore_errors=True)
                except OSError:
                    continue

    def get_active_handles(self, session_id: str) -> List[RuntimeSkillHandle]:
        """Return currently active RuntimeSkillHandles for a specific isolated session."""
        with self._lock:
            session_map = self._active_sessions.get(session_id, {})
            return [h for h in session_map.values() if h.active]

    def find_active_handle(self, skill_id: str) -> Optional[Tuple[str, RuntimeSkillHandle]]:
        """Resolve an active handle by exact ID, qualified ID, or skill name.

        Returns ``(session_id, handle)`` for the first match, or ``None`` when the skill is
        not currently loaded in any session. Keep this in sync with the session summary so
        status queries never report a loaded skill as inactive.
        """
        target = (skill_id or "").strip().lower().rstrip("/")
        if not target:
            return None
        bare = target.rsplit("/", 1)[-1]
        with self._lock:
            for session_id, handles in self._active_sessions.items():
                for ext_id, handle in handles.items():
                    if not handle.active:
                        continue
                    candidates = {
                        ext_id.lower().rstrip("/"),
                        handle.extension_id.lower().rstrip("/"),
                        handle.name.lower().rstrip("/"),
                    }
                    if target in candidates:
                        return session_id, handle
                    if any(c.rsplit("/", 1)[-1] == bare for c in candidates):
                        return session_id, handle
        return None

    def active_skill_count(self) -> int:
        """Return total number of simultaneously active skills across sessions and bundle registry."""
        with self._lock:
            active_ids: set[str] = set(self._active_bundles.keys())
            for handles in self._active_sessions.values():
                for ext_id, h in handles.items():
                    if h.active:
                        active_ids.add(ext_id)
            return len(active_ids)

    def current_loaded_payload_bytes(self) -> int:
        with self._lock:
            total = 0
            seen: set[str] = set()
            for handles in self._active_sessions.values():
                for ext_id, h in handles.items():
                    if h.active and ext_id not in seen:
                        total += h.total_bytes
                        seen.add(ext_id)
            for ext_id, b in self._active_bundles.items():
                if ext_id not in seen and b.handle.active:
                    total += b.handle.total_bytes
                    seen.add(ext_id)
            return total

    def get_memory_snapshot(self, active_mcp_processes: int = 0) -> MemorySnapshot:
        """Measure process-tree RSS, loaded payload bytes, staged disk usage, and capacity counts."""
        active_count = self.active_skill_count()
        payload_bytes = self.current_loaded_payload_bytes()
        if isinstance(self.memory_provider, FakeMemoryProvider):
            self.memory_provider.sync_runtime_state(active_count, payload_bytes)

        self_rss, child_rss, _, src_label = self.memory_provider.get_process_and_children_rss_bytes()
        total_rss = self_rss + child_rss
        total_mib = round(total_rss / (1024.0 * 1024.0), 3)
        disk_bytes = compute_directory_disk_bytes(self.bundle_stager.active_staging_dir)

        with self._lock:
            in_use_count = len(self._in_use_skills) + sum(
                1 for b in self._active_bundles.values() if b.in_use and b.skill_id not in self._in_use_skills
            )
            pinned_count = len(self._pinned_skills) + sum(
                1 for b in self._active_bundles.values() if b.pinned and b.skill_id not in self._pinned_skills
            )

        return MemorySnapshot(
            process_rss_bytes=self_rss,
            child_rss_bytes=child_rss,
            total_process_tree_bytes=total_rss,
            total_process_tree_mib=total_mib,
            loaded_payload_bytes=payload_bytes,
            staged_bundle_disk_bytes=disk_bytes,
            active_skill_count=active_count,
            in_use_skill_count=in_use_count,
            pinned_skill_count=pinned_count,
            active_worker_processes=self.script_manager.active_workers,
            active_mcp_processes=active_mcp_processes,
            threshold_mib=self.settings.memory_threshold_mib,
            target_watermark_mib=self.settings.memory_target_mib,
            over_threshold=(total_mib >= self.settings.memory_threshold_mib),
            genuine_unrelieved_pressure=False,
            measurement_source=src_label,
        )

    def on_settings_updated(self, old_settings: RuntimeSettings, new_settings: RuntimeSettings) -> List[str]:
        """Handle live runtime settings updates, safely evicting eligible skills if active_skill_limit dropped."""
        self.settings = new_settings
        self.script_manager.settings = new_settings
        evicted: List[str] = []
        if self.active_skill_count() > self.settings.active_skill_limit:
            needed = self.active_skill_count() - self.settings.active_skill_limit
            evicted = self._evict_lru_skills(
                count=needed,
                reason=f"active_skill_limit reduced from {old_settings.active_skill_limit} to {new_settings.active_skill_limit}",
            )
        self.check_and_handle_memory_pressure()
        return evicted

    def _resolve_active_bundle_key(self, skill_id: str) -> Optional[str]:
        with self._lock:
            if skill_id in self._active_bundles:
                return skill_id
            low = skill_id.strip().lower()
            for k, entry in self._active_bundles.items():
                if k.lower() == low or entry.manifest.name.lower() == low or k.lower().endswith(f"/{low}"):
                    return k
            return None

    def resolve_active_bundle_id(self, skill_id: str) -> Optional[str]:
        """Public, read-only resolution of an imported bundle identifier."""
        return self._resolve_active_bundle_key(skill_id)

    def session_holds_skill(self, skill_id: str, *, exclude_session: Optional[str] = None) -> bool:
        """Return True when any live session (optionally excluding one) still holds this skill."""
        resolved = self._resolve_active_bundle_key(skill_id) or skill_id
        low = resolved.strip().lower()
        with self._lock:
            for sid, handles in self._active_sessions.items():
                if exclude_session is not None and sid == exclude_session:
                    continue
                for key, handle in handles.items():
                    if getattr(handle, "active", False) and (
                        key.lower() == low
                        or getattr(handle, "extension_id", "").lower() == low
                        or getattr(handle, "name", "").lower() == low.split("/")[-1]
                    ):
                        return True
        return False

    def pin_skill(self, extension_id: str, pinned: bool = True) -> bool:
        with self._lock:
            if pinned:
                self._pinned_skills.add(extension_id)
            else:
                self._pinned_skills.discard(extension_id)
            if extension_id in self._active_bundles:
                self._active_bundles[extension_id].pinned = pinned
            return True

    def set_skill_in_use(self, extension_id: str, in_use: bool) -> bool:
        with self._lock:
            if in_use:
                self._in_use_skills.add(extension_id)
            else:
                self._in_use_skills.discard(extension_id)
            if extension_id in self._active_bundles:
                self._active_bundles[extension_id].in_use = in_use
                if in_use:
                    self._active_bundles[extension_id].touch()
            return True

    def _get_eligible_eviction_candidates(self) -> List[Tuple[str, str]]:
        """Return list of (session_id, extension_id) ordered by least-recently-used (excluding pinned & in_use)."""
        with self._lock:
            items: List[Tuple[float, str, str]] = []
            seen_ext: set[str] = set()
            for sid, handles in self._active_sessions.items():
                for ext_id, h in handles.items():
                    if not h.active:
                        continue
                    b_entry = self._active_bundles.get(ext_id)
                    if (
                        ext_id in self._pinned_skills
                        or ext_id in self._in_use_skills
                        or (b_entry and (b_entry.pinned or b_entry.in_use))
                    ):
                        continue
                    ts = self._handle_last_access.get((sid, ext_id), 0.0)
                    if b_entry:
                        ts = max(ts, b_entry.last_accessed_monotonic)
                    items.append((ts, sid, ext_id))
                    seen_ext.add(ext_id)

            for ext_id, b_entry in self._active_bundles.items():
                if ext_id in seen_ext or b_entry.pinned or b_entry.in_use or ext_id in self._pinned_skills or ext_id in self._in_use_skills:
                    continue
                items.append((b_entry.last_accessed_monotonic, b_entry.session_id, ext_id))

            items.sort(key=lambda x: x[0])
            return [(sid, ext_id) for _, sid, ext_id in items]

    def _evict_lru_skills(self, count: int, reason: str) -> List[str]:
        candidates = self._get_eligible_eviction_candidates()
        evicted: List[str] = []
        for sid, ext_id in candidates:
            if len(evicted) >= count:
                break
            if ext_id in self._active_bundles:
                self.unload_bundle(ext_id, reason=reason)
            else:
                self.unload_skill(ext_id, session_id=sid)
            if ext_id not in evicted:
                evicted.append(ext_id)
        return evicted

    def check_and_handle_memory_pressure(self) -> Dict[str, Any]:
        """Enforce the 250 MiB threshold by evicting batches of 5-10 eligible LRU skills down to 210 MiB."""
        snap = self.get_memory_snapshot()
        if not snap.over_threshold:
            return {
                "triggered": False,
                "initial_mib": snap.total_process_tree_mib,
                "final_mib": snap.total_process_tree_mib,
                "evicted_skills": [],
                "evicted_count": 0,
                "batches_run": 0,
                "genuine_unrelieved_pressure": False,
            }

        initial_mib = snap.total_process_tree_mib
        all_evicted: List[str] = []
        batches_run = 0
        batch_size = min(
            self.settings.eviction_batch_max,
            max(self.settings.eviction_batch_min, self.settings.eviction_batch_default),
        )

        while True:
            current_snap = self.get_memory_snapshot()
            if current_snap.total_process_tree_mib <= self.settings.memory_target_mib:
                break
            eligible = self._get_eligible_eviction_candidates()
            if not eligible:
                break
            to_evict_count = min(batch_size, len(eligible))
            evicted_batch = self._evict_lru_skills(
                count=to_evict_count,
                reason=f"memory_pressure ({current_snap.total_process_tree_mib} MiB >= {self.settings.memory_threshold_mib} MiB)",
            )
            if not evicted_batch:
                break
            all_evicted.extend(evicted_batch)
            batches_run += 1

        final_snap = self.get_memory_snapshot()
        unrelieved = final_snap.total_process_tree_mib > self.settings.memory_threshold_mib

        event = {
            "triggered": True,
            "initial_mib": initial_mib,
            "final_mib": final_snap.total_process_tree_mib,
            "target_watermark_mib": self.settings.memory_target_mib,
            "evicted_skills": all_evicted,
            "evicted_count": len(all_evicted),
            "batches_run": batches_run,
            "genuine_unrelieved_pressure": unrelieved,
        }
        with self._lock:
            self._eviction_events.append(event)
        self.db.log_audit(
            "memory_pressure_eviction",
            verdict="unrelieved_pressure" if unrelieved else "relieved",
            details=event,
        )
        return event

    def import_skill_bundle(
        self,
        extension_id: str,
        *,
        session_id: str = "default",
        pin: bool = False,
        approved: bool = False,
    ) -> ActiveBundleEntry:
        """Execute the exact 13-state skill bundle import lifecycle (Section 7)."""
        limits = self.config.loader_limits
        state_history: List[str] = [
            ImportState.DISCOVERED.value,
            ImportState.PREVIEWED.value,
            ImportState.SELECTED.value,
        ]

        # Enforce 25-skill active limit prior to importing a new bundle
        if extension_id not in self._active_bundles and self.active_skill_count() >= self.settings.active_skill_limit:
            needed = (self.active_skill_count() - self.settings.active_skill_limit) + 1
            evicted = self._evict_lru_skills(
                count=needed,
                reason=f"active_skill_limit ({self.settings.active_skill_limit}) reached prior to importing {extension_id}",
            )
            if self.active_skill_count() >= self.settings.active_skill_limit and not evicted:
                raise SkillLoadError(
                    f"Cannot import '{extension_id}': active_skill_limit ({self.settings.active_skill_limit}) reached "
                    "and all active skills are currently pinned or in_use."
                )

        bundle = self.discovery.fetch_bundle(extension_id)
        if bundle is None:
            raise SkillLoadError(f"Extension '{extension_id}' could not be found in any configured provider.")

        # State 4 & 5: FETCHED_INTO_QUARANTINE -> ARTIFACT_VALIDATED (Tier 0)
        state_history.append(ImportState.FETCHED_INTO_QUARANTINE.value)
        local_src = (
            Path(bundle.record.source_path)
            if (bundle.record and bundle.record.source_path and Path(bundle.record.source_path).exists())
            else None
        )
        if local_src is not None:
            manifest = self.bundle_stager.stage_into_quarantine(
                local_src,
                skill_id=bundle.extension_id,
                source_provider=bundle.source_provider,
                source_uri=bundle.record.canonical_uri if bundle.record else bundle.extension_id,
                source_subpath=bundle.record.source_path if bundle.record else "",
                resolved_revision=getattr(bundle.record, "version_or_revision", "HEAD") if bundle.record else "HEAD",
            )
        else:
            manifest = self.bundle_stager.stage_from_files_map(
                bundle.files,
                skill_id=bundle.extension_id,
                source_provider=bundle.source_provider,
                source_uri=bundle.record.canonical_uri if bundle.record else bundle.extension_id,
                source_subpath=bundle.record.source_path if bundle.record else "",
                resolved_revision=getattr(bundle.record, "version_or_revision", "HEAD") if bundle.record else "HEAD",
            )
        state_history.append(ImportState.ARTIFACT_VALIDATED.value)

        # Loader-level payload bounds apply to every import, not just the JIT load path.
        referenced_entries = [
            f for f in manifest.files if f.is_referenced and f.relative_path != "SKILL.md"
        ]
        if len(referenced_entries) > limits.max_references:
            shutil.rmtree(Path(manifest.staged_path), ignore_errors=True)
            raise SkillLoadError(
                f"Cannot import '{extension_id}': SKILL.md references {len(referenced_entries)} support files, "
                f"exceeding max_references ({limits.max_references})."
            )
        skill_md_entry = next((f for f in manifest.files if f.relative_path == "SKILL.md"), None)
        if skill_md_entry is not None and skill_md_entry.size_bytes > limits.max_file_size_bytes:
            shutil.rmtree(Path(manifest.staged_path), ignore_errors=True)
            raise SkillLoadError(
                f"Cannot import '{extension_id}': SKILL.md ({skill_md_entry.size_bytes} bytes) exceeds "
                f"max_file_size_bytes ({limits.max_file_size_bytes})."
            )

        # State 6: TIERED_VERIFICATION (Tiers 1-3)
        state_history.append(ImportState.TIERED_VERIFICATION.value)
        verification = self.coordinator.verify_bundle(manifest, self.settings)

        # State 7: APPROVED_BY_POLICY vs REJECTED / UNKNOWN
        if not verification.allowed_to_load:
            terminal = (
                ImportState.REJECTED
                if verification.assurance_state == AssuranceState.UNSAFE
                else ImportState.UNKNOWN
            )
            state_history.append(terminal.value)
            verification.transition_history = list(state_history)
            quarantine_path = None
            try:
                quarantine_path = self.quarantine.quarantine_staged_bundle(
                    manifest,
                    verification.to_dict(),
                    reason=verification.policy_reason,
                )
            except Exception:
                quarantine_path = None
            self.db.log_audit(
                "import_skill_rejected",
                session_id=session_id,
                provider=manifest.source_provider,
                extension_id=bundle.extension_id,
                verdict=verification.assurance_state.value,
                details={
                    "bundle_digest": manifest.bundle_digest,
                    "final_state": terminal.value,
                    "reason": verification.policy_reason,
                    "quarantine_path": str(quarantine_path) if quarantine_path else None,
                },
            )
            shutil.rmtree(Path(manifest.staged_path), ignore_errors=True)
            with self._lock:
                self._retained_import_history[bundle.extension_id] = {
                    "skill_id": bundle.extension_id,
                    "name": manifest.name,
                    "version": manifest.version,
                    "source_provider": manifest.source_provider,
                    "source_uri": manifest.source_uri,
                    "bundle_digest": manifest.bundle_digest,
                    "assurance_state": verification.assurance_state.value,
                    "final_state": terminal.value,
                    "state_history": state_history,
                    "verification": verification.to_dict(),
                    "quarantine_path": str(quarantine_path) if quarantine_path else None,
                }
            if verification.assurance_state == AssuranceState.UNSAFE:
                raise SkillLoadSecurityError(verification.policy_reason)
            raise SkillLoadError(verification.policy_reason)

        state_history.append(ImportState.APPROVED_BY_POLICY.value)

        # State 8 & 9: STAGED_TEMPORARILY -> LOADED_INTO_ACTIVE_SESSION (with transactional rollback on failure)
        active_staged_dir: Optional[Path] = None
        try:
            active_staged_dir = self.bundle_stager.promote_to_active_staging(manifest, session_id=session_id)
            state_history.append(ImportState.STAGED_TEMPORARILY.value)

            skill_md_file = active_staged_dir / "SKILL.md"
            skill_md_text = skill_md_file.read_text(encoding="utf-8", errors="replace")
            frontmatter, body = parse_skill_md(skill_md_text)
            loaded_refs: Dict[str, str] = {}
            total_bytes = len(skill_md_text.encode("utf-8"))
            for f_entry in referenced_entries[: limits.max_references]:
                if f_entry.encoding_valid:
                    ref_p = active_staged_dir / f_entry.relative_path
                    if ref_p.exists() and total_bytes + f_entry.size_bytes <= limits.max_total_bytes:
                        loaded_refs[f_entry.relative_path] = ref_p.read_text(encoding="utf-8", errors="replace")
                        total_bytes += f_entry.size_bytes

            handle = RuntimeSkillHandle(
                handle_id=f"hdl_{uuid.uuid4().hex[:12]}",
                session_id=session_id,
                decision_id=verification.verification_id,
                extension_id=bundle.extension_id,
                name=manifest.name,
                source_provider=manifest.source_provider,
                trust_level=bundle.trust_level,
                content_hash=manifest.bundle_digest,
                provenance_uri=manifest.source_uri,
                skill_md_body=body,
                frontmatter=frontmatter,
                loaded_references=loaded_refs,
                total_bytes=total_bytes,
                estimated_tokens=max(1, total_bytes // 4),
                dedup_stub=False,
            )
            with self._lock:
                self._active_sessions.setdefault(session_id, {})[bundle.extension_id] = handle
                self._handle_last_access[(session_id, bundle.extension_id)] = time.monotonic()

            state_history.append(ImportState.LOADED_INTO_ACTIVE_SESSION.value)
            verification.transition_history = list(state_history)

            entry = ActiveBundleEntry(
                skill_id=bundle.extension_id,
                session_id=session_id,
                bundle_digest=manifest.bundle_digest,
                staged_dir=str(active_staged_dir),
                manifest=manifest,
                verification=verification,
                handle=handle,
                import_state=ImportState.LOADED_INTO_ACTIVE_SESSION,
                state_history=state_history,
                pinned=pin,
            )
            with self._lock:
                self._active_bundles[bundle.extension_id] = entry
                if pin:
                    self._pinned_skills.add(bundle.extension_id)

            self.check_and_handle_memory_pressure()
            if bundle.record is not None:
                bundle.record.security_verdict = verification.assurance_state.value
                bundle.record.content_hash = manifest.bundle_digest
                try:
                    self.db.upsert_extension(bundle.record)
                except Exception:
                    pass
            self.db.log_audit(
                "import_skill",
                session_id=session_id,
                provider=manifest.source_provider,
                extension_id=bundle.extension_id,
                verdict=verification.assurance_state.value,
                details={
                    "bundle_digest": manifest.bundle_digest,
                    "final_state": ImportState.LOADED_INTO_ACTIVE_SESSION.value,
                    "references_loaded": len(loaded_refs),
                    "pinned": pin,
                    "approved": approved,
                },
            )
            return entry
        except Exception:
            if active_staged_dir and active_staged_dir.exists():
                shutil.rmtree(active_staged_dir, ignore_errors=True)
            with self._lock:
                self._active_bundles.pop(bundle.extension_id, None)
            self.unload_skill(bundle.extension_id, session_id=session_id)
            raise

    def invoke_loaded_bundle(self, skill_id: str) -> RuntimeSkillHandle:
        with self._lock:
            resolved_key = self._resolve_active_bundle_key(skill_id)
            entry = self._active_bundles.get(resolved_key) if resolved_key else None
            if entry is None:
                raise SkillLoadError(f"Skill bundle '{skill_id}' is not currently imported in the active runtime.")
            entry.touch()
            entry.transition(ImportState.USED)
            return entry.handle

    def execute_bundle_script(
        self,
        skill_id: str,
        relative_script_path: str,
        arguments: Optional[List[str]] = None,
        *,
        explicit_approval: bool = False,
    ) -> ScriptExecutionResult:
        """Execute a permitted script inside an active bundle while protecting it from eviction (`in_use=True`)."""
        with self._lock:
            resolved_key = self._resolve_active_bundle_key(skill_id)
            entry = self._active_bundles.get(resolved_key) if resolved_key else None
            if entry is None or resolved_key is None:
                raise SkillLoadError(f"Skill bundle '{skill_id}' must be imported and active before running scripts.")
            skill_id = resolved_key
            entry.in_use = True
            self._in_use_skills.add(skill_id)
            entry.touch()

        try:
            res = self.script_manager.run_script(
                manifest=entry.manifest,
                verification=entry.verification,
                staged_bundle_dir=Path(entry.staged_dir),
                relative_script_path=relative_script_path,
                arguments=arguments,
                explicit_approval=explicit_approval,
                current_digest_checker=self.bundle_stager.recompute_staged_digest,
            )
            with self._lock:
                entry.transition(ImportState.SCRIPT_EXECUTED_IF_ALLOWED)
            return res
        finally:
            with self._lock:
                entry.in_use = False
                self._in_use_skills.discard(skill_id)

    def unload_bundle(self, skill_id: str, *, reason: str = "explicit_unload") -> Dict[str, Any]:
        """Transition an active bundle through UNLOADED -> TEMPORARY_FILES_REMOVED -> METADATA_AND_RESULTS_RETAINED."""
        with self._lock:
            resolved_key = self._resolve_active_bundle_key(skill_id) or skill_id
            skill_id = resolved_key
            entry = self._active_bundles.pop(skill_id, None)
            self._pinned_skills.discard(skill_id)
            self._in_use_skills.discard(skill_id)
            sess_ids = [sid for sid, m in self._active_sessions.items() if skill_id in m]

        unload_res = {"unloaded": False}
        for sid in sess_ids:
            unload_res = self.unload_skill(skill_id, session_id=sid)

        if entry is None:
            return unload_res

        entry.transition(ImportState.UNLOADED)
        staged_path = Path(entry.staged_dir)
        if staged_path.exists():
            shutil.rmtree(staged_path, ignore_errors=True)
        q_path = Path(entry.manifest.staged_path)
        if q_path.exists():
            shutil.rmtree(q_path, ignore_errors=True)
        entry.transition(ImportState.TEMPORARY_FILES_REMOVED)
        entry.transition(ImportState.METADATA_AND_RESULTS_RETAINED)

        retained = {
            "skill_id": skill_id,
            "name": entry.manifest.name,
            "version": entry.manifest.version,
            "source_provider": entry.manifest.source_provider,
            "source_uri": entry.manifest.source_uri,
            "source_subpath": entry.manifest.source_subpath,
            "bundle_digest": entry.bundle_digest,
            "closure_digest": entry.verification.closure_digest,
            "assurance_state": entry.verification.assurance_state.value,
            "quality_score": entry.verification.quality_score,
            "unload_reason": reason,
            "final_state": entry.import_state.value,
            "state_history": list(entry.state_history),
        }
        with self._lock:
            self._retained_import_history[skill_id] = retained
        gc.collect()
        return {"unloaded": True, **retained}

    def unload_all_bundles(self, *, force_pinned: bool = False) -> List[str]:
        """Unload all active bundles and sessions not currently executing work (`in_use`)."""
        with self._lock:
            keys = list(self._active_bundles.keys())
            sess_ids = list(self._active_sessions.keys())
        unloaded: List[str] = []
        for sid in keys:
            entry = self._active_bundles.get(sid)
            if entry and entry.in_use:
                continue
            if entry and entry.pinned and not force_pinned:
                continue
            res = self.unload_bundle(sid, reason="unload_all")
            if res.get("unloaded"):
                unloaded.append(sid)
        for sess_id in sess_ids:
            self.unload_session(sess_id)
        return unloaded

    def recall_skill_metadata(self, skill_id: str) -> Optional[Dict[str, Any]]:
        """Recall persisted metadata and source URI for a previously loaded/unloaded skill (Section 13)."""
        with self._lock:
            if skill_id in self._retained_import_history:
                return dict(self._retained_import_history[skill_id])
        rec = self.discovery.resolve_extension(skill_id)
        if rec is not None:
            return {
                "skill_id": rec.extension_id,
                "name": rec.name,
                "version": getattr(rec, "version_or_revision", "1.0.0"),
                "source_provider": rec.source_provider,
                "source_uri": rec.canonical_uri,
                "source_subpath": rec.source_path,
                "bundle_digest": rec.content_hash,
                "assurance_state": rec.security_verdict,
                "final_state": "CATALOG_PERSISTED",
            }
        return None

    def get_all_active_sessions_summary(self) -> Dict[str, Any]:
        """Return summary of active sessions, bundles, and memory footprint without exposing skill bodies."""
        snap = self.get_memory_snapshot()
        with self._lock:
            summary: Dict[str, Any] = {}
            for sid, handles in self._active_sessions.items():
                active_list = [h for h in handles.values() if h.active]
                if active_list:
                    summary[sid] = {
                        "active_skill_count": len(active_list),
                        "skill_ids": [h.extension_id for h in active_list],
                        "total_bytes": sum(h.total_bytes for h in active_list),
                        "estimated_tokens": sum(h.estimated_tokens for h in active_list),
                    }
            return {
                "active_sessions": summary,
                "active_bundles": list(self._active_bundles.keys()),
                "active_skill_limit": self.settings.active_skill_limit,
                "total_active_handles": sum(v["active_skill_count"] for v in summary.values()),
                "total_unloaded_handles_history": len(self._unload_events),
                "memory_snapshot": snap.to_dict(),
                "eviction_events": list(self._eviction_events),
            }

    # -------------------------------------------------------------------------
    # V1 Core Methods (Preserved 100% for backward compatibility)
    # -------------------------------------------------------------------------

    def load_skill(
        self,
        extension_id: str,
        *,
        session_id: str = "default",
        decision_id: str = "manual",
        include_references: bool = True,
        requested_references: Optional[List[str]] = None,
        allow_dedup_stub: bool = False,
        approved: bool = False,
    ) -> RuntimeSkillHandle:
        """Load a skill's SKILL.md and validated relative references into temporary session memory."""
        start = time.perf_counter()
        limits = self.config.loader_limits

        # Enforce 25-skill active limit if loading a new distinct skill
        with self._lock:
            already_active = any(extension_id in m for m in self._active_sessions.values()) or (
                extension_id in self._active_bundles
            )
        if not already_active and self.active_skill_count() >= self.settings.active_skill_limit:
            needed = (self.active_skill_count() - self.settings.active_skill_limit) + 1
            evicted = self._evict_lru_skills(
                count=needed,
                reason=f"active_skill_limit ({self.settings.active_skill_limit}) reached prior to loading {extension_id}",
            )
            if self.active_skill_count() >= self.settings.active_skill_limit and not evicted:
                raise SkillLoadError(
                    f"Cannot load '{extension_id}': active_skill_limit ({self.settings.active_skill_limit}) reached "
                    "and all active skills are pinned or in_use."
                )

        bundle = self.discovery.fetch_bundle(extension_id)
        if bundle is None or "SKILL.md" not in bundle.files:
            raise self._missing_bundle_error(extension_id)

        def _payload_size(content: str | bytes) -> int:
            return len(content if isinstance(content, bytes) else content.encode("utf-8"))

        bundle_total_bytes = sum(_payload_size(v) for v in bundle.files.values())
        if bundle_total_bytes > limits.max_total_bytes:
            raise SkillLoadError(
                f"Skill '{bundle.extension_id}' payload is {bundle_total_bytes} bytes, exceeding "
                f"max_total_bytes ({limits.max_total_bytes})."
            )
        if _payload_size(bundle.files["SKILL.md"]) > limits.max_file_size_bytes:
            raise SkillLoadError(
                f"SKILL.md in '{bundle.extension_id}' exceeds max_file_size_bytes ({limits.max_file_size_bytes})."
            )

        if bundle.extension_type != ExtensionType.SKILL.value:
            raise SkillLoadError(f"Extension '{extension_id}' is type '{bundle.extension_type}', not a loadable skill.")

        live_hash = compute_bundle_content_hash(bundle.files)
        if bundle.record and bundle.record.source_path:
            local_p = Path(bundle.record.source_path)
            if local_p.exists():
                live_hash = compute_directory_content_hash(local_p)
        bundle.content_hash = live_hash

        assessment = self.db.get_cached_security_scan(bundle.extension_id, live_hash, SCANNER_VERSION)
        if assessment is None:
            assessment = scan_bundle(bundle)
            has_scripts = any(Path(k).suffix.lower() in (".py", ".sh", ".bash", ".js", ".ts") for k in bundle.files)
            self.policy_engine.evaluate(assessment, approved=approved, alters_config_or_runs_code=has_scripts)
            if assessment.verdict == SecurityVerdict.DANGEROUS.value:
                self.quarantine.quarantine_bundle(bundle, assessment)
            self.db.save_security_scan(assessment)
        else:
            has_scripts = any(Path(k).suffix.lower() in (".py", ".sh", ".bash", ".js", ".ts") for k in bundle.files)
            self.policy_engine.evaluate(assessment, approved=approved, alters_config_or_runs_code=has_scripts)

        if assessment.verdict == SecurityVerdict.DANGEROUS.value and assessment.allowed is not True:
            raise SkillLoadSecurityError(
                f"Refusing to load skill '{bundle.extension_id}': security verdict is DANGEROUS "
                f"({len(assessment.findings)} finding(s)). Quarantined at: {assessment.quarantine_path}"
            )
        if assessment.allowed is not True:
            raise SkillLoadSecurityError(
                f"Refusing to load skill '{bundle.extension_id}': {assessment.policy_reason}"
            )

        raw_skill_md = bundle.files["SKILL.md"]
        skill_md_text = (
            raw_skill_md.decode("utf-8-sig", errors="replace") if isinstance(raw_skill_md, bytes) else raw_skill_md
        )
        md_bytes = len(skill_md_text.encode("utf-8"))
        if md_bytes > limits.max_file_size_bytes:
            raise SkillLoadError(
                f"SKILL.md in '{bundle.extension_id}' ({md_bytes} bytes) exceeds max_file_size_bytes ({limits.max_file_size_bytes})."
            )

        frontmatter, body = parse_skill_md(skill_md_text)
        if "_invalid_frontmatter" in frontmatter:
            raise SkillLoadError(
                f"Invalid SKILL.md frontmatter in '{bundle.extension_id}': {frontmatter['_invalid_frontmatter']}"
            )

        loaded_refs: Dict[str, str] = {}
        total_bytes = md_bytes

        if include_references:
            if requested_references is not None:
                candidate_refs = requested_references
            else:
                extracted = extract_referenced_support_paths(skill_md_text)
                if extracted is None:
                    raise SkillLoadSecurityError(
                        f"Rejected skill '{bundle.extension_id}': path traversal detected in SKILL.md reference links."
                    )
                candidate_refs = sorted(extracted)

            local_root = (
                Path(bundle.record.source_path).resolve()
                if (bundle.record and bundle.record.source_path and Path(bundle.record.source_path).exists())
                else None
            )

            for ref_rel in candidate_refs[: limits.max_references]:
                try:
                    safe_rel = validate_bundle_rel_path(ref_rel, allow_nested=True, max_depth=limits.max_nesting_depth)
                except ValueError as exc:
                    raise SkillLoadSecurityError(
                        f"Unsafe reference path '{ref_rel}' in '{bundle.extension_id}': {exc}"
                    ) from exc

                ext = Path(safe_rel).suffix.lower()
                if ext and ext not in limits.allowed_extensions:
                    continue

                if local_root is not None:
                    cand_file = local_root / safe_rel
                    if is_link_like(cand_file):
                        target = cand_file.resolve()
                        if not target.is_relative_to(local_root):
                            raise SkillLoadSecurityError(
                                f"Reference symlink/junction '{safe_rel}' escapes skill root '{local_root}'."
                            )
                    if cand_file.exists() and not cand_file.resolve().is_relative_to(local_root):
                        raise SkillLoadSecurityError(
                            f"Reference path '{safe_rel}' escapes skill root '{local_root}'."
                        )

                if safe_rel not in bundle.files:
                    continue

                raw_ref = bundle.files[safe_rel]
                ref_text = raw_ref.decode("utf-8-sig", errors="replace") if isinstance(raw_ref, bytes) else raw_ref
                ref_bytes = len(ref_text.encode("utf-8"))
                if ref_bytes > limits.max_file_size_bytes:
                    continue
                if total_bytes + ref_bytes > limits.max_total_bytes:
                    break
                loaded_refs[safe_rel] = ref_text
                total_bytes += ref_bytes

            # Auto-include local helper modules imported by loaded scripts (e.g. scripts/_raster.py)
            # when references were discovered from SKILL.md links rather than explicitly requested.
            if requested_references is None:
                loaded_refs, total_bytes = self._augment_with_local_helper_modules(bundle, loaded_refs, total_bytes)

        if self.config.enable_content_cache:
            cache_dest = self.config.content_cache_dir / f"{bundle.name}-{live_hash.replace('sha256:', '')}.json"
            try:
                cache_dest.write_text(
                    json.dumps(
                        {"extension_id": bundle.extension_id, "hash": live_hash, "files": list(bundle.files.keys())}
                    ),
                    encoding="utf-8",
                )
            except OSError:
                pass

        with self._lock:
            dedup_map = self._session_dedup.setdefault(session_id, {})
            dedup_key = (bundle.extension_id, live_hash)
            payload_digest = hashlib.sha256(skill_md_text.encode("utf-8")).hexdigest()

            if allow_dedup_stub and dedup_map.get(dedup_key) == payload_digest:
                stub_body = (
                    f"[Skill '{bundle.name}' ({live_hash}) unchanged since earlier load in session '{session_id}'; "
                    "refer to prior loaded instructions in this session.]"
                )
                handle = RuntimeSkillHandle(
                    handle_id=f"hdl_{uuid.uuid4().hex[:12]}",
                    session_id=session_id,
                    decision_id=decision_id,
                    extension_id=bundle.extension_id,
                    name=bundle.name,
                    source_provider=bundle.source_provider,
                    trust_level=bundle.trust_level,
                    content_hash=live_hash,
                    provenance_uri=bundle.record.canonical_uri if bundle.record else bundle.extension_id,
                    skill_md_body=stub_body,
                    frontmatter=frontmatter,
                    loaded_references={},
                    total_bytes=len(stub_body.encode("utf-8")),
                    estimated_tokens=max(1, len(stub_body) // 4),
                    dedup_stub=True,
                )
            else:
                dedup_map[dedup_key] = payload_digest
                handle = RuntimeSkillHandle(
                    handle_id=f"hdl_{uuid.uuid4().hex[:12]}",
                    session_id=session_id,
                    decision_id=decision_id,
                    extension_id=bundle.extension_id,
                    name=bundle.name,
                    source_provider=bundle.source_provider,
                    trust_level=bundle.trust_level,
                    content_hash=live_hash,
                    provenance_uri=bundle.record.canonical_uri if bundle.record else bundle.extension_id,
                    skill_md_body=body,
                    frontmatter=frontmatter,
                    loaded_references=loaded_refs,
                    total_bytes=total_bytes,
                    estimated_tokens=max(1, total_bytes // 4),
                    dedup_stub=False,
                )
            self._active_sessions.setdefault(session_id, {})[bundle.extension_id] = handle
            self._handle_last_access[(session_id, bundle.extension_id)] = time.monotonic()

        elapsed_ms = (time.perf_counter() - start) * 1000.0
        self.db.log_audit(
            "load_skill",
            session_id=session_id,
            provider=bundle.source_provider,
            extension_id=bundle.extension_id,
            verdict=assessment.verdict,
            elapsed_ms=elapsed_ms,
            details={
                "handle_id": handle.handle_id,
                "content_hash": live_hash,
                "total_bytes": handle.total_bytes,
                "references_loaded": len(loaded_refs),
                "dedup_stub": handle.dedup_stub,
            },
        )
        pressure = self.check_and_handle_memory_pressure()
        with self._lock:
            still_active = self._active_sessions.get(session_id, {}).get(bundle.extension_id) is handle
        if not still_active and pressure.get("triggered"):
            # Better an explicit, actionable failure than returning a handle whose payload was
            # immediately evicted by the memory governor.
            raise SkillLoadError(
                f"'{bundle.extension_id}' was evicted immediately after loading because process memory "
                f"({pressure.get('final_mib')} MiB) is above memory_threshold_mib "
                f"({self.settings.memory_threshold_mib}). Raise the threshold or reduce the index/cache footprint."
            )
        return handle

    def _nearby_skill_hints(self, extension_id: str, limit: int = 3) -> List[str]:
        """Return a few catalog IDs close to a failed lookup, for actionable error messages."""
        segment = extension_id.strip().rstrip("/").rsplit("/", 1)[-1].strip()
        query = re.sub(r"[^A-Za-z0-9]+", " ", segment).strip()
        if not query or len(query) < 3:
            return []
        try:
            hits = self.db.search_extensions(query, limit=10)
        except Exception:
            return []
        token = segment.lower().replace("-", "").replace("_", "")
        hints: List[str] = []
        for rec in hits:
            flat_id = rec.extension_id.lower().replace("-", "").replace("_", "")
            flat_name = rec.name.lower().replace("-", "").replace("_", "")
            if token and (token in flat_id or token == flat_name or token in flat_name):
                if rec.extension_id != extension_id:
                    hints.append(rec.extension_id)
            if len(hints) >= limit:
                break
        return hints

    @staticmethod
    def _display_identifier(value: str, limit: int = 120) -> str:
        """Keep user-controlled IDs from flooding logs/CLI output with huge echoes."""
        text = str(value)
        return text if len(text) <= limit else f"{text[: limit - 3]}..."

    def _missing_bundle_error(self, extension_id: str) -> SkillLoadError:
        """Build a precise error explaining why a bundle could not be materialized for loading."""
        display_id = self._display_identifier(extension_id)
        rec = None
        try:
            rec = self.discovery.resolve_extension(extension_id)
        except Exception:
            rec = None
        if rec is None:
            hints = self._nearby_skill_hints(extension_id)
            hint_text = f" Closest catalog matches: {', '.join(hints)}." if hints else ""
            return SkillLoadError(
                f"Extension '{display_id}' could not be found or has no SKILL.md bundle.{hint_text} "
                "Run 'search-skills <keywords>' to discover catalog IDs; imported local folders use the "
                "'local-custom/<directory-name>' ID format."
            )
        network_only_providers = {
            "github", "skills.sh", "clawhub", "browse-sh", "lobehub", "hermes-index", "mcp-registry", "smithery",
        }
        if rec.source_provider in network_only_providers:
            if self.config.network.offline_mode:
                return SkillLoadError(
                    f"Extension '{display_id}' is a remote '{rec.source_provider}' index record with no locally "
                    f"cached bundle. It requires a live fetch ({rec.canonical_uri or 'upstream provider'}); offline "
                    "mode is enabled — rerun without --offline or pre-seed a cached index/bundle."
                )
            return SkillLoadError(
                f"Extension '{display_id}' is a remote '{rec.source_provider}' index record and its bundle could "
                f"not be fetched ({rec.canonical_uri or 'upstream provider'}). The record may be stale or the "
                "provider unreachable; try search-skills to refresh the catalog."
            )
        return SkillLoadError(
            f"Extension '{display_id}' resolved to '{rec.source_provider}' but has no SKILL.md bundle "
            f"(canonical: {rec.canonical_uri or 'n/a'})."
        )

    @staticmethod
    def _local_module_candidates(importer_rel: str, text: str) -> List[str]:
        """Return bundle-relative candidate paths for local modules imported by a script."""
        base_dir = str(Path(importer_rel).parent).replace("\\", "/")
        if base_dir == ".":
            base_dir = ""
        candidates: List[str] = []
        for match in _PY_IMPORT_RE.finditer(text):
            mod = match.group("mod").lstrip(".")
            if not mod:
                continue
            root = mod.split(".")[0]
            if not root.isidentifier():
                continue
            candidates.append(f"{base_dir}/{root}.py".lstrip("/"))
            candidates.append(f"{base_dir}/{root}/__init__.py".lstrip("/"))
        for match in _JS_IMPORT_RE.finditer(text):
            spec = match.group("spec").replace("\\", "/")
            joined = f"{base_dir}/{spec}" if base_dir else spec
            parts: List[str] = []
            for seg in joined.split("/"):
                if seg in ("", "."):
                    continue
                if seg == "..":
                    if parts:
                        parts.pop()
                    continue
                parts.append(seg)
            rel = "/".join(parts)
            if not rel:
                continue
            candidates.append(rel)
            for ext in _JS_EXTENSIONS:
                candidates.append(f"{rel}{ext}")
                candidates.append(f"{rel}/index{ext}")
        return candidates

    def _augment_with_local_helper_modules(
        self,
        bundle: ExtensionBundle,
        loaded_refs: Dict[str, str],
        total_bytes: int,
    ) -> Tuple[Dict[str, str], int]:
        """Include local helper modules imported by already-loaded scripts (bounded fixpoint).

        SKILL.md files frequently reference only top-level scripts while those scripts import sibling helpers
        (e.g. `scripts/_raster.py`). Those helpers are part of `bundle.files` for local/zip/subtree bundles,
        so they are added here to keep fetched payloads runnable, subject to the same reference limits.
        """
        limits = self.config.loader_limits
        script_suffixes = (".py", ".js", ".ts", ".mjs", ".cjs")
        pending = [rel for rel in loaded_refs if Path(rel).suffix.lower() in script_suffixes]
        seen: Set[str] = set(loaded_refs)
        for _round in range(8):  # bounded helper-of-helper chain depth
            added: List[str] = []
            for rel in pending:
                for cand in self._local_module_candidates(rel, loaded_refs.get(rel, "")):
                    if cand in seen or cand not in bundle.files:
                        continue
                    ext = Path(cand).suffix.lower()
                    if ext and ext not in limits.allowed_extensions:
                        continue
                    try:
                        safe_rel = validate_bundle_rel_path(cand, allow_nested=True, max_depth=limits.max_nesting_depth)
                    except ValueError:
                        continue
                    if len(loaded_refs) >= limits.max_references or total_bytes >= limits.max_total_bytes:
                        return loaded_refs, total_bytes
                    raw_ref = bundle.files[safe_rel]
                    ref_text = raw_ref.decode("utf-8-sig", errors="replace") if isinstance(raw_ref, bytes) else raw_ref
                    ref_bytes = len(ref_text.encode("utf-8"))
                    if ref_bytes > limits.max_file_size_bytes:
                        continue
                    if total_bytes + ref_bytes > limits.max_total_bytes:
                        return loaded_refs, total_bytes
                    loaded_refs[safe_rel] = ref_text
                    total_bytes += ref_bytes
                    seen.add(safe_rel)
                    added.append(safe_rel)
            if not added:
                break
            pending = added
        return loaded_refs, total_bytes

    def load_skills_parallel(
        self,
        extension_ids: List[str],
        *,
        session_id: str = "default",
        decision_id: str = "manual",
        include_references: bool = True,
        allow_dedup_stub: bool = False,
        approved: bool = False,
        max_workers: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Load multiple skills concurrently through a bounded worker pool.

        Each skill is fetched, scanned, hash-verified, and materialized independently; per-session state updates
        are serialized by the loader lock. Failures are reported per skill without aborting the batch.
        """
        ordered_ids = [str(x).strip() for x in extension_ids if str(x).strip()]
        deduped_ids = list(dict.fromkeys(ordered_ids))
        limits = self.config.loader_limits
        if not deduped_ids:
            return {
                "session_id": session_id,
                "requested_count": 0,
                "loaded_count": 0,
                "failed_count": 0,
                "workers": 0,
                "elapsed_ms": 0.0,
                "loaded": [],
                "failed": [],
            }

        workers = int(max_workers or limits.max_parallel_workers)
        workers = max(1, min(workers, len(deduped_ids)))
        start = time.perf_counter()
        loaded: List[RuntimeSkillHandle] = []
        failed: List[Dict[str, str]] = []

        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sb-load") as pool:
            futures = {
                pool.submit(
                    self.load_skill,
                    ext_id,
                    session_id=session_id,
                    decision_id=decision_id,
                    include_references=include_references,
                    allow_dedup_stub=allow_dedup_stub,
                    approved=approved,
                ): ext_id
                for ext_id in deduped_ids
            }
            for fut in as_completed(futures):
                ext_id = futures[fut]
                try:
                    loaded.append(fut.result())
                except SkillLoadError as exc:
                    failed.append({"extension_id": ext_id, "error": str(exc), "error_type": type(exc).__name__})
                except Exception as exc:  # unexpected per-skill failure must not abort the batch
                    failed.append({"extension_id": ext_id, "error": f"{type(exc).__name__}: {exc}", "error_type": type(exc).__name__})

        loaded.sort(key=lambda h: h.extension_id)
        failed.sort(key=lambda f: f["extension_id"])
        elapsed_ms = round((time.perf_counter() - start) * 1000.0, 2)
        self.db.log_audit(
            "load_skills_parallel",
            session_id=session_id,
            provider="loader",
            elapsed_ms=elapsed_ms,
            details={
                "requested_count": len(deduped_ids),
                "loaded_count": len(loaded),
                "failed_count": len(failed),
                "workers": workers,
            },
        )
        return {
            "session_id": session_id,
            "requested_count": len(deduped_ids),
            "loaded_count": len(loaded),
            "failed_count": len(failed),
            "workers": workers,
            "elapsed_ms": elapsed_ms,
            "loaded": [
                {
                    "extension_id": h.extension_id,
                    "handle_id": h.handle_id,
                    "name": h.name,
                    "source_provider": h.source_provider,
                    "total_bytes": h.total_bytes,
                    "estimated_tokens": h.estimated_tokens,
                    "references_loaded": len(h.loaded_references),
                    "dedup_stub": h.dedup_stub,
                }
                for h in loaded
            ],
            "failed": failed,
        }

    def unload_skill(self, extension_id: str, *, session_id: str = "default") -> Dict[str, Any]:
        """Explicitly unload a skill from a session, releasing its instruction body and reference buffers."""
        with self._lock:
            session_map = self._active_sessions.get(session_id, {})
            target_key = None
            for k, h in session_map.items():
                if (
                    k.lower() == extension_id.lower()
                    or h.name.lower() == extension_id.lower()
                    or h.handle_id == extension_id
                ):
                    target_key = k
                    break

            if target_key is None:
                return {
                    "unloaded": False,
                    "session_id": session_id,
                    "extension_id": extension_id,
                    "reason": "Skill was not active in the specified session",
                }

            handle = session_map.pop(target_key)
            bytes_freed = handle.total_bytes
            c_hash = handle.content_hash
            ext_id = handle.extension_id
            self._handle_last_access.pop((session_id, ext_id), None)

            handle.skill_md_body = ""
            handle.loaded_references.clear()
            handle.frontmatter.clear()
            handle.total_bytes = 0
            handle.active = False
            handle.released_at = utc_now_iso()

            dedup_map = self._session_dedup.get(session_id, {})
            dedup_map.pop((ext_id, c_hash), None)

            if not session_map:
                self._active_sessions.pop(session_id, None)

            # Retain recall metadata
            if ext_id not in self._retained_import_history:
                self._retained_import_history[ext_id] = {
                    "skill_id": ext_id,
                    "name": handle.name,
                    "source_provider": handle.source_provider,
                    "source_uri": handle.provenance_uri,
                    "bundle_digest": c_hash,
                    "final_state": ImportState.METADATA_AND_RESULTS_RETAINED.value,
                }

            event = {
                "handle_id": handle.handle_id,
                "session_id": session_id,
                "extension_id": ext_id,
                "bytes_freed": bytes_freed,
                "released_at": handle.released_at,
            }
            self._unload_events.append(event)

        gc.collect()
        self.db.log_audit(
            "unload_skill",
            session_id=session_id,
            extension_id=ext_id,
            details=event,
        )
        return {
            "unloaded": True,
            **event,
            "context_isolation_note": handle.context_isolation_note,
        }

    def unload_session(self, session_id: str) -> Dict[str, Any]:
        """Unload and release all active skills and deduplication state for a session."""
        with self._lock:
            session_map = self._active_sessions.get(session_id, {})
            keys = list(session_map.keys())

        unloaded_items = []
        total_freed = 0
        for k in keys:
            res = self.unload_skill(k, session_id=session_id)
            if res.get("unloaded"):
                unloaded_items.append(res["extension_id"])
                total_freed += int(res.get("bytes_freed", 0))

        with self._lock:
            self._session_dedup.pop(session_id, None)
            self._active_sessions.pop(session_id, None)

        gc.collect()
        return {
            "session_id": session_id,
            "unloaded_count": len(unloaded_items),
            "unloaded_extensions": unloaded_items,
            "total_bytes_freed": total_freed,
            "released_at": utc_now_iso(),
        }

    def reset_session_dedup(self, session_id: Optional[str] = None) -> None:
        """Reset repeat-view deduplication cache (e.g. after context compaction)."""
        with self._lock:
            if session_id is None:
                self._session_dedup.clear()
            else:
                self._session_dedup.pop(session_id, None)

    @contextmanager
    def temporary_skill_scope(
        self,
        extension_ids: List[str],
        *,
        session_id: str = "default",
        decision_id: str = "scoped",
        approved: bool = False,
    ) -> Iterator[List[RuntimeSkillHandle]]:
        """Context manager that loads selected skills just-in-time and guarantees unloading in a finally block."""
        handles: List[RuntimeSkillHandle] = []
        try:
            for ext_id in extension_ids:
                h = self.load_skill(ext_id, session_id=session_id, decision_id=decision_id, approved=approved)
                handles.append(h)
            yield handles
        finally:
            for h in handles:
                self.unload_skill(h.extension_id, session_id=session_id)

    @asynccontextmanager
    async def async_temporary_skill_scope(
        self,
        extension_ids: List[str],
        *,
        session_id: str = "default",
        decision_id: str = "scoped",
        approved: bool = False,
    ) -> AsyncIterator[List[RuntimeSkillHandle]]:
        """Async context manager that guarantees unloading on normal exit, exception, or asyncio cancellation."""
        handles: List[RuntimeSkillHandle] = []
        try:
            for ext_id in extension_ids:
                h = self.load_skill(ext_id, session_id=session_id, decision_id=decision_id, approved=approved)
                handles.append(h)
            yield handles
        finally:
            for h in handles:
                self.unload_skill(h.extension_id, session_id=session_id)
