""" Unified Discovery Engine orchestrating local and remote providers, deduplication, and SQLite indexing."""

from __future__ import annotations

import gc
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from skillbridge.cache.database import CatalogDatabase
from skillbridge.config import SkillBridgeConfig
from skillbridge.discovery.normalizer import normalize_repo_alias
from skillbridge.models import ExtensionBundle, ExtensionRecord, ExtensionType, TrustLevel
from skillbridge.providers.base import ExtensionProvider, GuardedHttpClient
from skillbridge.providers.hermes_hub import HermesHubProvider
from skillbridge.providers.local import LocalSkillsProvider
from skillbridge.providers.remote import (
    GitHubSkillsProvider,
    MCPRegistryProvider,
    WellKnownSkillsProvider,
)
from skillbridge.providers.smithery import SmitheryMCPProvider

logger = logging.getLogger("skillbridge.discovery")

TRUST_PRIORITY = {
    TrustLevel.BUILTIN.value: 4,
    TrustLevel.TRUSTED.value: 3,
    TrustLevel.AGENT_CREATED.value: 2,
    TrustLevel.COMMUNITY.value: 1,
    TrustLevel.UNTRUSTED.value: 0,
}


def deduplicate_records(records: List[ExtensionRecord]) -> List[ExtensionRecord]:
    """Deduplicate extension records by extension_id, preferring higher trust levels on collision."""
    by_id: Dict[str, ExtensionRecord] = {}
    for rec in records:
        key = rec.extension_id.lower()
        existing = by_id.get(key)
        if existing is None or TRUST_PRIORITY.get(rec.trust_level, 0) > TRUST_PRIORITY.get(existing.trust_level, 0):
            by_id[key] = rec
    return list(by_id.values())


class DiscoveryEngine:
    """Unified discovery orchestrator across local directories, Hermes Hub (100k+ skills), GitHub, well-known endpoints, and MCP Registry."""

    def __init__(
        self,
        config: Optional[SkillBridgeConfig] = None,
        db: Optional[CatalogDatabase] = None,
        http_client: Optional[GuardedHttpClient] = None,
    ):
        self.config = config or SkillBridgeConfig()
        self.config.ensure_dirs()
        self.db = db or CatalogDatabase(self.config.db_path, enable_telemetry=self.config.enable_telemetry)
        self.http = http_client or GuardedHttpClient(self.config.network)

        self.local_provider = LocalSkillsProvider(self.config)
        self.hermes_hub_provider = HermesHubProvider(self.config, self.http)
        self.github_provider = GitHubSkillsProvider(self.config, self.http)
        self.well_known_provider = WellKnownSkillsProvider(self.config, self.http)
        self.mcp_provider = MCPRegistryProvider(self.config, self.http)
        self.smithery_provider = SmitheryMCPProvider(self.config, self.http)

        self.skill_providers: List[ExtensionProvider] = [
            self.local_provider,
            self.hermes_hub_provider,
            self.github_provider,
            self.well_known_provider,
        ]
        self.mcp_providers: List[ExtensionProvider] = [
            self.mcp_provider,
            self.smithery_provider,
        ]
        self.all_providers: List[ExtensionProvider] = [
            *self.skill_providers,
            *self.mcp_providers,
        ]
        self._seeded = False

    def ensure_catalog_seeded(self, force_rescan: bool = False) -> Dict[str, int]:
        """Populate the SQLite catalog with local skills, bundled Hermes index cache, and curated MCP servers."""
        existing_total = self.db.count_extensions()
        if not force_rescan and (self._seeded or existing_total >= 500):
            if not self._seeded:
                # Only scan fast custom/project/user directories to pick up any newly added local skills
                for entry in self.config.get_local_skill_discovery_dirs():
                    if entry["source"] not in ("hermes-bundled", "hermes-official"):
                        custom_recs = self.local_provider._scan_single_root(entry["path"], entry["source"], entry["trust"])
                        if custom_recs:
                            self.db.upsert_extensions_batch(custom_recs)
                self._seeded = True
            return {
                "skills": self.db.count_extensions(ExtensionType.SKILL.value),
                "mcp_servers": self.db.count_extensions(ExtensionType.MCP_SERVER.value),
            }

        start = time.perf_counter()
        skills_before = self.db.count_extensions(ExtensionType.SKILL.value)
        mcps_before = self.db.count_extensions(ExtensionType.MCP_SERVER.value)
        local_skills = self.local_provider.scan_all_local()
        hub_cached = self.hermes_hub_provider._load_bundled_and_cached_index()
        local_mcps = self.mcp_provider._load_local_mcp_catalog()

        merged = deduplicate_records([*local_skills, *hub_cached, *local_mcps])
        self.db.upsert_extensions_batch(merged)
        total_indexed = len(merged)
        local_skill_count = len(local_skills)
        hub_cached_count = len(hub_cached)
        mcp_count = len(local_mcps)
        # The catalog is now the durable copy; release the parsed index (100k+ records, hundreds
        # of MiB) so long-lived processes stay well under the runtime memory threshold.
        self.hermes_hub_provider.release_index_caches()
        merged = []  # release the merged record list (large)
        hub_cached = []
        local_skills = []
        local_mcps = []
        gc.collect()
        self._seeded = True
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        skills_after = self.db.count_extensions(ExtensionType.SKILL.value)
        mcps_after = self.db.count_extensions(ExtensionType.MCP_SERVER.value)
        # Only log catalog_seed when the catalog actually changed (or a forced rescan ran), so that
        # per-process re-seeding does not bury real fetches/loads in the recent audit trail.
        if force_rescan or (skills_before, mcps_before) != (skills_after, mcps_after):
            self.db.log_audit(
                "catalog_seed",
                provider="discovery",
                elapsed_ms=elapsed_ms,
                details={"total_indexed": total_indexed, "local_skills": local_skill_count, "hub_cached": hub_cached_count, "mcps": mcp_count},
            )
        return {
            "skills": skills_after,
            "mcp_servers": mcps_after,
            "total": total_indexed,
        }

    def search_skills(
        self,
        query: str,
        *,
        source_filter: str = "all",
        limit: int = 20,
        session_id: str = "default",
    ) -> Tuple[List[ExtensionRecord], Dict[str, str]]:
        """Search skills across local SQLite FTS5 catalog and active providers.

        Returns (deduplicated_records, source_status_map).
        Even if a network provider fails, local catalog search always succeeds.
        """
        start = time.perf_counter()
        self.ensure_catalog_seeded()
        source_status: Dict[str, str] = {}
        collected: List[ExtensionRecord] = []

        # 1. Local / Indexed SQLite FTS5 Search (always available even offline)
        try:
            db_hits = self.db.search_extensions(
                query,
                extension_type=ExtensionType.SKILL.value,
                source_provider=None if source_filter == "all" else source_filter,
                limit=limit * 2,
            )
            collected.extend(db_hits)
            source_status["sqlite_catalog"] = f"ok ({len(db_hits)} hits)"
        except Exception as exc:
            source_status["sqlite_catalog"] = f"error: {exc}"

        # 2. Query live providers if needed or if URL/repo query given
        is_url_or_well_known = query.strip().startswith(("http://", "https://", "well-known:"))
        if not self.config.network.offline_mode and (len(collected) < limit or is_url_or_well_known or source_filter != "all"):
            providers_to_run: List[ExtensionProvider] = []
            if is_url_or_well_known:
                providers_to_run.append(self.well_known_provider)
            for prov in self.skill_providers:
                if source_filter in ("all", prov.PROVIDER_ID) and prov not in providers_to_run:
                    providers_to_run.append(prov)

            with ThreadPoolExecutor(max_workers=min(len(providers_to_run) or 1, 4)) as pool:
                futures = {pool.submit(prov.search, query, limit): prov.PROVIDER_ID for prov in providers_to_run}
                for fut in as_completed(futures):
                    pid = futures[fut]
                    try:
                        res = fut.result()
                        source_status[pid] = f"ok ({len(res)} hits)"
                        if res:
                            self.db.upsert_extensions_batch(res)
                            collected.extend(res)
                    except Exception as exc:
                        source_status[pid] = f"failed ({type(exc).__name__}: {exc})"
        else:
            if self.config.network.offline_mode:
                source_status["network"] = "skipped (offline_mode=True)"

        deduped = deduplicate_records(collected)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        self.db.log_audit(
            "search_skills",
            session_id=session_id,
            provider=source_filter,
            elapsed_ms=elapsed_ms,
            details={"result_count": len(deduped[:limit]), "sources": source_status},
        )
        return deduped[:limit], source_status

    def search_mcp(
        self,
        query: str,
        *,
        limit: int = 20,
        session_id: str = "default",
    ) -> Tuple[List[ExtensionRecord], Dict[str, str]]:
        """Search MCP servers across local catalog and the Official MCP Registry."""
        start = time.perf_counter()
        self.ensure_catalog_seeded()
        source_status: Dict[str, str] = {}
        collected: List[ExtensionRecord] = []

        db_hits = self.db.search_extensions(
            query,
            extension_type=ExtensionType.MCP_SERVER.value,
            limit=limit * 2,
        )
        collected.extend(db_hits)
        source_status["sqlite_mcp_catalog"] = f"ok ({len(db_hits)} hits)"

        if not self.config.network.offline_mode:
            with ThreadPoolExecutor(max_workers=min(len(self.mcp_providers) or 1, 4)) as pool:
                futures = {pool.submit(prov.search, query, limit): prov.PROVIDER_ID for prov in self.mcp_providers}
                for fut in as_completed(futures):
                    pid = futures[fut]
                    try:
                        live_hits = fut.result()
                        source_status[pid] = f"ok ({len(live_hits)} hits)"
                        if live_hits:
                            self.db.upsert_extensions_batch(live_hits)
                            collected.extend(live_hits)
                    except Exception as exc:
                        source_status[pid] = f"failed ({type(exc).__name__}: {exc})"
        else:
            for prov in self.mcp_providers:
                source_status[prov.PROVIDER_ID] = "skipped (offline_mode=True)"

        deduped = deduplicate_records(collected)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        self.db.log_audit(
            "search_mcp",
            session_id=session_id,
            provider="mcp-providers",
            elapsed_ms=elapsed_ms,
            details={"result_count": len(deduped[:limit]), "sources": source_status},
        )
        return deduped[:limit], source_status

    def resolve_extension(self, extension_id: str) -> Optional[ExtensionRecord]:
        """Resolve an extension by ID or name from SQLite catalog or upstream providers."""
        self.ensure_catalog_seeded()
        for cand in (
            extension_id,
            extension_id.replace(":", "/"),
            extension_id.split("/")[-1].split(":")[-1],
        ):
            rec = self.db.get_extension(cand)
            if rec:
                return rec
        normalized = normalize_repo_alias(extension_id)
        for prov in self.all_providers:
            try:
                inspected = prov.inspect(normalized)
                if inspected:
                    self.db.upsert_extension(inspected)
                    return inspected
            except Exception:
                continue
        return None

    def fetch_bundle(self, extension_id: str) -> Optional[ExtensionBundle]:
        """Fetch the complete file bundle for a skill or MCP server across providers."""
        self.ensure_catalog_seeded()
        rec = self.resolve_extension(extension_id)
        target_id = rec.extension_id if rec else extension_id

        # Route to matching provider first
        if rec:
            if rec.extension_type == ExtensionType.MCP_SERVER.value:
                if rec.source_provider == "smithery":
                    bundle = self.smithery_provider.fetch_bundle(target_id)
                    if bundle:
                        return bundle
                return self.mcp_provider.fetch_bundle(target_id)
            if rec.source_provider in ("hermes-bundled", "hermes-official", "hermes-local", "opencode-user", "opencode-project", "claude-user", "claude-project", "agents-user", "agents-project", "local-custom"):
                bundle = self.local_provider.fetch_bundle(target_id, record=rec)
                if bundle:
                    return bundle
            if rec.source_provider == "clawhub":
                slug = rec.extension_id
                if rec.canonical_uri and "/skills/" in rec.canonical_uri:
                    slug = rec.canonical_uri.split("/skills/", 1)[1]
                bundle = self.hermes_hub_provider.fetch_clawhub_bundle(slug)
                if bundle:
                    bundle.extension_id = rec.extension_id
                    bundle.record = rec
                    return bundle
            if rec.source_provider in ("lobehub", "browse-sh", "hermes-index"):
                bundle = self.hermes_hub_provider.fetch_bundle(target_id)
                if bundle:
                    return bundle
                if rec.repo and rec.source_path:
                    bundle = self.github_provider.fetch_bundle(f"{rec.repo}/{rec.source_path}")
                    if bundle:
                        bundle.extension_id = rec.extension_id
                        return bundle
            if rec.source_provider == "well-known" or target_id.startswith("well-known:"):
                bundle = self.well_known_provider.fetch_bundle(target_id)
                if bundle:
                    return bundle
            if rec.source_provider in ("github", "skills.sh"):
                gh_target = f"{rec.repo}/{rec.source_path}" if rec.repo else target_id
                bundle = self.github_provider.fetch_bundle(gh_target)
                if bundle:
                    bundle.extension_id = rec.extension_id
                    return bundle

        # Fallback probe across all providers
        for prov in self.all_providers:
            try:
                bundle = prov.fetch_bundle(target_id)
                if bundle:
                    if bundle.record:
                        self.db.upsert_extension(bundle.record)
                    return bundle
            except Exception:
                continue
        return None
