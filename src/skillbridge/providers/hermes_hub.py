"""Hermes Skills Hub 100k+ Ecosystem Providers:

Covers:
1. Hermes Centralized Skills Index (`https://hermes-agent.nousresearch.com/docs/api/skills-index.json` + bundled index cache)
2. Skills.sh Marketplace (`https://skills.sh/api/search` & `https://www.skills.sh/sitemap.xml` ~89,753 skills)
3. ClawHub (`https://clawhub.ai/api/v1` ~50,000+ skills with safe ZIP extraction & owner verification)
4. LobeHub (`https://chat-agents.lobehub.com/index.json` ~14,500+ agents converted to SKILL.md)
5. Browse.sh (`https://browse.sh/api/skills` site-specific browser skills)
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import io
from itertools import zip_longest
import json
import logging
import re
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from skillbridge.config import SkillBridgeConfig
from skillbridge.discovery.normalizer import (
    compute_bundle_content_hash,
    parse_skill_md,
    validate_bundle_rel_path,
    validate_skill_name,
)
from skillbridge.models import ExtensionBundle, ExtensionRecord, ExtensionType, TrustLevel
from skillbridge.providers.base import ExtensionProvider, GuardedHttpClient

logger = logging.getLogger("skillbridge.providers.hermes_hub")

TRUSTED_REPOS = {"openai/skills", "anthropics/skills", "huggingface/skills", "nvidia/skills", "nousresearch/hermes-agent"}


def _trust_for_repo(repo: str, default: str = TrustLevel.COMMUNITY.value) -> str:
    if repo and repo.strip().lower() in TRUSTED_REPOS:
        return TrustLevel.TRUSTED.value
    return default


def _convert_lobehub_to_skill_md(agent_data: Dict[str, Any]) -> str:
    """Convert a LobeHub agent definition into portable Agent Skills SKILL.md format."""
    meta = agent_data.get("meta", agent_data)
    identifier = str(agent_data.get("identifier") or "lobehub-agent").strip().lower()
    identifier = re.sub(r"[^a-z0-9-]+", "-", identifier).strip("-") or "lobehub-agent"
    title = str(meta.get("title") or identifier)
    description = str(meta.get("description") or f"LobeHub specialized agent for {title}").replace("\n", " ")[:500]
    tags = meta.get("tags", [])
    tag_list = [str(t) for t in tags] if isinstance(tags, list) else []
    system_role = str(agent_data.get("config", {}).get("systemRole") or meta.get("description") or "")
    fm_lines = [
        "---",
        f"name: {identifier}",
        f"description: {json.dumps(description)}",
        "metadata:",
        "  hermes:",
        f"    tags: [{', '.join(json.dumps(t) for t in tag_list)}]",
        "  lobehub:",
        "    source: lobehub",
        "---",
    ]
    body_lines = [
        f"# {title}",
        "",
        description,
        "",
        "## Instructions",
        "",
        system_role if system_role else f"Follow domain best practices for {title}.",
    ]
    return "\n".join(fm_lines) + "\n\n" + "\n".join(body_lines) + "\n"


class HermesHubProvider(ExtensionProvider):
    """Unified provider connecting to the Hermes Skills Hub (100k+ skills across Hermes Index, skills.sh, ClawHub, LobeHub, browse.sh)."""

    PROVIDER_ID = "hermes-hub"
    EXTENSION_TYPE = ExtensionType.SKILL.value

    HERMES_INDEX_URL = "https://hermes-agent.nousresearch.com/docs/api/skills-index.json"
    SKILLS_SH_SEARCH_URL = "https://skills.sh/api/search"
    SKILLS_SH_SITEMAP_URL = "https://www.skills.sh/sitemap.xml"
    CLAWHUB_BASE_URL = "https://clawhub.ai/api/v1"
    LOBEHUB_INDEX_URL = "https://chat-agents.lobehub.com/index.json"
    BROWSE_SH_URL = "https://browse.sh/api/skills"

    def __init__(self, config: Optional[SkillBridgeConfig] = None, http_client: Optional[GuardedHttpClient] = None):
        self.config = config or SkillBridgeConfig()
        self.http = http_client or GuardedHttpClient(self.config.network)
        self._cached_records: Optional[List[ExtensionRecord]] = None
        self._bundled_records: Optional[List[ExtensionRecord]] = None
        self._lobehub_map: Dict[str, Dict[str, Any]] = {}

    def _append_bundled_caches(self, records: List[ExtensionRecord], seen: set[str]) -> None:
        """Append packaged index caches (Anthropic skills + LobeHub agents) into ``records``."""
        bundled_cache = self.config.bundled_data_dir / "index_cache"
        anth_file = bundled_cache / "anthropics_skills_skills_.json"
        if anth_file.is_file():
            try:
                anth_list = json.loads(anth_file.read_text(encoding="utf-8-sig"))
                if isinstance(anth_list, list):
                    for item in anth_list:
                        rec = self._entry_to_record(item, default_source="github")
                        if rec and rec.extension_id not in seen:
                            seen.add(rec.extension_id)
                            records.append(rec)
            except (OSError, json.JSONDecodeError):
                pass

        lobe_file = bundled_cache / "lobehub_index.json"
        if lobe_file.is_file():
            try:
                lobe_data = json.loads(lobe_file.read_text(encoding="utf-8-sig"))
                agents = lobe_data.get("agents", []) if isinstance(lobe_data, dict) else []
                for agent in agents:
                    if not isinstance(agent, dict):
                        continue
                    meta = agent.get("meta", agent)
                    ident = str(agent.get("identifier") or "").strip()
                    if not ident:
                        continue
                    ext_id = f"lobehub/{ident}"
                    if ext_id in seen:
                        continue
                    seen.add(ext_id)
                    self._lobehub_map[ext_id] = agent
                    self._lobehub_map[ident] = agent
                    title = str(meta.get("title") or ident)
                    desc = str(meta.get("description") or title)
                    tags = [str(t) for t in meta.get("tags", [])] if isinstance(meta.get("tags"), list) else []
                    cat = str(meta.get("category") or "general")
                    records.append(
                        ExtensionRecord(
                            extension_id=ext_id,
                            name=ident,
                            display_name=title,
                            extension_type=ExtensionType.SKILL.value,
                            description=desc[:1024],
                            source_provider="lobehub",
                            canonical_uri=f"https://chat-agents.lobehub.com/{ident}.json",
                            repo="lobehub/lobe-chat-agents",
                            source_path=ident,
                            version_or_revision=str(agent.get("createdAt") or "1"),
                            trust_level=TrustLevel.COMMUNITY.value,
                            tags=tags,
                            task_categories=[cat],
                            capabilities=tags[:5],
                            popularity_signals={"token_usage": agent.get("tokenUsage", 0)},
                            extra_metadata={"author": agent.get("author", ""), "homepage": agent.get("homepage", "")},
                        )
                    )
            except (OSError, json.JSONDecodeError):
                pass

    def _load_bundled_index(self) -> List[ExtensionRecord]:
        """Load only the packaged index caches; never fetches or parses the large live index."""
        if self._bundled_records is not None:
            return self._bundled_records
        records: List[ExtensionRecord] = []
        seen: set[str] = set()
        self._append_bundled_caches(records, seen)
        self._bundled_records = records
        return records

    def release_index_caches(self) -> None:
        """Drop the parsed 100k+ record live index after it has been persisted to the catalog.

        The SQLite catalog is the durable copy. Keeping the parsed list alive would push
        long-lived processes over the runtime memory threshold for no benefit.
        """
        self._cached_records = None

    def _load_bundled_and_cached_index(self) -> List[ExtensionRecord]:
        """Load bundled Hermes index caches (Anthropic skills + LobeHub 505 agents) plus any fetched hermes-index.json."""
        if self._cached_records is not None:
            return self._cached_records

        records: List[ExtensionRecord] = []
        seen: set[str] = set()

        # 1. Check live or cached hermes-index.json
        cache_file = self.config.index_cache_dir / "hermes-index.json"
        index_data = None
        if cache_file.is_file():
            try:
                index_data = json.loads(cache_file.read_text(encoding="utf-8-sig"))
            except (OSError, json.JSONDecodeError):
                index_data = None
        if index_data is None and not self.config.network.offline_mode:
            fetched = self.http.get_json(self.HERMES_INDEX_URL, headers={"Accept-Encoding": "gzip, deflate"})
            if isinstance(fetched, dict) and isinstance(fetched.get("skills"), list):
                index_data = fetched
                try:
                    self.config.index_cache_dir.mkdir(parents=True, exist_ok=True)
                    cache_file.write_text(json.dumps(fetched), encoding="utf-8")
                except OSError:
                    pass

        if isinstance(index_data, dict) and isinstance(index_data.get("skills"), list):
            for entry in index_data["skills"]:
                rec = self._entry_to_record(entry, default_source="hermes-index")
                if rec and rec.extension_id not in seen:
                    seen.add(rec.extension_id)
                    records.append(rec)

        # 2. Load bundled Hermes index_cache files (anthropics_skills_skills_.json & lobehub_index.json)
        self._append_bundled_caches(records, seen)

        self._cached_records = records
        return records

    def _entry_to_record(self, entry: Dict[str, Any], default_source: str = "hermes-index") -> Optional[ExtensionRecord]:
        if not isinstance(entry, dict):
            return None
        name = str(entry.get("name") or "").strip()
        ident = str(entry.get("identifier") or name).strip()
        if not name or not ident:
            return None
        source = str(entry.get("source") or default_source)
        repo = str(entry.get("repo") or "")
        trust = str(entry.get("trust_level") or _trust_for_repo(repo))
        tags = [str(t) for t in entry.get("tags", [])] if isinstance(entry.get("tags"), list) else []
        extra = entry.get("extra") if isinstance(entry.get("extra"), dict) else {}
        return ExtensionRecord(
            extension_id=ident,
            name=name,
            display_name=name,
            extension_type=ExtensionType.SKILL.value,
            description=str(entry.get("description") or "")[:1024],
            source_provider=source,
            canonical_uri=str(extra.get("detail_url") or (f"https://github.com/{repo}" if repo else "")),
            repo=repo,
            source_path=str(entry.get("path") or ""),
            trust_level=trust,
            tags=tags,
            task_categories=[str(extra.get("category") or "general")],
            capabilities=tags[:5],
            popularity_signals={"weekly_installs": extra.get("install_count", 0)},
            extra_metadata=extra,
        )

    def search_skills_sh(self, query: str, limit: int = 10) -> List[ExtensionRecord]:
        """Query skills.sh API directly when online."""
        if self.config.network.offline_mode:
            return []
        data = self.http.get_json(self.SKILLS_SH_SEARCH_URL, params={"q": query, "limit": limit})
        if not isinstance(data, dict) or not isinstance(data.get("skills"), list):
            return []
        out: List[ExtensionRecord] = []
        for item in data["skills"][:limit]:
            if not isinstance(item, dict):
                continue
            slug = str(item.get("id") or item.get("slug") or item.get("name") or "").strip("/")
            name = str(item.get("name") or slug.split("/")[-1]).strip()
            if not slug or not name:
                continue
            # The API reports the canonical repo separately from the in-repo skill path; repos
            # often nest skills (e.g. anthropics/skills stores them under skills/), and the
            # GitHub fetch resolves any nesting when the direct path has no SKILL.md.
            source_repo = str(item.get("source") or "").strip("/")
            skill_id_field = str(item.get("skillId") or "").strip("/")
            repo = source_repo if source_repo.count("/") == 1 else (
                "/".join(slug.split("/")[:2]) if slug.count("/") >= 1 else ""
            )
            if skill_id_field:
                source_path = skill_id_field
            else:
                source_path = slug.split("/", 2)[2] if slug.count("/") >= 2 else name
            out.append(
                ExtensionRecord(
                    extension_id=f"skills.sh/{slug}",
                    name=name,
                    display_name=name,
                    extension_type=ExtensionType.SKILL.value,
                    description=str(item.get("description") or item.get("summary") or f"skills.sh skill {name}")[:1024],
                    source_provider="skills.sh",
                    canonical_uri=f"https://skills.sh/{slug}",
                    repo=repo,
                    source_path=source_path,
                    trust_level=_trust_for_repo(repo),
                    tags=[str(t) for t in item.get("tags", [])] if isinstance(item.get("tags"), list) else [],
                    popularity_signals={"installs": item.get("installs", item.get("weeklyInstalls", 0))},
                )
            )
        return out

    def search_clawhub(self, query: str, limit: int = 10) -> List[ExtensionRecord]:
        """Query the ClawHub search API (`clawhub.ai/api/v1/search`) when online."""
        if self.config.network.offline_mode:
            return []
        data = self.http.get_json(f"{self.CLAWHUB_BASE_URL}/search", params={"q": query, "limit": limit})
        items = data.get("results", data.get("skills", data.get("items", []))) if isinstance(data, dict) else (data if isinstance(data, list) else [])
        if not isinstance(items, list):
            return []
        out: List[ExtensionRecord] = []
        for raw in items[:limit]:
            if not isinstance(raw, dict):
                continue
            nested = raw.get("skill") if isinstance(raw.get("skill"), dict) else raw
            install = nested.get("install") if isinstance(nested.get("install"), dict) else raw.get("install")
            install_ref = str(install.get("reference") or "").strip("/") if isinstance(install, dict) else ""
            owner_handle = ""
            native = raw.get("native") if isinstance(raw.get("native"), dict) else {}
            owner = native.get("owner") or raw.get("owner") or nested.get("owner")
            if isinstance(owner, dict):
                owner_handle = str(owner.get("handle") or owner.get("name") or "").strip()
            elif owner:
                owner_handle = str(owner).strip()
            if install_ref and "/" in install_ref:
                if not owner_handle:
                    owner_handle = install_ref.split("/")[0]
            slug = str(nested.get("slug") or raw.get("slug") or "").strip()
            if not slug and install_ref:
                slug = install_ref.split("/")[-1]
            if not slug:
                continue
            links = raw.get("links") if isinstance(raw.get("links"), dict) else {}
            canonical = str(links.get("canonical") or raw.get("canonicalUrl") or f"https://clawhub.ai/skills/{install_ref or slug}")
            if canonical.startswith("/"):
                canonical = f"https://clawhub.ai{canonical}"
            ident = f"clawhub/{owner_handle}/{slug}" if owner_handle else f"clawhub/{slug}"
            out.append(
                ExtensionRecord(
                    extension_id=ident,
                    name=slug,
                    display_name=str(nested.get("displayName") or nested.get("title") or slug),
                    extension_type=ExtensionType.SKILL.value,
                    description=str(nested.get("summary") or nested.get("description") or raw.get("summary") or "")[:1024],
                    source_provider="clawhub",
                    canonical_uri=canonical,
                    version_or_revision=str(raw.get("latestVersion") or nested.get("version") or "latest"),
                    trust_level=TrustLevel.COMMUNITY.value,
                    extra_metadata={"owner": owner_handle, "slug": slug, "install_reference": install_ref},
                )
            )
        return out

    def search_browse_sh(self, query: str, limit: int = 10) -> List[ExtensionRecord]:
        """Query Browserbase's browse.sh skill catalog when online."""
        if self.config.network.offline_mode:
            return []
        data = self.http.get_json(self.BROWSE_SH_URL)
        skills = data.get("skills", []) if isinstance(data, dict) else []
        if not isinstance(skills, list):
            return []
        q = query.strip().lower()
        out: List[ExtensionRecord] = []
        for item in skills:
            if not isinstance(item, dict):
                continue
            slug = str(item.get("slug") or "")
            name = str(item.get("name") or "")
            desc = str(item.get("description") or item.get("title") or "")
            if not slug or not name:
                continue
            if q and q not in f"{name} {desc} {item.get('hostname', '')}".lower():
                continue
            out.append(
                ExtensionRecord(
                    extension_id=f"browse-sh/{slug}",
                    name=name,
                    display_name=name,
                    extension_type=ExtensionType.SKILL.value,
                    description=desc[:1024],
                    source_provider="browse-sh",
                    canonical_uri=f"https://browse.sh/api/skills/{slug}",
                    trust_level=TrustLevel.COMMUNITY.value,
                    tags=[str(t) for t in item.get("tags", [])] if isinstance(item.get("tags"), list) else [],
                    popularity_signals={"install_count": item.get("installCount", 0)},
                )
            )
            if len(out) >= limit:
                break
        return out

    def search(self, query: str, limit: int = 20) -> List[ExtensionRecord]:
        records = self._load_bundled_index()
        q = query.strip().lower()
        results: List[ExtensionRecord] = []
        if not q:
            results.extend(records[:limit])
        else:
            terms = [t for t in "".join(c if c.isalnum() else " " for c in q).split() if t]
            scored: List[tuple[int, ExtensionRecord]] = []
            for rec in records:
                hay = f"{rec.name} {rec.display_name} {rec.description} {' '.join(rec.tags)} {rec.extension_id}".lower()
                score = 0
                if q == rec.name.lower() or q == rec.extension_id.lower():
                    score += 100
                elif q in rec.name.lower():
                    score += 45
                elif q in hay:
                    score += 20
                for term in terms:
                    if term in rec.name.lower():
                        score += 12
                    elif term in hay:
                        score += 4
                if score > 0:
                    scored.append((score, rec))
            scored.sort(key=lambda x: (-x[0], x[1].extension_id))
            results.extend(r for _, r in scored[:limit])

        if len(results) < limit and not self.config.network.offline_mode:
            remaining = max(1, limit - len(results))
            live_calls = (
                (self.search_skills_sh, max(1, remaining // 2)),
                (self.search_clawhub, max(1, remaining // 3)),
                (self.search_browse_sh, max(1, remaining // 3)),
            )
            batches: List[List[ExtensionRecord]] = []
            with ThreadPoolExecutor(max_workers=len(live_calls)) as pool:
                futures = [pool.submit(fn, query, limit=cap) for fn, cap in live_calls]
                for fut in futures:
                    try:
                        batches.append(fut.result())
                    except Exception:
                        batches.append([])
            # Round-robin merge across live providers so no single source starves the others
            seen_ids = {r.extension_id.lower() for r in results}
            for group in zip_longest(*batches):
                for rec in group:
                    if rec is None:
                        continue
                    key = rec.extension_id.lower()
                    if key in seen_ids:
                        continue
                    seen_ids.add(key)
                    results.append(rec)
                    if len(results) >= limit:
                        return results[:limit]
        return results[:limit]

    def inspect(self, extension_id: str) -> Optional[ExtensionRecord]:
        target = extension_id.strip().lower()
        # Search the packaged caches first, then the live-index records only if they are already
        # resident. Never trigger a 50+ MB index parse just to resolve an identifier: persisted
        # index records live in the SQLite catalog, which callers resolve before providers.
        for rec in self._load_bundled_index():
            if rec.extension_id.lower() == target or rec.name.lower() == target:
                return rec
        for rec in self._cached_records or []:
            if rec.extension_id.lower() == target or rec.name.lower() == target:
                return rec
        return None

    def fetch_clawhub_zip_bundle(self, slug: str, zip_bytes: bytes, owner: str = "") -> Optional[ExtensionBundle]:
        """Safely extract an in-memory ClawHub ZIP bundle, blocking path traversal and symlinks."""
        safe_slug = validate_skill_name(slug.split("/")[-1])
        files: Dict[str, str | bytes] = {}
        seen_paths: set[str] = set()
        total_uncompressed = 0
        max_archive_bytes = self.config.loader_limits.max_total_bytes
        try:
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    # Reject Unix symlinks in zip external_attr (0o120000)
                    unix_mode = (info.external_attr >> 16) & 0o170000
                    if unix_mode == 0o120000:
                        logger.warning("Rejected symlink inside ClawHub archive: %s", info.filename)
                        return None
                    safe_rel = validate_bundle_rel_path(info.filename)
                    path_key = safe_rel.casefold()
                    if path_key in seen_paths:
                        logger.warning("Rejected duplicate/case-colliding path in ClawHub archive: %s", info.filename)
                        return None
                    seen_paths.add(path_key)
                    if info.file_size > self.config.loader_limits.max_file_size_bytes * 4:
                        logger.warning("Rejected oversized file in ClawHub archive: %s (%d bytes)", safe_rel, info.file_size)
                        return None
                    total_uncompressed += info.file_size
                    if total_uncompressed > max_archive_bytes:
                        logger.warning(
                            "Rejected oversized ClawHub archive for %s: total uncompressed %d bytes exceeds cap %d",
                            slug, total_uncompressed, max_archive_bytes,
                        )
                        return None
                    raw = zf.read(info.filename)
                    try:
                        files[safe_rel] = raw.decode("utf-8-sig")
                    except UnicodeDecodeError:
                        files[safe_rel] = raw
        except (zipfile.BadZipFile, ValueError) as exc:
            logger.warning("Unsafe or corrupted ClawHub ZIP for %s: %s", slug, exc)
            return None

        if "SKILL.md" not in files:
            return None
        c_hash = compute_bundle_content_hash(files)
        return ExtensionBundle(
            extension_id=f"clawhub/{owner}/{safe_slug}" if owner else f"clawhub/{safe_slug}",
            name=safe_slug,
            extension_type=ExtensionType.SKILL.value,
            source_provider="clawhub",
            trust_level=TrustLevel.COMMUNITY.value,
            files=files,
            content_hash=c_hash,
            metadata={"owner": owner, "slug": safe_slug},
        )

    def fetch_clawhub_bundle(self, slug_or_id: str, owner: str = "") -> Optional[ExtensionBundle]:
        """Download a ClawHub bundle by slug, resolving the owner through search when needed.

        Handles both qualified IDs (`clawhub/<owner>/<slug>`) and bare index-record IDs, which
        are common in the Hermes live index (for example `pdftomd`).
        """
        if self.config.network.offline_mode:
            return None
        raw = (slug_or_id or "").strip().strip("/")
        if not raw:
            return None
        if raw.startswith("clawhub/"):
            raw = raw.removeprefix("clawhub/").strip("/")
        parts = [p for p in raw.split("/") if p]
        if not parts:
            return None
        slug = parts[-1]
        if not owner and len(parts) >= 2 and not raw.startswith("skills/"):
            owner = parts[-2]

        def _download(candidate_owner: str) -> Optional[ExtensionBundle]:
            params: Dict[str, Any] = {"slug": slug}
            if candidate_owner:
                params["ownerHandle"] = candidate_owner
            try:
                zip_bytes = self.http.get_bytes(f"{self.CLAWHUB_BASE_URL}/download", params=params)
            except Exception as exc:  # noqa: BLE001 - try the next candidate
                logger.debug("ClawHub download failed for %s (owner=%r): %s", slug, candidate_owner, exc)
                return None
            if not zip_bytes:
                return None
            return self.fetch_clawhub_zip_bundle(slug, zip_bytes, owner=candidate_owner)

        tried: set[str] = set()
        for candidate_owner in ([owner] if owner else []) + [""]:
            if candidate_owner in tried:
                continue
            tried.add(candidate_owner)
            bundle = _download(candidate_owner)
            if bundle:
                return bundle

        # Unqualified slugs can be ambiguous (HTTP 409). Resolve the owner through search.
        try:
            hits = self.search_clawhub(slug, limit=10)
        except Exception as exc:  # noqa: BLE001 - search is best-effort here
            logger.debug("ClawHub owner resolution failed for %s: %s", slug, exc)
            hits = []
        for hit in hits:
            hit_slug = str(hit.extra_metadata.get("slug") or hit.name or "").strip().lower()
            if hit_slug != slug.lower():
                continue
            hit_owner = str(hit.extra_metadata.get("owner") or "").strip()
            if not hit_owner or hit_owner in tried:
                continue
            tried.add(hit_owner)
            bundle = _download(hit_owner)
            if bundle:
                return bundle
        return None

    def fetch_bundle(self, extension_id: str) -> Optional[ExtensionBundle]:
        rec = self.inspect(extension_id)
        ident = rec.extension_id if rec else extension_id
        if ident in self._lobehub_map or ident.removeprefix("lobehub/") in self._lobehub_map:
            agent_data = self._lobehub_map.get(ident) or self._lobehub_map.get(ident.removeprefix("lobehub/"))
            if agent_data:
                skill_md = _convert_lobehub_to_skill_md(agent_data)
                files = {"SKILL.md": skill_md}
                c_hash = compute_bundle_content_hash(files)
                name = str(agent_data.get("identifier") or ident.split("/")[-1])
                if rec:
                    rec.content_hash = c_hash
                return ExtensionBundle(
                    extension_id=f"lobehub/{name}",
                    name=name,
                    extension_type=ExtensionType.SKILL.value,
                    source_provider="lobehub",
                    trust_level=TrustLevel.COMMUNITY.value,
                    files=files,
                    record=rec,
                    content_hash=c_hash,
                    metadata={"converted_from": "lobehub_agent_json"},
                )

        if ident.startswith("clawhub/") and not self.config.network.offline_mode:
            return self.fetch_clawhub_bundle(ident)

        if ident.startswith("browse-sh/") and not self.config.network.offline_mode:
            slug = ident.removeprefix("browse-sh/")
            detail = self.http.get_json(f"{self.BROWSE_SH_URL}/{slug}")
            md_url = detail.get("skillMdUrl") if isinstance(detail, dict) else None
            if isinstance(md_url, str) and md_url.startswith("http"):
                text = self.http.get_text(md_url)
                if text:
                    files = {"SKILL.md": text}
                    return ExtensionBundle(
                        extension_id=ident,
                        name=slug.split("/")[-1],
                        extension_type=ExtensionType.SKILL.value,
                        source_provider="browse-sh",
                        trust_level=TrustLevel.COMMUNITY.value,
                        files=files,
                        record=rec,
                        content_hash=compute_bundle_content_hash(files),
                    )
        return None
