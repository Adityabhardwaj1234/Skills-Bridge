"""Local skill directory provider supporting Hermes, OpenCode, Claude Code, and Agent Skills formats."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional

from skillbridge.config import SkillBridgeConfig
from skillbridge.discovery.normalizer import (
    compute_directory_content_hash,
    parse_skill_md,
    validate_bundle_rel_path,
)
from skillbridge.models import (
    DependencySpec,
    ExtensionBundle,
    ExtensionRecord,
    ExtensionType,
)
from skillbridge.providers.base import ExtensionProvider

EXCLUDED_DIRS = {".git", ".hub", ".archive", "__pycache__", "node_modules", ".venv", "venv", "index-cache"}
SUPPORT_DIRS = {"references", "templates", "scripts", "assets", "examples", "workflows", "design-system"}

# Process-level memo for immutable bundled Hermes catalog directories so tests creating new SkillBridge instances
# do not re-walk 16MB of bundled Hermes skills on every test case.
_BUNDLED_DIR_CACHE: Dict[str, List[ExtensionRecord]] = {}


def _extract_tags_and_deps(frontmatter: Dict[str, Any], category_hint: str = "") -> tuple[List[str], List[str], List[DependencySpec]]:
    tags: List[str] = []
    platforms: List[str] = ["linux", "darwin", "win32"]
    deps: List[DependencySpec] = []

    if isinstance(frontmatter.get("tags"), list):
        tags.extend(str(t) for t in frontmatter["tags"])

    meta = frontmatter.get("metadata")
    if isinstance(meta, dict):
        hermes = meta.get("hermes")
        if isinstance(hermes, dict):
            if isinstance(hermes.get("tags"), list):
                tags.extend(str(t) for t in hermes["tags"])
            if isinstance(hermes.get("platforms"), list) and hermes["platforms"]:
                plat_map = {"macos": "darwin", "darwin": "darwin", "linux": "linux", "windows": "win32", "win32": "win32"}
                platforms = [plat_map.get(str(p).lower(), str(p).lower()) for p in hermes["platforms"]]
            req = hermes.get("requires") or hermes.get("dependencies")
            if isinstance(req, list):
                for item in req:
                    if isinstance(item, str):
                        deps.append(DependencySpec(kind="executable", name=item))
            env_vars = hermes.get("env") or hermes.get("required_env")
            if isinstance(env_vars, list):
                for ev in env_vars:
                    if isinstance(ev, str):
                        deps.append(DependencySpec(kind="env_var", name=ev, required=True, secret=True))

    if category_hint and category_hint not in tags:
        tags.append(category_hint)
    dedup_tags = list(dict.fromkeys(t.strip() for t in tags if str(t).strip()))
    return dedup_tags, platforms, deps


class LocalSkillsProvider(ExtensionProvider):
    """Discovers and loads skills from local Hermes, OpenCode, Claude Code, and custom skill directories."""

    PROVIDER_ID = "local"
    EXTENSION_TYPE = ExtensionType.SKILL.value

    def __init__(self, config: Optional[SkillBridgeConfig] = None):
        self.config = config or SkillBridgeConfig()
        self._dir_map: Dict[str, Path] = {}
        self._cached_records: Optional[List[ExtensionRecord]] = None
        self._by_id: Dict[str, ExtensionRecord] = {}

    def _scan_single_root(self, root: Path, source_label: str, trust_level: str) -> List[ExtensionRecord]:
        is_bundled = source_label in ("hermes-bundled", "hermes-official")
        cache_key = f"{source_label}:{root}"
        if is_bundled and cache_key in _BUNDLED_DIR_CACHE:
            return _BUNDLED_DIR_CACHE[cache_key]

        recs: List[ExtensionRecord] = []
        if not root.exists() or not root.is_dir():
            return recs

        for skill_md in sorted(root.rglob("SKILL.md")):
            rel_parts = skill_md.relative_to(root).parts
            if any(part in EXCLUDED_DIRS or part.startswith(".") for part in rel_parts[:-1]):
                continue
            if any(part in SUPPORT_DIRS for part in rel_parts[:-1]):
                continue

            skill_dir = skill_md.parent
            rel_dir = skill_dir.relative_to(root).as_posix()
            try:
                raw_bytes = skill_md.read_bytes()
                raw_text = raw_bytes.decode("utf-8-sig", errors="replace")
            except OSError:
                continue

            fm, _body = parse_skill_md(raw_text)
            name = str(fm.get("name") or skill_dir.name).strip()
            desc = str(fm.get("description") or f"Local skill {name}").strip()
            category = rel_dir.split("/")[0] if "/" in rel_dir else "general"
            tags, platforms, deps = _extract_tags_and_deps(fm, category_hint=category)

            prefix = "official" if is_bundled else source_label
            ext_id = f"{prefix}/{rel_dir}" if rel_dir != "." else f"{prefix}/{name}"

            # Fast initial digest on SKILL.md; full recursive directory hash is computed on bundle load/preview
            fast_hash = f"sha256:{hashlib.sha256(raw_bytes).hexdigest()[:16]}"
            rec = ExtensionRecord(
                extension_id=ext_id,
                name=name,
                display_name=str(fm.get("title") or name),
                extension_type=ExtensionType.SKILL.value,
                description=desc[:1024],
                source_provider=source_label,
                canonical_uri=skill_dir.resolve().as_uri(),
                repo="NousResearch/hermes-agent" if is_bundled else "",
                source_path=str(skill_dir.resolve()),
                version_or_revision=str(fm.get("version") or "local"),
                content_hash=fast_hash,
                trust_level=trust_level,
                security_verdict="SAFE" if trust_level == "builtin" else "UNKNOWN",
                tags=tags,
                task_categories=[category],
                capabilities=tags[:5],
                platforms=platforms,
                compatible_clients=["opencode", "claude-code", "hermes"],
                dependencies=deps,
                extra_metadata={"local_path": str(skill_dir.resolve()), "frontmatter_keys": list(fm.keys())},
            )
            recs.append(rec)

        if is_bundled:
            _BUNDLED_DIR_CACHE[cache_key] = recs
        return recs

    def scan_all_local(self, force_refresh: bool = False) -> List[ExtensionRecord]:
        """Scan all configured local directories and return normalized ExtensionRecords."""
        if self._cached_records is not None and not force_refresh:
            return self._cached_records

        records: List[ExtensionRecord] = []
        seen_ids: set[str] = set()
        self._by_id.clear()
        self._dir_map.clear()

        # Scan custom/project/user dirs first so user/fixture overrides take precedence over bundled defaults
        entries = list(self.config.get_local_skill_discovery_dirs())
        custom_first = [e for e in entries if e["source"] not in ("hermes-bundled", "hermes-official")] + [
            e for e in entries if e["source"] in ("hermes-bundled", "hermes-official")
        ]

        for entry in custom_first:
            root: Path = entry["path"]
            source_label: str = entry["source"]
            trust_level: str = entry["trust"]
            for rec in self._scan_single_root(root, source_label, trust_level):
                if rec.extension_id in seen_ids:
                    continue
                seen_ids.add(rec.extension_id)
                skill_dir = Path(rec.source_path)
                self._dir_map[rec.extension_id] = skill_dir
                self._dir_map.setdefault(rec.name.lower(), skill_dir)
                self._by_id[rec.extension_id.lower()] = rec
                self._by_id.setdefault(rec.name.lower(), rec)
                records.append(rec)

        self._cached_records = records
        return records

    def search(self, query: str, limit: int = 20) -> List[ExtensionRecord]:
        all_recs = self.scan_all_local()
        q = query.strip().lower()
        if not q:
            return all_recs[:limit]
        terms = [t for t in "".join(c if c.isalnum() else " " for c in q).split() if t]
        scored: List[tuple[int, ExtensionRecord]] = []
        for rec in all_recs:
            hay = f"{rec.name} {rec.description} {' '.join(rec.tags)} {' '.join(rec.task_categories)} {rec.extension_id}".lower()
            score = 0
            if q == rec.name.lower() or q == rec.extension_id.lower():
                score += 100
            elif q in rec.name.lower():
                score += 50
            elif q in hay:
                score += 25
            for term in terms:
                if term in rec.name.lower().split("-"):
                    score += 20
                elif term in rec.name.lower():
                    score += 12
                elif term in [t.lower() for t in rec.tags]:
                    score += 10
                elif term in hay:
                    score += 4
            if score > 0:
                scored.append((score, rec))
        scored.sort(key=lambda x: (-x[0], x[1].extension_id))
        return [r for _, r in scored[:limit]]

    def inspect(self, extension_id: str) -> Optional[ExtensionRecord]:
        cand_path = Path(extension_id)
        if cand_path.exists():
            skill_dir = cand_path.parent if cand_path.is_file() else cand_path
            if (skill_dir / "SKILL.md").exists():
                recs = self._scan_single_root(skill_dir, "local-custom", "community")
                if recs:
                    return recs[0]
        self.scan_all_local()
        target = extension_id.strip().lower()
        return self._by_id.get(target)

    def fetch_bundle(self, extension_id: str, record: Optional[ExtensionRecord] = None) -> Optional[ExtensionBundle]:
        rec = record or self.inspect(extension_id)
        if not rec:
            return None
        skill_dir = Path(rec.source_path)
        if not skill_dir.exists() or not skill_dir.is_dir():
            return None
        files: Dict[str, str | bytes] = {}
        for f in sorted(skill_dir.rglob("*")):
            if f.is_symlink() or not f.is_file():
                continue
            rel = f.relative_to(skill_dir).as_posix()
            if rel.startswith(".") or "__pycache__" in rel.split("/") or rel.endswith(".pyc"):
                continue
            try:
                safe_rel = validate_bundle_rel_path(rel)
            except ValueError:
                continue
            try:
                files[safe_rel] = f.read_text(encoding="utf-8-sig")
            except UnicodeDecodeError:
                try:
                    files[safe_rel] = f.read_bytes()
                except OSError:
                    continue
            except OSError:
                continue
        if "SKILL.md" not in files:
            return None
        c_hash = compute_directory_content_hash(skill_dir)
        rec.content_hash = c_hash
        return ExtensionBundle(
            extension_id=rec.extension_id,
            name=rec.name,
            extension_type=rec.extension_type,
            source_provider=rec.source_provider,
            trust_level=rec.trust_level,
            files=files,
            record=rec,
            content_hash=c_hash,
            metadata={"local_path": str(skill_dir.resolve())},
        )
