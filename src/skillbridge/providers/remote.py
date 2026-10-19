"""GitHub repository, /.well-known/skills/ endpoint, and Official MCP Registry providers."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urljoin, urlparse, urlunparse

import yaml

from skillbridge.config import SkillBridgeConfig
from skillbridge.discovery.normalizer import (
    compute_bundle_content_hash,
    extract_referenced_support_paths,
    normalize_repo_alias,
    parse_skill_md,
    validate_bundle_rel_path,
    validate_skill_name,
)
from skillbridge.models import (
    DependencySpec,
    ExtensionBundle,
    ExtensionRecord,
    ExtensionType,
    MCPTransportSpec,
    TrustLevel,
)
from skillbridge.providers.base import ExtensionProvider, GuardedHttpClient

logger = logging.getLogger("skillbridge.providers.remote")


class GitHubSkillsProvider(ExtensionProvider):
    """Discovers and fetches skills from GitHub repositories with revision-pinned tree validation."""

    PROVIDER_ID = "github"
    EXTENSION_TYPE = ExtensionType.SKILL.value
    API_BASE = "https://api.github.com/repos"
    RAW_BASE = "https://raw.githubusercontent.com"

    def __init__(self, config: Optional[SkillBridgeConfig] = None, http_client: Optional[GuardedHttpClient] = None):
        self.config = config or SkillBridgeConfig()
        self.http = http_client or GuardedHttpClient(self.config.network)

    def _resolve_trust(self, repo: str) -> str:
        r_low = repo.strip().lower()
        for trusted in self.config.security_policy.trusted_repos:
            if r_low == trusted.lower():
                return TrustLevel.TRUSTED.value
        return TrustLevel.COMMUNITY.value

    def _split_identifier(self, identifier: str) -> Optional[tuple[str, str]]:
        cleaned = normalize_repo_alias(identifier.removeprefix("github/").removeprefix("skills.sh/").removeprefix("skills-sh/"))
        parts = [p for p in cleaned.split("/") if p]
        if len(parts) < 2:
            return None
        repo = f"{parts[0]}/{parts[1]}"
        subpath = "/".join(parts[2:])
        return repo, subpath

    def search(self, query: str, limit: int = 15) -> List[ExtensionRecord]:
        # Check if query itself is a GitHub repo or alias
        split = self._split_identifier(query) if ("/" in query or query.lower() in ("anthropic", "openai", "nvidia", "huggingface")) else None
        if split and not self.config.network.offline_mode:
            rec = self.inspect(query)
            return [rec] if rec else []
        return []

    def inspect(self, extension_id: str) -> Optional[ExtensionRecord]:
        if self.config.network.offline_mode:
            return None
        split = self._split_identifier(extension_id)
        if not split:
            return None
        repo, subpath = split
        skill_md_path = f"{subpath}/SKILL.md" if subpath else "SKILL.md"
        raw_url = f"{self.RAW_BASE}/{repo}/main/{quote(skill_md_path, safe='/')}"
        content = self.http.get_text(raw_url)
        if content is None:
            api_url = f"{self.API_BASE}/{repo}/contents/{quote(skill_md_path, safe='/')}"
            content = self.http.get_text(api_url, headers={"Accept": "application/vnd.github.v3.raw"})
        if not content:
            return None
        fm, _ = parse_skill_md(content)
        name = str(fm.get("name") or (subpath.split("/")[-1] if subpath else repo.split("/")[-1]))
        desc = str(fm.get("description") or f"GitHub skill {name} from {repo}")
        tags = [str(t) for t in fm.get("tags", [])] if isinstance(fm.get("tags"), list) else []
        return ExtensionRecord(
            extension_id=f"github/{repo}/{subpath}".rstrip("/"),
            name=name,
            display_name=name,
            extension_type=ExtensionType.SKILL.value,
            description=desc[:1024],
            source_provider="github",
            canonical_uri=f"https://github.com/{repo}/tree/main/{subpath}".rstrip("/"),
            repo=repo,
            source_path=subpath,
            trust_level=self._resolve_trust(repo),
            tags=tags,
        )

    def fetch_bundle(self, extension_id: str) -> Optional[ExtensionBundle]:
        if self.config.network.offline_mode:
            return None
        split = self._split_identifier(extension_id)
        if not split:
            return None
        repo, subpath = split
        # Fetch repo metadata & tree SHA first to pin all file fetches to the same revision (prevents TOCTOU)
        repo_meta = self.http.get_json(f"{self.API_BASE}/{repo}")
        branch = repo_meta.get("default_branch", "main") if isinstance(repo_meta, dict) else "main"
        tree_data = self.http.get_json(f"{self.API_BASE}/{repo}/git/trees/{branch}", params={"recursive": "1"})
        ref = tree_data.get("sha", branch) if isinstance(tree_data, dict) else branch

        skill_md_path = f"{subpath}/SKILL.md" if subpath else "SKILL.md"
        skill_md = self.http.get_text(f"{self.RAW_BASE}/{repo}/{ref}/{quote(skill_md_path, safe='/')}")
        if skill_md is None:
            skill_md = self.http.get_text(
                f"{self.API_BASE}/{repo}/contents/{quote(skill_md_path, safe='/')}",
                params={"ref": ref},
                headers={"Accept": "application/vnd.github.v3.raw"},
            )
        if skill_md is None and subpath and isinstance(tree_data, dict) and isinstance(tree_data.get("tree"), list):
            # Marketplace indexes commonly report only the skill folder name (e.g. "pdf") while
            # the repo nests it (e.g. "skills/pdf"). Resolve the real directory by matching the
            # path suffix against every SKILL.md directory in the pinned tree, shallowest first.
            suffix = "/" + subpath.strip("/")
            candidates = []
            for entry in tree_data["tree"]:
                path = str(entry.get("path") or "")
                if entry.get("type") != "blob" or not path.endswith("/SKILL.md"):
                    continue
                dir_path = path[: -len("/SKILL.md")]
                if dir_path == subpath or dir_path.endswith(suffix):
                    candidates.append(dir_path)
            candidates.sort(key=len)
            for candidate in candidates:
                resolved_md = f"{candidate}/SKILL.md"
                skill_md = self.http.get_text(f"{self.RAW_BASE}/{repo}/{ref}/{quote(resolved_md, safe='/')}")
                if skill_md is None:
                    skill_md = self.http.get_text(
                        f"{self.API_BASE}/{repo}/contents/{quote(resolved_md, safe='/')}",
                        params={"ref": ref},
                        headers={"Accept": "application/vnd.github.v3.raw"},
                    )
                if skill_md is not None:
                    subpath = candidate
                    break
        if skill_md is None:
            return None

        referenced = extract_referenced_support_paths(skill_md)
        if referenced is None:
            logger.warning("Rejected GitHub skill %s due to suspicious path traversal in references", extension_id)
            return None

        files: Dict[str, str | bytes] = {"SKILL.md": skill_md}
        prefix = f"{subpath.rstrip('/')}/" if subpath else ""

        if isinstance(tree_data, dict) and isinstance(tree_data.get("tree"), list):
            for entry in tree_data["tree"]:
                path = str(entry.get("path") or "")
                if not path.startswith(prefix):
                    continue
                rel = path[len(prefix) :]
                if not rel or rel == "SKILL.md" or rel.startswith("."):
                    continue
                # Reject symlinks (mode 120000)
                if entry.get("mode") == "120000" or entry.get("type") != "blob":
                    if rel in referenced:
                        logger.warning("Rejected GitHub skill %s: referenced file %s is a symlink", extension_id, rel)
                        return None
                    continue
                try:
                    safe_rel = validate_bundle_rel_path(rel)
                except ValueError:
                    return None
                f_text = self.http.get_text(f"{self.RAW_BASE}/{repo}/{ref}/{quote(path, safe='/')}")
                if f_text is not None:
                    files[safe_rel] = f_text
        else:
            for rel in sorted(referenced):
                item_path = f"{prefix}{rel}"
                f_text = self.http.get_text(f"{self.RAW_BASE}/{repo}/{ref}/{quote(item_path, safe='/')}")
                if f_text is not None:
                    files[rel] = f_text

        fm, _ = parse_skill_md(skill_md)
        name = str(fm.get("name") or (subpath.split("/")[-1] if subpath else repo.split("/")[-1]))
        c_hash = compute_bundle_content_hash(files)
        rec = self.inspect(extension_id)
        if rec:
            rec.version_or_revision = ref
            rec.content_hash = c_hash
        return ExtensionBundle(
            extension_id=f"github/{repo}/{subpath}".rstrip("/"),
            name=name,
            extension_type=ExtensionType.SKILL.value,
            source_provider="github",
            trust_level=self._resolve_trust(repo),
            files=files,
            record=rec,
            content_hash=c_hash,
            metadata={"repo": repo, "revision": ref, "source_url": f"https://github.com/{repo}/tree/{ref}/{subpath}".rstrip("/")},
        )


class WellKnownSkillsProvider(ExtensionProvider):
    """Discovers and fetches skills from RFC /.well-known/skills/index.json endpoints."""

    PROVIDER_ID = "well-known"
    EXTENSION_TYPE = ExtensionType.SKILL.value
    BASE_PATH = "/.well-known/skills"

    def __init__(self, config: Optional[SkillBridgeConfig] = None, http_client: Optional[GuardedHttpClient] = None):
        self.config = config or SkillBridgeConfig()
        self.http = http_client or GuardedHttpClient(self.config.network)

    def _to_index_url(self, url_or_query: str) -> Optional[str]:
        q = url_or_query.strip().removeprefix("well-known:")
        if not q.startswith(("http://", "https://")):
            return None
        if q.endswith("/index.json"):
            return q
        if f"{self.BASE_PATH}/" in q:
            base = q.split(f"{self.BASE_PATH}/", 1)[0]
            return f"{base}{self.BASE_PATH}/index.json"
        return f"{q.rstrip('/')}{self.BASE_PATH}/index.json"

    def search(self, query: str, limit: int = 10) -> List[ExtensionRecord]:
        if self.config.network.offline_mode:
            return []
        index_url = self._to_index_url(query)
        if not index_url:
            return []
        data = self.http.get_json(index_url)
        skills = data.get("skills", []) if isinstance(data, dict) else []
        if not isinstance(skills, list):
            return []
        base_url = index_url[: -len("/index.json")]
        out: List[ExtensionRecord] = []
        for entry in skills[:limit]:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name") or "").strip()
            if not name:
                continue
            files = entry.get("files", ["SKILL.md"])
            out.append(
                ExtensionRecord(
                    extension_id=f"well-known:{base_url}/{name}",
                    name=name,
                    display_name=name,
                    extension_type=ExtensionType.SKILL.value,
                    description=str(entry.get("description") or f"Well-known skill {name}")[:1024],
                    source_provider="well-known",
                    canonical_uri=f"{base_url}/{name}/SKILL.md",
                    source_path=name,
                    trust_level=TrustLevel.COMMUNITY.value,
                    extra_metadata={"index_url": index_url, "base_url": base_url, "files": files},
                )
            )
        return out

    def inspect(self, extension_id: str) -> Optional[ExtensionRecord]:
        if self.config.network.offline_mode:
            return None
        raw = extension_id.strip().removeprefix("well-known:")
        if not raw.startswith(("http://", "https://")) or f"{self.BASE_PATH}/" not in raw:
            return None
        clean = raw[:-len("/SKILL.md")] if raw.endswith("/SKILL.md") else raw.rstrip("/")
        base_url, skill_name = clean.rsplit("/", 1)
        records = self.search(f"{base_url}/index.json", limit=100)
        for rec in records:
            if rec.name == skill_name:
                return rec
        return None

    def fetch_bundle(self, extension_id: str) -> Optional[ExtensionBundle]:
        if self.config.network.offline_mode:
            return None
        rec = self.inspect(extension_id)
        if not rec:
            return None
        try:
            safe_name = validate_skill_name(rec.name)
        except ValueError:
            return None
        base_url = rec.extra_metadata.get("base_url", "")
        file_list = rec.extra_metadata.get("files", ["SKILL.md"])
        if not isinstance(file_list, list) or not file_list:
            file_list = ["SKILL.md"]
        downloaded: Dict[str, str | bytes] = {}
        for rel_path in file_list:
            if not isinstance(rel_path, str):
                continue
            try:
                safe_rel = validate_bundle_rel_path(rel_path)
            except ValueError:
                logger.warning("Well-known skill %s advertised unsafe path %r", extension_id, rel_path)
                return None
            file_url = f"{base_url}/{safe_name}/{safe_rel}"
            if urlparse(file_url).netloc != urlparse(base_url).netloc:
                return None
            text = self.http.get_text(file_url)
            if text is None:
                return None
            downloaded[safe_rel] = text
        if "SKILL.md" not in downloaded:
            return None
        c_hash = compute_bundle_content_hash(downloaded)
        rec.content_hash = c_hash
        return ExtensionBundle(
            extension_id=rec.extension_id,
            name=safe_name,
            extension_type=ExtensionType.SKILL.value,
            source_provider="well-known",
            trust_level=TrustLevel.COMMUNITY.value,
            files=downloaded,
            record=rec,
            content_hash=c_hash,
            metadata=rec.extra_metadata,
        )


class MCPRegistryProvider(ExtensionProvider):
    """Discovers and inspects MCP servers from the Official MCP Registry (registry.modelcontextprotocol.io)
    and the bundled Nous-approved 65+ MCP server catalog (`optional_mcps`).
    """

    PROVIDER_ID = "mcp-registry"
    EXTENSION_TYPE = ExtensionType.MCP_SERVER.value
    REGISTRY_API_URL = "https://registry.modelcontextprotocol.io/v0/servers"

    # Standard local stdio reference MCP servers so users can discover both local stdio and remote HTTP MCPs offline
    BUILTIN_STDIO_MCPS: List[Dict[str, Any]] = [
        {
            "name": "filesystem",
            "id": "mcp/filesystem",
            "description": "Official MCP filesystem server for reading, writing, and searching local directories safely.",
            "transport": {"transport_type": "stdio", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "."]},
            "deps": [{"kind": "executable", "name": "npx"}, {"kind": "executable", "name": "node"}],
            "tags": ["filesystem", "files", "local", "stdio", "io"],
        },
        {
            "name": "playwright",
            "id": "mcp/playwright",
            "description": "Playwright MCP server for browser automation, E2E testing, DOM inspection, and screenshots.",
            "transport": {"transport_type": "stdio", "command": "npx", "args": ["-y", "@playwright/mcp@latest"]},
            "deps": [{"kind": "executable", "name": "npx"}, {"kind": "executable", "name": "node"}],
            "tags": ["playwright", "browser", "frontend", "testing", "automation"],
        },
        {
            "name": "postgres",
            "id": "mcp/postgres",
            "description": "PostgreSQL MCP server for inspecting database schemas and running read-only SQL queries.",
            "transport": {
                "transport_type": "stdio",
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-postgres"],
                "env": {"POSTGRES_URL": "${POSTGRES_URL}"},
                "auth_type": "api_key",
            },
            "deps": [{"kind": "executable", "name": "npx"}, {"kind": "env_var", "name": "POSTGRES_URL", "secret": True}],
            "tags": ["postgres", "database", "sql", "schema"],
        },
        {
            "name": "git",
            "id": "mcp/git",
            "description": "Official Git MCP server for repository history, diff inspection, branch management, and commit search.",
            "transport": {"transport_type": "stdio", "command": "uvx", "args": ["mcp-server-git", "--repository", "."]},
            "deps": [{"kind": "executable", "name": "git"}],
            "tags": ["git", "repository", "commits", "version-control"],
        },
        {
            "name": "skillbridge",
            "id": "mcp/skillbridge",
            "description": "SkillBridge self-hosted MCP server exposing dynamic skill preflight, search, preview, loading, unloading, and installer tools.",
            "transport": {"transport_type": "stdio", "command": "python3", "args": ["-m", "skillbridge", "mcp-serve"]},
            "deps": [{"kind": "executable", "name": "python3"}],
            "tags": ["skillbridge", "skills", "orchestration", "preflight", "mcp"],
        },
    ]

    def __init__(self, config: Optional[SkillBridgeConfig] = None, http_client: Optional[GuardedHttpClient] = None):
        self.config = config or SkillBridgeConfig()
        self.http = http_client or GuardedHttpClient(self.config.network)
        self._local_mcps: Optional[List[ExtensionRecord]] = None

    def _load_local_mcp_catalog(self) -> List[ExtensionRecord]:
        if self._local_mcps is not None:
            return self._local_mcps

        records: List[ExtensionRecord] = []
        # 1. Load builtin stdio MCPs
        for item in self.BUILTIN_STDIO_MCPS:
            t_spec = MCPTransportSpec(**item["transport"])
            deps = [DependencySpec(**d) for d in item.get("deps", [])]
            records.append(
                ExtensionRecord(
                    extension_id=item["id"],
                    name=item["name"],
                    display_name=item["name"],
                    extension_type=ExtensionType.MCP_SERVER.value,
                    description=item["description"],
                    source_provider="mcp-catalog",
                    canonical_uri="https://registry.modelcontextprotocol.io",
                    trust_level=TrustLevel.TRUSTED.value,
                    security_verdict="SAFE",
                    tags=item["tags"],
                    task_categories=["mcp", item["tags"][0]],
                    capabilities=item["tags"],
                    dependencies=deps,
                    mcp_transport=t_spec,
                )
            )

        # 2. Load 65 Nous-curated optional-mcps manifests from bundled Hermes catalog
        mcps_dir = self.config.bundled_data_dir / "optional_mcps"
        if mcps_dir.is_dir():
            for manifest_path in sorted(mcps_dir.glob("*/manifest.yaml")):
                try:
                    raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8-sig"))
                except (OSError, yaml.YAMLError):
                    continue
                if not isinstance(raw, dict):
                    continue
                name = str(raw.get("name") or manifest_path.parent.name).strip()
                desc = str(raw.get("description") or f"MCP server {name}").strip()
                source_uri = str(raw.get("source") or "")
                t_raw = raw.get("transport") or {}
                a_raw = raw.get("auth") or {}
                s_raw = raw.get("suggest") or {}

                t_type = str(t_raw.get("type") or "stdio")
                auth_type = str(a_raw.get("type") or "none")
                env_dict: Dict[str, str] = {}
                if isinstance(t_raw.get("env"), dict):
                    env_dict.update({str(k): str(v) for k, v in t_raw["env"].items()})
                deps: List[DependencySpec] = []
                if isinstance(a_raw.get("env"), list):
                    for ev in a_raw["env"]:
                        if isinstance(ev, dict) and ev.get("name"):
                            ev_name = str(ev["name"])
                            env_dict[ev_name] = f"${{{ev_name}}}"
                            deps.append(
                                DependencySpec(
                                    kind="env_var",
                                    name=ev_name,
                                    required=bool(ev.get("required", True)),
                                    secret=bool(ev.get("secret", True)),
                                    description=str(ev.get("prompt") or ""),
                                )
                            )
                cmd = t_raw.get("command")
                if cmd:
                    deps.append(DependencySpec(kind="executable", name=str(cmd)))

                transport = MCPTransportSpec(
                    transport_type=t_type,
                    command=str(cmd) if cmd else None,
                    args=[str(a) for a in t_raw.get("args", [])] if isinstance(t_raw.get("args"), list) else [],
                    url=str(t_raw.get("url")) if t_raw.get("url") else None,
                    env=env_dict,
                    auth_type=auth_type,
                    oauth_config=a_raw.get("oauth", {}) if isinstance(a_raw.get("oauth"), dict) else {},
                )
                keywords = [str(k) for k in s_raw.get("keywords", [])] if isinstance(s_raw.get("keywords"), list) else []
                tags = list(dict.fromkeys([name, t_type, auth_type, *keywords]))
                records.append(
                    ExtensionRecord(
                        extension_id=f"mcp/{name}",
                        name=name,
                        display_name=name,
                        extension_type=ExtensionType.MCP_SERVER.value,
                        description=desc[:1024],
                        source_provider="hermes-mcp-catalog",
                        canonical_uri=source_uri,
                        source_path=str(manifest_path.resolve()),
                        trust_level=TrustLevel.TRUSTED.value,
                        security_verdict="SAFE",
                        tags=tags,
                        task_categories=["mcp"],
                        capabilities=keywords or [name],
                        dependencies=deps,
                        mcp_transport=transport,
                        extra_metadata={"post_install": str(raw.get("post_install") or "").strip()},
                    )
                )

        self._local_mcps = records
        return records

    def _parse_registry_server(self, item: Dict[str, Any]) -> Optional[ExtensionRecord]:
        server = item.get("server", item) if isinstance(item, dict) else {}
        if not isinstance(server, dict):
            return None
        name = str(server.get("name") or server.get("id") or "").strip()
        if not name:
            return None
        short_name = name.split("/")[-1]
        desc = str(server.get("description") or f"MCP Registry server {name}")
        version = str(server.get("version") or "latest")
        repo_info = server.get("repository") if isinstance(server.get("repository"), dict) else {}
        repo_url = str(repo_info.get("url") or "")

        # Parse packages / remotes from Official MCP Registry v0 schema
        packages = server.get("packages") if isinstance(server.get("packages"), list) else []
        remotes = server.get("remotes") if isinstance(server.get("remotes"), list) else []
        transport: Optional[MCPTransportSpec] = None
        deps: List[DependencySpec] = []

        if remotes and isinstance(remotes[0], dict):
            r0 = remotes[0]
            transport = MCPTransportSpec(
                transport_type=str(r0.get("transport_type") or r0.get("type") or "http"),
                url=str(r0.get("url") or ""),
            )
        elif packages and isinstance(packages[0], dict):
            p0 = packages[0]
            reg_name = str(p0.get("registry_name") or p0.get("registry_type") or "npm")
            pkg_id = str(p0.get("name") or p0.get("identifier") or short_name)
            runtime = "npx" if reg_name == "npm" else ("uvx" if reg_name in ("pypi", "python") else str(p0.get("runtime_hint") or "npx"))
            args = ["-y", pkg_id] if runtime == "npx" else [pkg_id]
            env_vars: Dict[str, str] = {}
            for ev in p0.get("environment_variables", []) if isinstance(p0.get("environment_variables"), list) else []:
                if isinstance(ev, dict) and ev.get("name"):
                    ev_name = str(ev["name"])
                    env_vars[ev_name] = f"${{{ev_name}}}"
                    deps.append(DependencySpec(kind="env_var", name=ev_name, required=bool(ev.get("is_required", True)), secret=bool(ev.get("is_secret", True))))
            deps.append(DependencySpec(kind="executable", name=runtime))
            transport = MCPTransportSpec(
                transport_type="stdio",
                command=runtime,
                args=args,
                env=env_vars,
            )
        else:
            transport = MCPTransportSpec(transport_type="stdio", command="npx", args=["-y", name])

        return ExtensionRecord(
            extension_id=f"mcp-registry/{name}",
            name=short_name,
            display_name=name,
            extension_type=ExtensionType.MCP_SERVER.value,
            description=desc[:1024],
            source_provider="mcp-registry",
            canonical_uri=repo_url or f"https://registry.modelcontextprotocol.io/v0/servers?search={name}",
            version_or_revision=version,
            trust_level=TrustLevel.COMMUNITY.value,
            tags=["mcp", short_name, transport.transport_type],
            task_categories=["mcp"],
            capabilities=[short_name],
            dependencies=deps,
            mcp_transport=transport,
        )

    def search(self, query: str, limit: int = 20) -> List[ExtensionRecord]:
        local_recs = self._load_local_mcp_catalog()
        q = query.strip().lower()
        results: List[ExtensionRecord] = []
        if not q:
            results.extend(local_recs[:limit])
        else:
            terms = [t for t in "".join(c if c.isalnum() else " " for c in q).split() if t]
            scored: List[tuple[int, ExtensionRecord]] = []
            for rec in local_recs:
                hay = f"{rec.name} {rec.description} {' '.join(rec.tags)} {rec.extension_id}".lower()
                score = 0
                if q == rec.name.lower() or q == rec.extension_id.lower():
                    score += 100
                elif q in rec.name.lower():
                    score += 50
                elif q in hay:
                    score += 25
                for term in terms:
                    if term in rec.name.lower():
                        score += 15
                    elif term in hay:
                        score += 5
                if score > 0:
                    scored.append((score, rec))
            scored.sort(key=lambda x: (-x[0], x[1].extension_id))
            results.extend(r for _, r in scored[:limit])

        if len(results) < limit and not self.config.network.offline_mode:
            data = self.http.get_json(self.REGISTRY_API_URL, params={"search": query, "limit": limit - len(results)})
            servers = data.get("servers", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
            if isinstance(servers, list):
                for item in servers:
                    rec = self._parse_registry_server(item)
                    if rec:
                        results.append(rec)
                        if len(results) >= limit:
                            break
        return results[:limit]

    def inspect(self, extension_id: str) -> Optional[ExtensionRecord]:
        target = extension_id.strip().lower()
        for rec in self._load_local_mcp_catalog():
            if rec.extension_id.lower() == target or rec.name.lower() == target:
                return rec
        if not self.config.network.offline_mode:
            clean = extension_id.removeprefix("mcp-registry/").removeprefix("mcp/")
            data = self.http.get_json(f"{self.REGISTRY_API_URL}/{quote(clean, safe='')}")
            if isinstance(data, dict):
                return self._parse_registry_server(data)
        # No fuzzy search here: an unknown identifier must never silently resolve to an
        # unrelated MCP server (that would make a failed skill load appear to succeed).
        return None

    def fetch_bundle(self, extension_id: str) -> Optional[ExtensionBundle]:
        rec = self.inspect(extension_id)
        if not rec:
            return None
        manifest_json = json.dumps(rec.to_dict(), indent=2)
        files = {"mcp_manifest.json": manifest_json}
        c_hash = compute_bundle_content_hash(files)
        rec.content_hash = c_hash
        return ExtensionBundle(
            extension_id=rec.extension_id,
            name=rec.name,
            extension_type=ExtensionType.MCP_SERVER.value,
            source_provider=rec.source_provider,
            trust_level=rec.trust_level,
            files=files,
            record=rec,
            content_hash=c_hash,
            metadata={"transport": rec.mcp_transport.__dict__ if rec.mcp_transport else {}},
        )
