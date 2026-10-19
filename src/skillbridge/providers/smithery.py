"""Smithery MCP Registry Provider (`https://registry.smithery.ai/servers`).

Discovers publicly listed MCP servers from the Smithery registry, normalizes them into
`ExtensionRecord`s with local (stdio via `npx @smithery/cli run`) or remote (streamable HTTP)
transports, and exposes their manifests for preview/scanning/installation.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from skillbridge.config import SkillBridgeConfig
from skillbridge.discovery.normalizer import compute_bundle_content_hash
from skillbridge.models import (
    DependencySpec,
    ExtensionBundle,
    ExtensionRecord,
    ExtensionType,
    MCPTransportSpec,
    TrustLevel,
)
from skillbridge.providers.base import ExtensionProvider, GuardedHttpClient


class SmitheryMCPProvider(ExtensionProvider):
    """Discovers MCP servers from the public Smithery registry."""

    PROVIDER_ID = "smithery"
    EXTENSION_TYPE = ExtensionType.MCP_SERVER.value
    REGISTRY_API_URL = "https://registry.smithery.ai/servers"
    HOSTED_MCP_TEMPLATE = "https://server.smithery.ai/{qualified}/mcp"

    def __init__(self, config: Optional[SkillBridgeConfig] = None, http_client: Optional[GuardedHttpClient] = None):
        self.config = config or SkillBridgeConfig()
        self.http = http_client or GuardedHttpClient(self.config.network)

    def _parse_server(self, item: Dict[str, Any], detail: Optional[Dict[str, Any]] = None) -> Optional[ExtensionRecord]:
        if not isinstance(item, dict):
            return None
        merged: Dict[str, Any] = dict(item)
        if isinstance(detail, dict):
            merged.update({k: v for k, v in detail.items() if v is not None})
        qualified = str(merged.get("qualifiedName") or "").strip("/")
        if not qualified or "/" not in qualified:
            return None
        slug = str(merged.get("slug") or qualified.split("/")[-1]).strip()
        display = str(merged.get("displayName") or slug).strip()
        desc = str(merged.get("description") or f"Smithery MCP server {qualified}").strip()
        verified = bool(merged.get("verified"))
        use_count = merged.get("useCount")

        transport = self._build_transport(merged, qualified)
        deps: List[DependencySpec] = []
        if transport.transport_type == "stdio":
            deps = [DependencySpec(kind="executable", name="npx"), DependencySpec(kind="executable", name="node")]

        tags = ["mcp", slug, transport.transport_type]
        if verified:
            tags.append("verified")
        homepage = str(merged.get("homepage") or "").strip()

        return ExtensionRecord(
            extension_id=f"smithery/{qualified}",
            name=slug,
            display_name=display,
            extension_type=ExtensionType.MCP_SERVER.value,
            description=desc[:1024],
            source_provider=self.PROVIDER_ID,
            canonical_uri=homepage or f"https://smithery.ai/server/{qualified}",
            version_or_revision=str(merged.get("createdAt") or "latest"),
            trust_level=TrustLevel.TRUSTED.value if verified else TrustLevel.COMMUNITY.value,
            tags=tags,
            task_categories=["mcp"],
            capabilities=[slug],
            dependencies=deps,
            popularity_signals={"use_count": int(use_count)} if isinstance(use_count, (int, float)) else {},
            mcp_transport=transport,
            extra_metadata={"qualified_name": qualified, "verified": verified, "by_smithery": bool(merged.get("bySmithery"))},
        )

    def _build_transport(self, merged: Dict[str, Any], qualified: str) -> MCPTransportSpec:
        connections = merged.get("connections") if isinstance(merged.get("connections"), list) else []
        for conn in connections:
            if not isinstance(conn, dict):
                continue
            deployment = str(conn.get("deploymentUrl") or conn.get("url") or "").strip()
            if deployment:
                return MCPTransportSpec(transport_type=str(conn.get("type") or "http"), url=deployment)
        if bool(merged.get("remote")):
            return MCPTransportSpec(
                transport_type="http",
                url=self.HOSTED_MCP_TEMPLATE.format(qualified=qualified),
            )
        return MCPTransportSpec(
            transport_type="stdio",
            command="npx",
            args=["-y", "@smithery/cli@latest", "run", qualified],
        )

    def search(self, query: str, limit: int = 20) -> List[ExtensionRecord]:
        if self.config.network.offline_mode:
            return []
        data = self.http.get_json(
            self.REGISTRY_API_URL,
            params={"q": query, "pageSize": max(1, min(limit, 50))},
        )
        servers = data.get("servers", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
        if not isinstance(servers, list):
            return []
        out: List[ExtensionRecord] = []
        for item in servers:
            if not isinstance(item, dict) or bool(item.get("unlisted")):
                continue
            rec = self._parse_server(item)
            if rec:
                out.append(rec)
            if len(out) >= limit:
                break
        return out

    def inspect(self, extension_id: str) -> Optional[ExtensionRecord]:
        clean = extension_id.strip()
        for prefix in ("smithery/", "mcp-smithery/"):
            clean = clean.removeprefix(prefix)
        if not clean:
            return None
        if self.config.network.offline_mode:
            return None
        detail = self.http.get_json(f"{self.REGISTRY_API_URL}/{quote(clean, safe='@/.-')}")
        if isinstance(detail, dict) and detail.get("qualifiedName"):
            return self._parse_server(detail, detail)
        # Fallback: match by slug through a single search page
        for rec in self.search(clean.split("/")[-1], limit=10):
            if rec.extension_id.lower() == f"smithery/{clean}".lower() or rec.name.lower() == clean.split("/")[-1].lower():
                return rec
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
