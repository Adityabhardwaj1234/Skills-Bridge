# SkillBridge Source Provider & Ecosystem Compatibility

SkillBridge isolates every external catalog and local directory behind the `ExtensionProvider` abstract interface (`src/skillbridge/providers/base.py`), normalizing heterogeneous manifests into `ExtensionRecord` objects.

## 1. Supported Extension Formats & Ecosystems

### A. Agent Skills Open Standard (`SKILL.md`)
- **Official References**: [Anthropic Agent Skills Repository](https://github.com/anthropics/skills), [Mintlify SKILL.md Specification](https://www.mintlify.com/docs/ai/skillmd).
- **Format**: A directory `<skill-name>/` containing a `SKILL.md` file with YAML frontmatter (`---`) and Markdown instructions, plus optional subdirectories (`references/`, `scripts/`, `examples/`, `assets/`).
- **Frontmatter Fields Parsed by SkillBridge**:
  - `name` (required slug: lowercase alphanumeric and hyphens `^[a-z0-9]+(-[a-z0-9]+)*$`)
  - `description` (trigger description used for discovery and ranking)
  - `version`, `author`, `license`
  - `tags`, `categories`, `capabilities`, `platforms`
  - `allowed-tools` / `tools`
  - `dependencies` / `requires` / `metadata.hermes`

### B. Hermes 100k+ Skills Hub Ecosystem (`providers/hermes_hub.py`)
SkillBridge incorporates full compatibility with the Hermes Agent skill ecosystem (`tools/skills_hub.py` and `tools/skills_sync.py`):
1. **Bundled & Optional Hermes Catalog (`HermesBundledCatalogProvider`)**:
   - Ships with **732 real Hermes skills and subagents** (`bundled_skills/`, `optional_skills/`, and `index_cache/` snapshots) and **70 curated MCP servers** (`optional_mcps/`) inside `src/skillbridge/data/hermes_catalog/`.
   - Works 100% offline with zero network latency and populates the SQLite + FTS5 catalog on first initialization.
2. **Hermes Centralized 100k+ Index (`HermesCentralIndexProvider`)**:
   - Endpoint: `https://hermes-agent.nousresearch.com/docs/api/skills-index.json`
   - Aggregates over 100,000 community skills across GitHub taps, Skills.sh, ClawHub, and LobeHub into a compressed index, with automatic fallback to the local bundled snapshot when offline.
3. **Vercel Skills.sh (`SkillsShProvider`)**:
   - Endpoint: `https://skills.sh/api/search?q=<query>&limit=<n>`
   - Maps `source` (`owner/repo`) and `skillId` to canonical GitHub paths (`skills/<skillId>/SKILL.md`) and normalizes install telemetry counts (`installs`) as a secondary provenance signal.
4. **ClawHub (`ClawHubProvider`)**:
   - Search Endpoint: `https://clawhub.ai/api/v1/search?q=<query>&limit=<n>`
   - Download Endpoint: `https://clawhub.ai/api/v1/download?slug=<slug>`
   - Downloads skill ZIP packages into an isolated staging directory using `ClawHubProvider.extract_zip_safely()`, which validates every entry against path traversal (`..`), POSIX symlinks (`0o120000`), per-file byte limits, and total archive byte limits before running the security scanner.
5. **LobeHub Agent Store (`LobeHubProvider`)**:
   - Endpoint: `https://chat-agents.lobehub.com/index.json`
   - Converts LobeHub JSON agent definitions (`meta.title`, `meta.description`, `meta.tags`, ` config.systemRole`) into compliant `SKILL.md` directories via `convert_agent_to_skill_md()`.
6. **Claude Marketplace / Browse.sh (`ClaudeMarketplaceProvider`)**:
   - Endpoint: `https://browse.sh/index.json`

### C. GitHub Repositories & Taps (`GitHubSkillProvider`)
- Supports querying official and community skill taps (`anthropics/skills`, `openai/skills`, `VoltAgent/awesome-openclaw-skills`, `Prompts.chat`) via the GitHub Contents and Git Trees REST API (`https://api.github.com/repos/{owner}/{repo}/git/trees/{ref}?recursive=1`).
- Supports repository alias expansion (e.g., `gh:anthropics/skills` -> `https://github.com/anthropics/skills`) and pins resolved commit SHAs (`version`) for content integrity.

### D. RFC 8615 Well-Known Skills Endpoints (`WellKnownSkillsProvider`)
- Queries `https://<domain>/.well-known/skills/index.json` (as documented in the [Mintlify `SKILL.md` standard](https://www.mintlify.com/docs/ai/skillmd)) and resolves relative `url`/`path` references against the origin domain after verifying SSRF safety.

### E. Official MCP Registry (`MCPRegistryProvider`)
- **Official References**: [Official MCP Registry Documentation](https://registry.modelcontextprotocol.io/docs), [Official Registry API Specification](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/api/official-registry-api.md).
- **Endpoint**: `https://registry.modelcontextprotocol.io/v0/servers?q=<query>&limit=<n>`
- **Response Parsing**: Extracts `name`, `description`, `version_detail.version`, `repository.url`, and `packages[]` (`registry_name`: `npm`, `pypi`, `oci`; `runtime_hint`: `npx`, `uvx`, `docker`; `environment_variables`), mapping them to `TransportType.STDIO`, `TransportType.HTTP`, or `TransportType.SSE` without silently converting transports.

---

## 2. Network Safety & Resilience Controls

All remote providers use `fetch_url_safe()` (`src/skillbridge/providers/base.py`), which enforces:
- **Explicit Connect/Read Timeouts**: Configurable `http_timeout_seconds` (default `8.0s`).
- **Bounded Response Sizes**: Reads in chunks up to `max_http_response_bytes` (default `2 MB`), aborting oversized responses immediately (`ResponseTooLargeError`).
- **Safe Redirect Validation**: Custom `_SafeRedirectHandler` re-validates every `301`/`302`/`307`/`308` redirect target against `validate_safe_url()` to prevent redirect-based SSRF to internal networks.
- **Retry with Exponential Backoff**: Retries transient `5xx`, `429`, and socket timeout errors up to `http_max_retries` times before gracefully degrading to the local SQLite catalog.
- **Strict Offline Mode**: Passing `--offline` or `SkillBridgeConfig(offline_mode=True)` disables all network calls (`OfflineModeError` in remote providers) while keeping local and bundled Hermes discovery 100% operational.
