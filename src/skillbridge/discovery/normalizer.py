"""Normalization, SKILL.md frontmatter parsing, path safety, reference extraction, and content hashing."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import unquote, urlparse, urlsplit, urlunparse

import yaml

# Agent Skills specification regex for valid skill names (1-64 chars, lowercase alphanumeric + single hyphens)
SKILL_NAME_SPEC_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
# Relaxed identifier regex for legacy community skills (allows underscores/dots in non-leading positions)
SKILL_ID_SAFE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")

ALLOWED_SUPPORT_DIRS = frozenset({"references", "templates", "scripts", "assets", "examples"})
LOCAL_LINK_RE = re.compile(
    r"(?:\]\(\s*|`|(?:^|[\s\"']))((?:references|templates|scripts|assets|examples)/[^\s)`\"'<>]+)",
    re.MULTILINE,
)
SUSPICIOUS_LOCAL_REF_RE = re.compile(
    r"(?:references|templates|scripts|assets|examples)/(?:[^\s)`\"'<>]*/)?\.\.(?:/|$)"
)
SAMEDIR_LINK_RE = re.compile(r"\]\(\s*([^)\s\"'<>]+)")
SAMEDIR_NAME_RE = re.compile(r"^(?:\./)?[A-Za-z0-9][A-Za-z0-9._-]*$")

REPO_ALIASES: Dict[str, str] = {
    "anthropic": "anthropics/skills",
    "anthropics": "anthropics/skills",
    "openai": "openai/skills",
    "huggingface": "huggingface/skills",
    "hf": "huggingface/skills",
    "nvidia": "NVIDIA/skills",
    "hermes": "NousResearch/hermes-agent",
    "nous": "NousResearch/hermes-agent",
    "voltagent": "voltagent/awesome-agent-skills",
    "scientific": "K-Dense-AI/scientific-agent-skills",
    "openscience": "synthetic-sciences/openscience",
}


def parse_skill_md(content: str) -> Tuple[Dict[str, Any], str]:
    """Parse YAML frontmatter and markdown body from SKILL.md content.

    Returns (frontmatter_dict, markdown_body). Returns ({}, full_content) if frontmatter is absent or invalid.
    """
    if not isinstance(content, str):
        return {}, ""
    cleaned = content.lstrip("\ufeff")
    if not cleaned.startswith("---"):
        return {}, cleaned
    match = re.search(r"\r?\n---\s*(?:\r?\n|$)", cleaned[3:])
    if not match:
        return {}, cleaned
    fm_raw = cleaned[3 : match.start() + 3]
    body = cleaned[3 + match.end() :].lstrip("\r\n")
    try:
        parsed = yaml.safe_load(fm_raw)
        if isinstance(parsed, dict):
            return parsed, body
        return {"_invalid_frontmatter": "Frontmatter must be a YAML mapping"}, body
    except yaml.YAMLError as exc:
        return {"_invalid_frontmatter": f"YAML parse error: {exc}"}, body


def validate_skill_frontmatter(frontmatter: Dict[str, Any], expected_dir_name: Optional[str] = None) -> List[str]:
    """Validate SKILL.md frontmatter against the Agent Skills open standard."""
    issues: List[str] = []
    if "_invalid_frontmatter" in frontmatter:
        issues.append(str(frontmatter["_invalid_frontmatter"]))
        return issues
    name = frontmatter.get("name")
    description = frontmatter.get("description")
    if not name or not isinstance(name, str):
        issues.append("Missing or non-string required field 'name'")
    else:
        if len(name) > 64:
            issues.append(f"Skill name '{name}' exceeds 64 characters")
        if not SKILL_NAME_SPEC_RE.match(name):
            issues.append(
                f"Skill name '{name}' does not strictly match Agent Skills regex ^[a-z0-9]+(-[a-z0-9]+)*$"
            )
        if expected_dir_name and name != expected_dir_name:
            issues.append(f"Skill name '{name}' does not match directory name '{expected_dir_name}'")
    if not description or not isinstance(description, str):
        issues.append("Missing or non-string required field 'description'")
    elif len(description) > 1024:
        issues.append(f"Skill description length ({len(description)}) exceeds 1024 characters")
    return issues


def validate_bundle_rel_path(rel_path: str, *, allow_nested: bool = True, max_depth: int = 6) -> str:
    """Validate and normalize a relative path within an extension bundle.

    Rejects empty paths, absolute paths, Windows drives/NTFS streams (:), '..' traversal, and excessive depth.
    """
    if not isinstance(rel_path, str):
        raise ValueError("Path must be a string")
    raw = rel_path.strip()
    if not raw:
        raise ValueError("Empty path is not allowed")
    win = PureWindowsPath(raw)
    if win.is_absolute() or win.drive:
        raise ValueError(f"Absolute or drive path is not allowed: {rel_path}")
    normalized = raw.replace("\\", "/")
    posix = PurePosixPath(normalized)
    parts = [p for p in posix.parts if p not in ("", ".")]
    if (
        normalized.startswith("/")
        or posix.is_absolute()
        or not parts
        or any(p == ".." for p in parts)
        or any(":" in p for p in parts)
        or any("\x00" in p for p in parts)
    ):
        raise ValueError(f"Unsafe bundle path rejected: {rel_path}")
    if not allow_nested and len(parts) != 1:
        raise ValueError(f"Nested path not allowed for skill identifier: {rel_path}")
    if len(parts) > max_depth:
        raise ValueError(f"Path depth ({len(parts)}) exceeds maximum depth ({max_depth}): {rel_path}")
    return "/".join(parts)


def validate_skill_name(name: str) -> str:
    """Validate a single-segment skill directory/identifier name."""
    cleaned = validate_bundle_rel_path(name, allow_nested=False)
    if not SKILL_ID_SAFE_RE.match(cleaned):
        raise ValueError(f"Invalid skill name characters: {name}")
    return cleaned


def extract_referenced_support_paths(skill_md_content: str) -> Optional[Set[str]]:
    """Extract referenced relative support files from SKILL.md; returns None if traversal attempt detected."""
    normalized = skill_md_content.replace("\\", "/")
    if SUSPICIOUS_LOCAL_REF_RE.search(normalized):
        return None
    paths: Set[str] = set()
    for match in LOCAL_LINK_RE.finditer(normalized):
        candidate = match.group(1).rstrip(".,;:")
        parsed = urlsplit(candidate)
        raw = unquote(parsed.path)
        if candidate.endswith("?") or any(c in raw for c in "*?[]<>"):
            continue
        try:
            safe = validate_bundle_rel_path(raw)
        except ValueError:
            return None
        if safe.split("/", 1)[0] in ALLOWED_SUPPORT_DIRS:
            base = safe.rsplit("/", 1)[-1]
            if re.search(r"[A-Za-z0-9]$", base):
                paths.add(safe)
    for match in SAMEDIR_LINK_RE.finditer(normalized):
        raw = match.group(1).rstrip(".,;:")
        name = unquote(urlsplit(raw).path).removeprefix("./")
        if not name or "://" in raw or raw.startswith(("mailto:", "#", "/")):
            continue
        if name.startswith(".."):
            continue
        if "/" in name or name.casefold() == "skill.md" or "." not in name.lstrip(".") or not SAMEDIR_NAME_RE.match(name):
            continue
        try:
            safe = validate_bundle_rel_path(name)
        except ValueError:
            return None
        paths.add(safe)
    return paths


def compute_directory_content_hash(directory: Path) -> str:
    """Compute canonical SHA-256 content hash over (POSIX relative path, file bytes) in sorted string order."""
    if not directory.exists():
        return ""
    if directory.is_file():
        return f"sha256:{hashlib.sha256(directory.read_bytes()).hexdigest()[:16]}"
    h = hashlib.sha256()
    items = []
    for p in directory.rglob("*"):
        if p.is_symlink():
            continue
        if p.is_file():
            rel = p.relative_to(directory).as_posix()
            if rel.startswith(".git/") or "__pycache__" in rel.split("/"):
                continue
            items.append((rel, p))
    for rel, p in sorted(items, key=lambda x: x[0]):
        h.update(rel.encode("utf-8") + b"\x00")
        try:
            h.update(p.read_bytes())
        except OSError:
            continue
    return f"sha256:{h.hexdigest()[:16]}"


def compute_bundle_content_hash(files: Dict[str, str | bytes]) -> str:
    """Compute canonical SHA-256 content hash for an in-memory file bundle (symmetric with disk hash)."""
    h = hashlib.sha256()
    normalized = {k.replace("\\", "/"): v for k, v in files.items()}
    for rel in sorted(normalized.keys()):
        h.update(rel.encode("utf-8") + b"\x00")
        val = normalized[rel]
        h.update(val if isinstance(val, bytes) else val.encode("utf-8"))
    return f"sha256:{h.hexdigest()[:16]}"


def normalize_repo_alias(repo_or_alias: str) -> str:
    """Expand known repository aliases and normalize GitHub URLs into owner/repo format."""
    cleaned = repo_or_alias.strip().rstrip("/")
    lower = cleaned.lower()
    if lower in REPO_ALIASES:
        return REPO_ALIASES[lower]
    if cleaned.startswith(("http://", "https://")):
        parsed = urlparse(cleaned)
        if parsed.netloc.lower() in ("github.com", "www.github.com"):
            parts = [p for p in parsed.path.split("/") if p]
            if len(parts) >= 2:
                repo_name = parts[1].removesuffix(".git")
                subpath = "/".join(parts[4:]) if len(parts) > 4 and parts[2] in ("tree", "blob") else "/".join(parts[2:])
                return f"{parts[0]}/{repo_name}/{subpath}".rstrip("/")
    return cleaned


def normalize_url(url: str) -> str:
    """Normalize HTTP(S) URLs consistently."""
    raw = url.strip()
    parsed = urlparse(raw)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))


def is_safe_http_url(url: str, *, allow_localhost: bool = False) -> Tuple[bool, str]:
    """Validate that a URL is HTTP/HTTPS and does not target loopback, link-local, or private IP ranges (SSRF guard)."""
    try:
        parsed = urlparse(url.strip())
    except ValueError as exc:
        return False, f"Malformed URL: {exc}"
    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"Disallowed URL scheme '{parsed.scheme}'; only http/https allowed"
    hostname = parsed.hostname
    if not hostname:
        return False, "Missing hostname in URL"
    host_lower = hostname.lower()
    if not allow_localhost and host_lower in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "169.254.169.254", "metadata.google.internal"):
        return False, f"Blocked loopback or cloud metadata host: {hostname}"
    try:
        ip = ipaddress.ip_address(host_lower)
        if not allow_localhost and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved):
            return False, f"Blocked non-public IP address: {ip}"
    except ValueError:
        if not allow_localhost and host_lower.endswith((".local", ".internal", ".localhost")):
            return False, f"Blocked internal domain suffix: {hostname}"
    return True, "ok"
