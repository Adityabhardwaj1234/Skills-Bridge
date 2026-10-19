"""Extension discovery engine and normalization utilities."""

from skillbridge.discovery.engine import DiscoveryEngine, deduplicate_records
from skillbridge.discovery.normalizer import (
    compute_bundle_content_hash,
    compute_directory_content_hash,
    extract_referenced_support_paths,
    is_safe_http_url,
    normalize_repo_alias,
    normalize_url,
    parse_skill_md,
    validate_bundle_rel_path,
    validate_skill_frontmatter,
    validate_skill_name,
)

__all__ = [
    "DiscoveryEngine",
    "compute_bundle_content_hash",
    "compute_directory_content_hash",
    "deduplicate_records",
    "extract_referenced_support_paths",
    "is_safe_http_url",
    "normalize_repo_alias",
    "normalize_url",
    "parse_skill_md",
    "validate_bundle_rel_path",
    "validate_skill_frontmatter",
    "validate_skill_name",
]
