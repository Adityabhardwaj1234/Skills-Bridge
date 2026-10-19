"""Native client adapters for OpenCode and Claude Code."""

from skillbridge.adapters.clients import (
    ClaudeCodeAdapter,
    ClientAdapter,
    OpenCodeAdapter,
    atomic_write_text,
    compute_unified_diff,
    dump_jsonc,
    parse_jsonc,
)

__all__ = [
    "ClaudeCodeAdapter",
    "ClientAdapter",
    "OpenCodeAdapter",
    "atomic_write_text",
    "compute_unified_diff",
    "dump_jsonc",
    "parse_jsonc",
]
