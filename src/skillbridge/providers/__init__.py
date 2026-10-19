"""Extension discovery providers for local directories, Hermes Hub, GitHub, well-known endpoints, MCP Registry, and Smithery."""

from skillbridge.providers.base import ExtensionProvider, GuardedHttpClient
from skillbridge.providers.hermes_hub import HermesHubProvider
from skillbridge.providers.local import LocalSkillsProvider
from skillbridge.providers.remote import (
    GitHubSkillsProvider,
    MCPRegistryProvider,
    WellKnownSkillsProvider,
)
from skillbridge.providers.smithery import SmitheryMCPProvider

__all__ = [
    "ExtensionProvider",
    "GitHubSkillsProvider",
    "GuardedHttpClient",
    "HermesHubProvider",
    "LocalSkillsProvider",
    "MCPRegistryProvider",
    "SmitheryMCPProvider",
    "WellKnownSkillsProvider",
]
