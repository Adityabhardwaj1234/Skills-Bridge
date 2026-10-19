"""Base provider interface and SSRF-guarded, size-bounded HTTP client for SkillBridge."""

from __future__ import annotations

import json
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import httpx

from skillbridge.config import NetworkConfig
from skillbridge.discovery.normalizer import is_safe_http_url
from skillbridge.models import ExtensionBundle, ExtensionRecord

logger = logging.getLogger("skillbridge.providers")

REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}


class GuardedHttpClient:
    """HTTP client enforcing explicit timeouts, redirect hop SSRF checks, response size caps, and retry backoff."""

    def __init__(self, config: Optional[NetworkConfig] = None, transport: Optional[httpx.BaseTransport] = None):
        self.config = config or NetworkConfig()
        self._transport = transport

    def _make_client(self) -> httpx.Client:
        timeout = httpx.Timeout(
            connect=self.config.connect_timeout_sec,
            read=self.config.read_timeout_sec,
            write=self.config.connect_timeout_sec,
            pool=self.config.connect_timeout_sec,
        )
        return httpx.Client(timeout=timeout, follow_redirects=False, transport=self._transport)

    def get_bytes(
        self,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        max_bytes: Optional[int] = None,
        allow_localhost: bool = False,
    ) -> Optional[bytes]:
        """Fetch raw bytes from a URL with SSRF redirect validation, retry backoff, and bounded size."""
        if self.config.offline_mode:
            return None

        cap = max_bytes or self.config.max_response_bytes
        current_url = url
        current_params = params

        for attempt in range(self.config.max_retries + 1):
            try:
                with self._make_client() as client:
                    for _hop in range(self.config.max_redirects + 1):
                        safe, reason = is_safe_http_url(current_url, allow_localhost=allow_localhost)
                        if not safe:
                            logger.warning("Blocked unsafe URL %s: %s", current_url, reason)
                            return None
                        with client.stream("GET", current_url, params=current_params, headers=headers) as resp:
                            if resp.status_code in REDIRECT_STATUS_CODES:
                                loc = resp.headers.get("location")
                                if not loc:
                                    return None
                                current_url = urljoin(current_url, loc)
                                current_params = None
                                continue
                            if resp.status_code in (429, 502, 503, 504) and attempt < self.config.max_retries:
                                time.sleep(0.3 * (2 ** attempt))
                                break
                            if resp.status_code != 200:
                                return None
                            chunks: List[bytes] = []
                            total = 0
                            for chunk in resp.iter_bytes(chunk_size=65536):
                                total += len(chunk)
                                if total > cap:
                                    raise ValueError(f"Response from {current_url} exceeded max size ({cap} bytes)")
                                chunks.append(chunk)
                            return b"".join(chunks)
                    else:
                        logger.warning("Exceeded max redirects (%d) for %s", self.config.max_redirects, url)
                        return None
            except ValueError:
                raise
            except (httpx.HTTPError, OSError) as exc:
                logger.debug("HTTP request failed for %s (attempt %d): %s", current_url, attempt + 1, exc)
                if attempt >= self.config.max_retries:
                    return None
                time.sleep(0.2 * (2 ** attempt))
        return None

    def get_text(
        self,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        max_bytes: Optional[int] = None,
        allow_localhost: bool = False,
    ) -> Optional[str]:
        raw = self.get_bytes(url, params=params, headers=headers, max_bytes=max_bytes, allow_localhost=allow_localhost)
        if raw is None:
            return None
        try:
            return raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            return raw.decode("utf-8", errors="replace")

    def get_json(
        self,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        max_bytes: Optional[int] = None,
        allow_localhost: bool = False,
    ) -> Optional[Any]:
        text = self.get_text(url, params=params, headers=headers, max_bytes=max_bytes, allow_localhost=allow_localhost)
        if text is None:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None


class ExtensionProvider(ABC):
    """Documented abstract interface for all extension discovery and retrieval providers."""

    PROVIDER_ID: str = "base"
    EXTENSION_TYPE: str = "skill"

    @abstractmethod
    def search(self, query: str, limit: int = 20) -> List[ExtensionRecord]:
        """Search for extensions matching query."""

    @abstractmethod
    def inspect(self, extension_id: str) -> Optional[ExtensionRecord]:
        """Retrieve normalized metadata for a single extension without executing code."""

    @abstractmethod
    def fetch_bundle(self, extension_id: str) -> Optional[ExtensionBundle]:
        """Fetch the extension files (SKILL.md, references, scripts, manifests) for preview/scanning/loading."""
