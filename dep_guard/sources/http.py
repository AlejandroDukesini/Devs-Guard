"""Hardened HTTP access for vulnerability sources.

- HTTPS only, and only to hosts in ALLOWED_HOSTS (URLs are constants, this is
  defence in depth against future misuse, not user input validation);
- redirects are not followed;
- response bodies are size-capped while streaming;
- 429/5xx/network errors are retried with exponential backoff and jitter,
  honouring Retry-After (capped);
- every failure surfaces as SourceError: callers must decide what "unknown"
  means, they never receive an empty-but-successful answer.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlsplit

import httpx

from dep_guard import __version__

log = logging.getLogger("depguard.http")

ALLOWED_HOSTS = frozenset({"api.osv.dev", "api.first.org", "www.cisa.gov"})
RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
USER_AGENT = f"depguard/{__version__} (+https://github.com/AlejandroDukesini/Devs-Guard)"
MAX_RETRY_AFTER = 30.0


class SourceError(Exception):
    """A vulnerability source could not provide an answer."""


Sleep = Callable[[float], Awaitable[None]]


def new_client(timeout: float) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        limits=httpx.Limits(max_connections=16, max_keepalive_connections=8),
    )


class HttpClient:
    def __init__(
        self,
        client: httpx.AsyncClient,
        retries: int = 3,
        max_bytes: int = 32 * 1024 * 1024,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        self._client = client
        self._retries = retries
        self._max_bytes = max_bytes
        self._sleep = sleep
        self.request_count = 0
        self._retry_after: float | None = None

    async def get_json(self, url: str, params: dict[str, str] | None = None) -> Any:
        return await self._request("GET", url, params=params)

    async def post_json(self, url: str, body: Any) -> Any:
        return await self._request("POST", url, body=body)

    async def _request(
        self, method: str, url: str, body: Any = None, params: dict[str, str] | None = None
    ) -> Any:
        parts = urlsplit(url)
        if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS:
            raise SourceError(f"refusing to contact non-allowlisted URL host {parts.hostname!r}")

        last_error = "unknown error"
        for attempt in range(self._retries + 1):
            if attempt:
                await self._sleep(self._backoff(attempt))
            self.request_count += 1
            try:
                async with self._client.stream(method, url, json=body, params=params) as resp:
                    if resp.status_code in RETRY_STATUS:
                        last_error = f"HTTP {resp.status_code}"
                        self._retry_after = _retry_after(resp.headers.get("Retry-After"))
                        log.debug(
                            "%s %s -> %s (attempt %d)", method, parts.path, last_error, attempt + 1
                        )
                        continue
                    if resp.status_code != 200:
                        raise SourceError(f"{parts.hostname} answered HTTP {resp.status_code}")
                    raw = await self._read_capped(resp)
            except httpx.TimeoutException:
                last_error = "timeout"
                self._retry_after = None
                continue
            except httpx.TransportError as exc:
                last_error = f"network error ({type(exc).__name__})"
                self._retry_after = None
                continue
            try:
                return json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise SourceError(f"{parts.hostname} returned invalid JSON") from None
        raise SourceError(
            f"{parts.hostname} unavailable after {self._retries + 1} attempts: {last_error}"
        )

    def _backoff(self, attempt: int) -> float:
        if self._retry_after is not None:
            return min(self._retry_after, MAX_RETRY_AFTER)
        base: float = 0.5 * (2 ** (attempt - 1))
        return base + random.uniform(0, base / 2)  # jitter, not crypto  # noqa: S311  # nosec B311

    async def _read_capped(self, resp: httpx.Response) -> bytes:
        chunks: list[bytes] = []
        total = 0
        async for chunk in resp.aiter_bytes():
            total += len(chunk)
            if total > self._max_bytes:
                raise SourceError("response exceeded size limit")
            chunks.append(chunk)
        return b"".join(chunks)


def _retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None
