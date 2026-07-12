"""Shared low-level sender used by Repeater and Fuzzer.

Enforces scope before any request leaves the tool.
"""
from __future__ import annotations

import time
from urllib.parse import urlparse

import httpx

from ..state import STATE

# Headers httpx must compute itself; sending user-supplied copies breaks requests.
_STRIP = {"content-length", "transfer-encoding", "connection"}


class ScopeError(Exception):
    pass


def _check_scope(url: str) -> str:
    host = urlparse(url).hostname or ""
    if not STATE.scope.is_allowed(host):
        raise ScopeError(
            f"Host '{host}' is out of scope. Add it to the scope allow-list "
            f"or disable scope enforcement to send this request."
        )
    return host


def _clean_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in (headers or {}).items() if k.lower() not in _STRIP}


async def send(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    headers: dict[str, str],
    body: str,
) -> dict:
    _check_scope(url)
    t0 = time.perf_counter()
    resp = await client.request(
        method.upper(),
        url,
        headers=_clean_headers(headers),
        content=(body or "").encode("utf-8", "replace"),
    )
    dt = (time.perf_counter() - t0) * 1000.0
    return {
        "status": resp.status_code,
        "reason": resp.reason_phrase,
        "headers": dict(resp.headers),
        "body": resp.text,
        "length": len(resp.content),
        "duration_ms": round(dt, 1),
    }


async def send_once(method: str, url: str, headers: dict, body: str, timeout: float = 30.0) -> dict:
    async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=timeout) as client:
        return await send(client, method, url, headers, body)
