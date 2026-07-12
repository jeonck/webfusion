"""Scan orchestration: fetch target, run passive (+ optional active) checks.

Includes an SSRF guard used by the hosted/passive mode to refuse internal hosts.
"""
from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from . import active as active_checks
from . import passive as passive_checks
from .findings import Finding, Severity, rank

USER_AGENT = "WebFusion-Scanner/0.1 (+authorized-testing-only)"


class SsrfBlocked(Exception):
    pass


class ScanError(Exception):
    pass


def _assert_public(host: str) -> None:
    """Raise SsrfBlocked if host resolves to a private/local/link-local address."""
    if not host:
        raise SsrfBlocked("empty host")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ScanError(f"cannot resolve host '{host}': {exc}")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise SsrfBlocked(f"host '{host}' resolves to non-public address {ip}")


@dataclass
class ScanResult:
    target: str
    started_at: float
    duration_ms: float
    findings: list[Finding] = field(default_factory=list)
    active: bool = False
    error: str = ""

    def counts(self) -> dict[str, int]:
        c = {s.value: 0 for s in Severity}
        for f in self.findings:
            c[f.severity.value] += 1
        return c

    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), key=rank, default=None)


async def scan(
    url: str,
    active: bool = False,
    allow_private: bool = True,
    timeout: float = 15.0,
) -> ScanResult:
    if not urlparse(url).scheme:
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ScanError("only http/https targets are supported")
    if not allow_private:
        _assert_public(parsed.hostname or "")

    t0 = time.time()
    findings: list[Finding] = []
    headers = {"User-Agent": USER_AGENT}
    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, timeout=timeout, headers=headers
    ) as client:
        try:
            resp = await client.get(url)
        except Exception as exc:
            return ScanResult(url, t0, (time.time() - t0) * 1000, error=str(exc))

        findings += passive_checks.run(resp)
        if active:
            findings += await active_checks.run(client, url)

    findings.sort(key=lambda f: rank(f.severity), reverse=True)
    return ScanResult(
        target=url, started_at=t0, duration_ms=round((time.time() - t0) * 1000, 1),
        findings=findings, active=active,
    )
