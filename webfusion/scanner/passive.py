"""Passive checks — analyze a single response, send no extra requests.

Safe to run against any authorized target and in the hosted (passive-only) mode.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx

from .findings import Finding, Severity

# (header, name, severity, cwe, remediation)
_SECURITY_HEADERS = [
    ("content-security-policy", "Missing Content-Security-Policy", Severity.MEDIUM,
     "CWE-693", "Add a Content-Security-Policy that restricts script/style/object sources."),
    ("strict-transport-security", "Missing HSTS (Strict-Transport-Security)", Severity.MEDIUM,
     "CWE-319", "Send Strict-Transport-Security with a long max-age on all HTTPS responses."),
    ("x-content-type-options", "Missing X-Content-Type-Options", Severity.LOW,
     "CWE-693", "Set 'X-Content-Type-Options: nosniff' to stop MIME sniffing."),
    ("x-frame-options", "Missing X-Frame-Options / frame-ancestors", Severity.LOW,
     "CWE-1021", "Set X-Frame-Options: DENY or a CSP frame-ancestors directive to prevent clickjacking."),
    ("referrer-policy", "Missing Referrer-Policy", Severity.LOW,
     "CWE-200", "Set a Referrer-Policy such as 'strict-origin-when-cross-origin'."),
]

_SERVER_ERROR_SIGNATURES = [
    r"Traceback \(most recent call last\)",
    r"java\.lang\.[A-Za-z.]+Exception",
    r"<b>Warning</b>:.*on line",
    r"System\.[A-Za-z.]+Exception",
    r"ORA-\d{5}",
]

_VERSION_DISCLOSURE = re.compile(r"(Apache|nginx|PHP|OpenSSL|IIS)/\d", re.I)


def _is_https(url: str) -> bool:
    return urlparse(url).scheme == "https"


def run(resp: httpx.Response) -> list[Finding]:
    findings: list[Finding] = []
    url = str(resp.url)
    headers = {k.lower(): v for k, v in resp.headers.items()}
    https = _is_https(url)
    body = resp.text or ""

    # --- security headers (only meaningful on HTML/document responses) ---
    ctype = headers.get("content-type", "")
    if "html" in ctype or not ctype:
        for hdr, name, sev, cwe, fix in _SECURITY_HEADERS:
            if hdr == "strict-transport-security" and not https:
                continue  # HSTS only applies to HTTPS
            if hdr == "x-frame-options":
                csp = headers.get("content-security-policy", "")
                if "frame-ancestors" in csp:
                    continue
            if hdr not in headers:
                findings.append(Finding(
                    id=hdr, name=name, severity=sev, confidence="high", url=url,
                    evidence=f"Response header '{hdr}' not present.",
                    description=f"The response is missing the {hdr} header.",
                    remediation=fix, cwe=cwe,
                ))

    # --- cookie flags ---
    for raw in resp.headers.get_list("set-cookie"):
        cname = raw.split("=", 1)[0].strip()
        low = raw.lower()
        missing = []
        if "httponly" not in low:
            missing.append("HttpOnly")
        if https and "secure" not in low:
            missing.append("Secure")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            findings.append(Finding(
                id="cookie-flags", name=f"Cookie '{cname}' missing {', '.join(missing)}",
                severity=Severity.LOW, confidence="high", url=url,
                evidence=raw[:120],
                description=f"Set-Cookie for '{cname}' lacks: {', '.join(missing)}.",
                remediation="Set HttpOnly, Secure (on HTTPS) and SameSite on session cookies.",
                cwe="CWE-1004",
            ))

    # --- CORS misconfiguration ---
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        findings.append(Finding(
            id="cors-wildcard-credentials", name="CORS allows any origin with credentials",
            severity=Severity.HIGH, confidence="high", url=url,
            evidence="Access-Control-Allow-Origin: * with Allow-Credentials: true",
            description="A wildcard ACAO combined with credentials lets any site read authenticated responses.",
            remediation="Reflect only an explicit allow-list of trusted origins when credentials are used.",
            cwe="CWE-942",
        ))

    # --- info disclosure: server banners with versions ---
    for h in ("server", "x-powered-by"):
        v = headers.get(h, "")
        if v and _VERSION_DISCLOSURE.search(v):
            findings.append(Finding(
                id="version-disclosure", name=f"Version disclosure in '{h}' header",
                severity=Severity.INFO, confidence="high", url=url, evidence=f"{h}: {v}",
                description="Server/framework version is exposed, aiding targeted attacks.",
                remediation="Suppress or genericize Server/X-Powered-By headers.",
                cwe="CWE-200",
            ))

    # --- info disclosure: stack traces / error signatures in body ---
    for sig in _SERVER_ERROR_SIGNATURES:
        m = re.search(sig, body)
        if m:
            findings.append(Finding(
                id="error-disclosure", name="Server error / stack trace disclosed",
                severity=Severity.MEDIUM, confidence="medium", url=url,
                evidence=m.group(0)[:120],
                description="The response body leaks a stack trace or server error detail.",
                remediation="Return generic error pages; log details server-side only.",
                cwe="CWE-209",
            ))
            break

    return findings
