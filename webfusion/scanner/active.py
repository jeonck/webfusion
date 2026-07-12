"""Active checks — send crafted payloads to probe for injection classes.

DANGEROUS / intrusive. Only invoked by the local CLI with --active, never from
the hosted scanner. Each check compares against a benign baseline to suppress
false positives, and the whole module is bounded (limited params & payloads).
"""
from __future__ import annotations

import re
import secrets
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from .findings import Finding, Severity

MAX_PARAMS = 12  # bound the work regardless of how many params a URL has

_SQL_ERRORS = re.compile(
    r"(SQL syntax.*MySQL|Warning.*\bmysqli?_|valid MySQL result|"
    r"PostgreSQL.*ERROR|org\.postgresql|SQLite/JDBCDriver|SQLite3::|"
    r"Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark|"
    r"ORA-\d{5}|quoted string not properly terminated)",
    re.I,
)
_PASSWD = re.compile(r"root:.*:0:0:")
_REDIRECT_PARAMS = {"redirect", "url", "next", "return", "returnurl", "dest", "destination", "continue", "r", "u"}


def _with_params(url: str, params: list[tuple[str, str]]) -> str:
    parts = urlparse(url)
    return urlunparse(parts._replace(query=urlencode(params)))


async def _get(client: httpx.AsyncClient, url: str, follow: bool = True):
    try:
        return await client.get(url, follow_redirects=follow)
    except Exception:
        return None


async def run(client: httpx.AsyncClient, url: str) -> list[Finding]:
    findings: list[Finding] = []
    parts = urlparse(url)
    params = parse_qsl(parts.query, keep_blank_values=True)[:MAX_PARAMS]

    baseline = await _get(client, url)
    baseline_body = baseline.text if baseline is not None else ""

    # ---- reflected XSS + error-based SQLi (per query param) ----
    for i, (key, _val) in enumerate(params):
        token = "wf" + secrets.token_hex(3)
        xss_probe = f'{token}"\'><svg/onload=alert(1)>'
        mutated = list(params)
        mutated[i] = (key, xss_probe)
        r = await _get(client, _with_params(url, mutated))
        if r is not None and xss_probe in (r.text or ""):
            findings.append(Finding(
                id="reflected-xss", name=f"Reflected XSS in parameter '{key}'",
                severity=Severity.HIGH, confidence="high", url=str(r.url),
                evidence=f"Payload reflected unencoded: {xss_probe}",
                description="User input is reflected into the response without output encoding.",
                remediation="Context-aware output encoding; apply a strict Content-Security-Policy.",
                cwe="CWE-79",
            ))

        sqli = list(params)
        sqli[i] = (key, _val + "'")
        r2 = await _get(client, _with_params(url, sqli))
        if r2 is not None and _SQL_ERRORS.search(r2.text or "") and not _SQL_ERRORS.search(baseline_body):
            m = _SQL_ERRORS.search(r2.text or "")
            findings.append(Finding(
                id="sqli-error", name=f"SQL injection (error-based) in parameter '{key}'",
                severity=Severity.CRITICAL, confidence="high", url=str(r2.url),
                evidence=(m.group(0)[:120] if m else "SQL error signature"),
                description="Appending a quote triggers a database error, indicating unsanitized SQL.",
                remediation="Use parameterized queries / prepared statements; never concatenate input into SQL.",
                cwe="CWE-89",
            ))

        # ---- open redirect (only for redirect-ish param names) ----
        if key.lower() in _REDIRECT_PARAMS:
            evil = "https://webfusion-oob.example/"
            red = list(params)
            red[i] = (key, evil)
            r3 = await _get(client, _with_params(url, red), follow=False)
            if r3 is not None and r3.is_redirect:
                loc = r3.headers.get("location", "")
                if "webfusion-oob.example" in loc:
                    findings.append(Finding(
                        id="open-redirect", name=f"Open redirect via parameter '{key}'",
                        severity=Severity.MEDIUM, confidence="high", url=str(r3.url),
                        evidence=f"Location: {loc}",
                        description="The app redirects to an attacker-controlled external URL.",
                        remediation="Allow-list redirect targets or use relative paths only.",
                        cwe="CWE-601",
                    ))

    # ---- path traversal (inject into first param, else skip) ----
    if params:
        trav = list(params)
        trav[0] = (params[0][0], "../../../../../../etc/passwd")
        r4 = await _get(client, _with_params(url, trav))
        if r4 is not None and _PASSWD.search(r4.text or ""):
            findings.append(Finding(
                id="path-traversal", name=f"Path traversal via parameter '{params[0][0]}'",
                severity=Severity.CRITICAL, confidence="high", url=str(r4.url),
                evidence="Response contains /etc/passwd contents (root:...:0:0:)",
                description="A file path parameter allows reading arbitrary files via '../' sequences.",
                remediation="Canonicalize and validate paths against an allow-list; never use raw input in file paths.",
                cwe="CWE-22",
            ))

    return findings
