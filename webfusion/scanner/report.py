"""Report formatters: console, JSON, SARIF 2.1.0, and a self-contained HTML."""
from __future__ import annotations

import html
import json
from typing import TYPE_CHECKING

from .findings import Severity, sarif_level

if TYPE_CHECKING:
    from .engine import ScanResult

_COLORS = {
    "critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m",
    "low": "\033[96m", "info": "\033[90m",
}
_RESET = "\033[0m"


def to_json(result: "ScanResult") -> str:
    return json.dumps({
        "target": result.target,
        "active": result.active,
        "duration_ms": result.duration_ms,
        "error": result.error,
        "counts": result.counts(),
        "findings": [f.to_dict() for f in result.findings],
    }, indent=2)


def to_console(result: "ScanResult", color: bool = True) -> str:
    lines = [f"\nWebFusion scan — {result.target}"]
    if result.error:
        lines.append(f"  ERROR: {result.error}")
        return "\n".join(lines)
    c = result.counts()
    lines.append(
        f"  {len(result.findings)} finding(s): "
        f"{c['critical']} critical, {c['high']} high, {c['medium']} medium, "
        f"{c['low']} low, {c['info']} info  ({result.duration_ms:.0f} ms)\n"
    )
    for f in result.findings:
        tag = f.severity.value.upper()
        if color:
            tag = _COLORS.get(f.severity.value, "") + tag + _RESET
        lines.append(f"  [{tag}] {f.name}  ({f.confidence} confidence, {f.cwe})")
        lines.append(f"        {f.url}")
        if f.evidence:
            lines.append(f"        evidence: {f.evidence}")
        lines.append(f"        fix: {f.remediation}")
    return "\n".join(lines)


def to_sarif(result: "ScanResult") -> str:
    rules: dict[str, dict] = {}
    results = []
    for f in result.findings:
        if f.id not in rules:
            rules[f.id] = {
                "id": f.id,
                "name": f.name,
                "shortDescription": {"text": f.name},
                "fullDescription": {"text": f.description or f.name},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{f.cwe.split('-')[-1]}.html" if f.cwe else "",
                "properties": {"security-severity": _cvss(f.severity), "cwe": f.cwe},
            }
        results.append({
            "ruleId": f.id,
            "level": sarif_level(f.severity),
            "message": {"text": f"{f.name}. {f.evidence} Fix: {f.remediation}"},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": f.url}}
            }],
            "properties": {"confidence": f.confidence, "severity": f.severity.value},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "WebFusion",
                "informationUri": "https://github.com/jeonck/webfusion",
                "version": "0.1.0",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)


def _cvss(sev: Severity) -> str:
    # GitHub uses security-severity (0-10) to bucket SARIF results.
    return {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}[sev.value]


def to_html(result: "ScanResult") -> str:
    rows = []
    for f in result.findings:
        rows.append(
            f"<tr class='sev-{f.severity.value}'><td>{f.severity.value.upper()}</td>"
            f"<td>{html.escape(f.name)}</td><td>{f.confidence}</td>"
            f"<td>{html.escape(f.cwe)}</td><td>{html.escape(f.remediation)}</td></tr>"
        )
    c = result.counts()
    return f"""<!doctype html><meta charset=utf-8><title>WebFusion report</title>
<style>body{{font-family:system-ui;margin:2rem;background:#0e1116;color:#d7dde5}}
table{{border-collapse:collapse;width:100%}}td,th{{padding:6px 10px;border-bottom:1px solid #2b333d;text-align:left}}
.sev-critical td:first-child{{color:#c678dd}}.sev-high td:first-child{{color:#e5534b}}
.sev-medium td:first-child{{color:#d29922}}.sev-low td:first-child{{color:#4c9aff}}.sev-info td:first-child{{color:#8b96a3}}</style>
<h1>WebFusion scan report</h1><p>{html.escape(result.target)} — {len(result.findings)} findings
({c['critical']}C {c['high']}H {c['medium']}M {c['low']}L {c['info']}I)</p>
<table><tr><th>Severity</th><th>Finding</th><th>Confidence</th><th>CWE</th><th>Remediation</th></tr>
{''.join(rows)}</table>"""
