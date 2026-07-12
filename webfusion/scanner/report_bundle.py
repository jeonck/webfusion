"""Aggregate multiple per-URL scans into one report (JSON / SARIF / HTML).

Used to scan a whole site (many endpoints) and emit a single deliverable.
"""
from __future__ import annotations

import datetime as _dt
import html
import json
from typing import TYPE_CHECKING

from .findings import Severity, rank, sarif_level

if TYPE_CHECKING:
    from .engine import ScanResult

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_SEV_COLOR = {
    "critical": "#c678dd", "high": "#e5534b", "medium": "#d29922",
    "low": "#4c9aff", "info": "#8b96a3",
}


def _all_findings(results: list["ScanResult"]) -> list:
    out = []
    for r in results:
        out.extend(r.findings)
    return out


def _counts(findings: list) -> dict[str, int]:
    c = {s.value: 0 for s in Severity}
    for f in findings:
        c[f.severity.value] += 1
    return c


def _risk(counts: dict[str, int]) -> tuple[str, str]:
    if counts["critical"]:
        return "Critical", _SEV_COLOR["critical"]
    if counts["high"]:
        return "High", _SEV_COLOR["high"]
    if counts["medium"]:
        return "Medium", _SEV_COLOR["medium"]
    if counts["low"]:
        return "Low", _SEV_COLOR["low"]
    return "Informational", _SEV_COLOR["info"]


def aggregate(results: list["ScanResult"]) -> dict:
    findings = _all_findings(results)
    counts = _counts(findings)
    risk, _ = _risk(counts)
    return {
        "endpoints_scanned": len(results),
        "total_findings": len(findings),
        "counts": counts,
        "risk_rating": risk,
    }


def to_json(results: list["ScanResult"], title: str, target: str) -> str:
    return json.dumps({
        "report": title,
        "target": target,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "scanner": "WebFusion 0.1.0",
        "summary": aggregate(results),
        "scans": [{
            "url": r.target,
            "active": r.active,
            "duration_ms": r.duration_ms,
            "findings": [f.to_dict() for f in r.findings],
        } for r in results],
    }, indent=2)


def to_sarif(results: list["ScanResult"]) -> str:
    rules: dict[str, dict] = {}
    sarif_results = []
    for f in _all_findings(results):
        if f.id not in rules:
            rules[f.id] = {
                "id": f.id, "name": f.name,
                "shortDescription": {"text": f.name},
                "fullDescription": {"text": f.description or f.name},
                "properties": {"cwe": f.cwe},
            }
        sarif_results.append({
            "ruleId": f.id, "level": sarif_level(f.severity),
            "message": {"text": f"{f.name}. {f.evidence} Fix: {f.remediation}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.url}}}],
            "properties": {"severity": f.severity.value, "confidence": f.confidence},
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "WebFusion", "version": "0.1.0",
                                "rules": list(rules.values())}},
            "results": sarif_results,
        }],
    }, indent=2)


def to_html(results: list["ScanResult"], title: str, target: str) -> str:
    findings = _all_findings(results)
    findings.sort(key=lambda f: rank(f.severity), reverse=True)
    counts = _counts(findings)
    risk, risk_color = _risk(counts)
    now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    total = len(findings) or 1

    # severity bar segments
    bar = "".join(
        f"<span style='width:{counts[s.value]/total*100:.1f}%;background:{_SEV_COLOR[s.value]}'></span>"
        for s in _SEV_ORDER if counts[s.value]
    )
    pills = "".join(
        f"<div class='pill'><span class='dot' style='background:{_SEV_COLOR[s.value]}'></span>"
        f"{s.value.title()} <b>{counts[s.value]}</b></div>"
        for s in _SEV_ORDER
    )

    cards = []
    for f in findings:
        col = _SEV_COLOR[f.severity.value]
        cards.append(f"""<div class="card" style="border-left-color:{col}">
  <div class="card-head">
    <span class="sev" style="background:{col}">{f.severity.value.upper()}</span>
    <h3>{html.escape(f.name)}</h3>
  </div>
  <div class="meta">{html.escape(f.confidence)} confidence · {html.escape(f.cwe or '')} ·
    <a href="{html.escape(f.url)}">{html.escape(f.url)}</a></div>
  {f'<div class="ev">{html.escape(f.evidence)}</div>' if f.evidence else ''}
  <div class="desc">{html.escape(f.description)}</div>
  <div class="fix"><b>Remediation:</b> {html.escape(f.remediation)}</div>
</div>""")

    endpoints = "".join(
        f"<tr><td>{html.escape(r.target)}</td><td>{'active' if r.active else 'passive'}</td>"
        f"<td>{len(r.findings)}</td><td>{r.duration_ms:.0f} ms</td></tr>"
        for r in results
    )

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<style>
  :root{{--bg:#0e1116;--panel:#161b22;--panel2:#1c232d;--border:#2b333d;--fg:#e6edf3;--muted:#8b96a3;--mono:ui-monospace,Menlo,monospace}}
  *{{box-sizing:border-box}}
  body{{margin:0;background:var(--bg);color:var(--fg);font-family:system-ui,-apple-system,sans-serif;line-height:1.5}}
  .wrap{{max-width:960px;margin:0 auto;padding:32px 24px 64px}}
  h1{{margin:0 0 4px;font-size:26px}} h1 span{{color:#4c9aff}}
  .subtitle{{color:var(--muted);font-size:14px;margin-bottom:22px}}
  .banner{{background:#3a2a12;border:1px solid #6b4d1f;color:#f0c674;padding:10px 14px;border-radius:8px;font-size:13px;margin-bottom:22px}}
  .grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:22px}}
  .box{{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:18px}}
  .risk{{font-size:30px;font-weight:700}}
  .bar{{display:flex;height:14px;border-radius:7px;overflow:hidden;background:var(--panel2);margin:10px 0}}
  .bar span{{display:block}}
  .pills{{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}}
  .pill{{background:var(--panel2);border:1px solid var(--border);border-radius:999px;padding:4px 11px;font-size:12.5px}}
  .pill b{{font-variant-numeric:tabular-nums}}
  .dot{{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px;vertical-align:middle}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  th,td{{text-align:left;padding:7px 8px;border-bottom:1px solid var(--border)}}
  th{{color:var(--muted);font-weight:600}}
  h2{{font-size:17px;margin:26px 0 12px;border-bottom:1px solid var(--border);padding-bottom:6px}}
  .card{{background:var(--panel);border:1px solid var(--border);border-left-width:4px;border-radius:10px;padding:14px 16px;margin-bottom:12px}}
  .card-head{{display:flex;align-items:center;gap:10px}}
  .card h3{{margin:0;font-size:15.5px}}
  .sev{{font-size:11px;font-weight:700;color:#0e1116;padding:2px 8px;border-radius:5px;letter-spacing:.03em}}
  .meta{{color:var(--muted);font-size:12.5px;margin:6px 0}}
  .meta a{{color:#4c9aff;text-decoration:none}}
  .ev{{font-family:var(--mono);font-size:12px;background:var(--panel2);padding:8px 10px;border-radius:7px;margin:8px 0;white-space:pre-wrap;word-break:break-word}}
  .desc{{font-size:13.5px;margin:6px 0}}
  .fix{{font-size:13.5px}} .fix b{{color:#4c9aff}}
  footer{{color:var(--muted);font-size:12px;margin-top:32px;border-top:1px solid var(--border);padding-top:14px}}
</style></head><body><div class="wrap">
  <h1>Web<span>Fusion</span> — Security Assessment Report</h1>
  <div class="subtitle">{html.escape(title)} · Generated {now} · Scanner WebFusion 0.1.0</div>
  <div class="banner">⚠ Authorized assessment. Target is a demo application owned by the tester.
    This report is for the site's owner and authorized recipients only.</div>

  <div class="grid">
    <div class="box">
      <div style="color:var(--muted);font-size:13px">Overall risk</div>
      <div class="risk" style="color:{risk_color}">{risk}</div>
      <div style="color:var(--muted);font-size:13px;margin-top:8px">Target: {html.escape(target)}</div>
      <div style="color:var(--muted);font-size:13px">Endpoints scanned: {len(results)}</div>
    </div>
    <div class="box">
      <div style="color:var(--muted);font-size:13px">Findings by severity ({len(findings)} total)</div>
      <div class="bar">{bar or '<span style="width:100%;background:var(--panel2)"></span>'}</div>
      <div class="pills">{pills}</div>
    </div>
  </div>

  <h2>Scope — endpoints assessed</h2>
  <div class="box"><table>
    <tr><th>URL</th><th>Mode</th><th>Findings</th><th>Time</th></tr>{endpoints}
  </table></div>

  <h2>Findings ({len(findings)})</h2>
  {''.join(cards) if cards else '<div class="box">No findings.</div>'}

  <footer>Generated by WebFusion — a shift-left DevSecOps scanner.
    For authorized security testing and education only.</footer>
</div></body></html>"""
