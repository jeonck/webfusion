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
    "critical": "#8b2fbf", "high": "#d0353f", "medium": "#b0741a",
    "low": "#17857a", "info": "#6b7686",
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
    """Polished, light-themed standalone HTML report (a 'report on white paper').

    Light is a deliberate committed treatment: locked so a dark viewer preference
    can't darken it. Same design as the shareable report artifact.
    """
    findings = _all_findings(results)
    findings.sort(key=lambda f: rank(f.severity), reverse=True)
    counts = _counts(findings)
    risk, _ = _risk(counts)
    now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M")

    bar = "".join(
        f"<span class='seg sev-{s.value}' style='flex:{counts[s.value]}'></span>"
        for s in _SEV_ORDER if counts[s.value]
    )
    chips = "".join(
        f"<div class='chip'><span class='swatch sev-{s.value}'></span>"
        f"{s.value.title()} <b>{counts[s.value]}</b></div>"
        for s in _SEV_ORDER
    )
    rows = "".join(
        f"<tr><td class='mono'>{html.escape(r.target)}</td>"
        f"<td><span class='mode'>{'active' if r.active else 'passive'}</span></td>"
        f"<td class='num'>{len(r.findings)}</td>"
        f"<td class='num'>{r.duration_ms:.0f}<span class='unit'>ms</span></td></tr>"
        for r in results
    )
    cards = []
    for f in findings:
        s = f.severity.value
        ev = f"<div class='ev mono'>{html.escape(f.evidence)}</div>" if f.evidence else ""
        cwe = f"<span class='cwe'>{html.escape(f.cwe)}</span>" if f.cwe else ""
        cards.append(f"""<article class="finding sev-{s}">
  <div class="f-head"><span class="badge sev-{s}">{s.upper()}</span>
    <h3>{html.escape(f.name)}</h3></div>
  <div class="f-meta">{cwe}<span class="conf">{html.escape(f.confidence)} confidence</span>
    <a class="mono" href="{html.escape(f.url)}">{html.escape(f.url)}</a></div>
  {ev}
  <p class="f-desc">{html.escape(f.description)}</p>
  <p class="f-fix"><span>Fix</span>{html.escape(f.remediation)}</p></article>""")

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<style>
  :root{{--bg:#eef1f6;--panel:#fff;--panel-2:#f3f5f9;--border:#e2e6ee;--fg:#1a2231;
    --muted:#5a6575;--accent:#2f6bd8;--crit:#8b2fbf;--high:#d0353f;--med:#b0741a;
    --low:#17857a;--info:#6b7686;--shadow:0 1px 2px rgba(24,39,68,.06),0 10px 30px rgba(24,39,68,.07);
    color-scheme:light;}}
  .sev-critical{{--sev:var(--crit)}}.sev-high{{--sev:var(--high)}}.sev-medium{{--sev:var(--med)}}
  .sev-low{{--sev:var(--low)}}.sev-info{{--sev:var(--info)}}
  *{{box-sizing:border-box}}
  body{{margin:0;background:var(--bg);color:var(--fg);line-height:1.55;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    -webkit-font-smoothing:antialiased}}
  .wrap{{max-width:880px;margin:0 auto;padding:40px 20px 72px;display:flex;flex-direction:column;gap:26px}}
  .mono{{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}}
  .num{{font-variant-numeric:tabular-nums;text-align:right}}
  .eyebrow{{font-size:12px;letter-spacing:.16em;text-transform:uppercase;color:var(--accent);font-weight:600}}
  h1{{margin:6px 0 0;font-size:29px;line-height:1.15;font-weight:700;letter-spacing:-.01em;text-wrap:balance}}
  h1 b{{color:var(--accent)}}
  .submeta{{color:var(--muted);font-size:13.5px;margin-top:6px}}
  .submeta .mono{{color:var(--fg)}}
  .banner{{display:flex;gap:9px;align-items:flex-start;font-size:13px;
    background:color-mix(in srgb,var(--med) 12%,var(--panel));
    border:1px solid color-mix(in srgb,var(--med) 40%,var(--border));border-radius:9px;padding:11px 14px}}
  .banner svg{{flex:none;margin-top:1px;color:var(--med)}}
  .summary{{display:grid;grid-template-columns:minmax(220px,1fr) 1.4fr;gap:16px}}
  @media(max-width:620px){{.summary{{grid-template-columns:1fr}}}}
  .card{{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:18px 20px;box-shadow:var(--shadow)}}
  .k{{font-size:12px;letter-spacing:.09em;text-transform:uppercase;color:var(--muted);font-weight:600}}
  .verdict{{display:flex;flex-direction:column;justify-content:center}}
  .verdict .risk{{font-size:40px;font-weight:800;letter-spacing:-.02em;line-height:1;color:var(--sev);margin-top:6px}}
  .verdict .tot{{color:var(--muted);font-size:13.5px;margin-top:8px}}
  .verdict .tot b{{color:var(--fg);font-variant-numeric:tabular-nums}}
  .bar{{display:flex;height:16px;border-radius:8px;overflow:hidden;margin:12px 0 14px;background:var(--panel-2);gap:2px}}
  .seg{{background:var(--sev)}}
  .legend{{display:flex;flex-wrap:wrap;gap:7px 10px}}
  .chip{{display:inline-flex;align-items:center;gap:7px;font-size:13px;color:var(--muted)}}
  .chip b{{color:var(--fg);font-variant-numeric:tabular-nums}}
  .swatch{{width:9px;height:9px;border-radius:2.5px;background:var(--sev)}}
  .sec-h{{display:flex;align-items:baseline;gap:10px;margin:6px 0 -8px}}
  .sec-h h2{{margin:0;font-size:16px;font-weight:700}}
  .sec-h .count{{color:var(--muted);font-size:13px;font-variant-numeric:tabular-nums}}
  .table-wrap{{overflow-x:auto;border:1px solid var(--border);border-radius:12px;background:var(--panel)}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  thead th{{text-align:left;color:var(--muted);font-weight:600;font-size:11.5px;letter-spacing:.05em;
    text-transform:uppercase;padding:11px 14px;border-bottom:1px solid var(--border)}}
  thead th.num{{text-align:right}}
  tbody td{{padding:10px 14px;border-bottom:1px solid var(--border)}}
  tbody tr:last-child td{{border-bottom:none}}
  td.mono{{font-size:12.5px}}
  .mode{{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);
    border:1px solid var(--border);border-radius:5px;padding:1px 7px}}
  .unit{{color:var(--muted);font-size:11px;margin-left:2px}}
  .findings{{display:flex;flex-direction:column;gap:11px}}
  .finding{{position:relative;background:var(--panel);border:1px solid var(--border);border-radius:12px;
    padding:15px 18px 15px 20px;box-shadow:var(--shadow);overflow:hidden}}
  .finding::before{{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--sev)}}
  .f-head{{display:flex;align-items:center;gap:11px}}
  .f-head h3{{margin:0;font-size:15.5px;font-weight:650;text-wrap:balance}}
  .badge{{flex:none;font-size:10.5px;font-weight:700;letter-spacing:.04em;color:#fff;background:var(--sev);padding:3px 8px;border-radius:5px}}
  .f-meta{{display:flex;flex-wrap:wrap;align-items:center;gap:6px 12px;margin:9px 0 2px;font-size:12.5px;color:var(--muted)}}
  .cwe{{color:var(--sev);font-weight:600}}
  .f-meta a{{color:var(--accent);text-decoration:none;font-size:12px;word-break:break-all}}
  .f-meta a:hover{{text-decoration:underline}}
  .ev{{font-size:12px;background:var(--panel-2);border:1px solid var(--border);border-radius:7px;
    padding:8px 11px;margin:10px 0;white-space:pre-wrap;word-break:break-word;color:var(--fg)}}
  .f-desc{{margin:8px 0 6px;font-size:13.5px}}
  .f-fix{{margin:0;font-size:13px;color:var(--muted)}}
  .f-fix span{{display:inline-block;font-size:10.5px;font-weight:700;letter-spacing:.05em;
    text-transform:uppercase;color:var(--accent);margin-right:8px}}
  footer{{color:var(--muted);font-size:12px;border-top:1px solid var(--border);padding-top:16px;text-align:center}}
  footer b{{color:var(--fg);font-weight:600}}
</style></head><body><div class="wrap">
  <header>
    <div class="eyebrow">Security Assessment</div>
    <h1>Web<b>Fusion</b> report — {html.escape(title)}</h1>
    <div class="submeta">Target <span class="mono">{html.escape(target)}</span> ·
      {len(results)} endpoints · Generated {now} · WebFusion 0.1.0</div>
  </header>

  <div class="banner">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
      stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
    <span>Authorized assessment against a target owned by the tester.
      This report is for the site owner and authorized recipients only.</span>
  </div>

  <section class="summary">
    <div class="card verdict sev-{risk.lower()}">
      <div class="k">Overall risk</div>
      <div class="risk">{risk}</div>
      <div class="tot"><b>{len(findings)}</b> findings across <b>{len(results)}</b> endpoints</div>
    </div>
    <div class="card">
      <div class="k">Findings by severity</div>
      <div class="bar">{bar or '<span class="seg" style="flex:1;background:var(--panel-2)"></span>'}</div>
      <div class="legend">{chips}</div>
    </div>
  </section>

  <div class="sec-h"><h2>Scope</h2><span class="count">{len(results)} endpoints assessed</span></div>
  <div class="table-wrap"><table>
    <thead><tr><th>Endpoint</th><th>Mode</th><th class="num">Findings</th><th class="num">Time</th></tr></thead>
    <tbody>{rows}</tbody></table></div>

  <div class="sec-h"><h2>Findings</h2><span class="count">{len(findings)} total, most severe first</span></div>
  <div class="findings">{''.join(cards) if cards else '<div class="card">No findings.</div>'}</div>

  <footer>Generated by <b>WebFusion</b> — a shift-left DevSecOps scanner ·
    For authorized security testing and education only.</footer>
</div></body></html>"""
