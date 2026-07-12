# WebFusion

A **shift-left DevSecOps** web-security toolkit that fuses two workflows over one
codebase:

1. **Scanner** (shift-left / CI) — a headless, API-first vulnerability scanner
   with **SARIF + JSON** output and CI exit-code gates. Runs in your pipeline,
   in a hosted dashboard, or from the CLI. *This is the shift-left surface.*
2. **Interactive proxy** (local) — an intercepting proxy with **Repeater** and a
   rate-cap-free **Fuzzer**, fusing OWASP ZAP-style capture with Burp-style
   manual testing for hands-on verification.

> ⚠️ **Authorized use only.** Scan/test only systems you own or have **explicit
> written permission** to test.

---

## 1. Shift-left scanner

Catch issues in dev/CI instead of production. Three ways to run it:

### CLI (for CI pipelines)

```bash
pip install -r requirements.txt
python -m webfusion.scan https://your-app.example.com \
    --active --fail-on high \
    --sarif report.sarif --json report.json
```

- **Passive checks** (safe, always on): missing security headers (CSP, HSTS,
  X-Content-Type-Options, X-Frame-Options, Referrer-Policy), insecure cookie
  flags, CORS wildcard-with-credentials, version disclosure, stack-trace leaks.
- **Active checks** (`--active`, intrusive): reflected XSS, error-based SQL
  injection, open redirect, path traversal — each baseline-compared to limit
  false positives.
- **`--fail-on <severity>`** exits `2` when findings meet the gate, failing the
  CI job. Every finding carries severity, confidence, evidence, CWE, and a fix.

### GitHub Actions (SARIF → Security tab)

`.github/workflows/security-scan.yml` runs the scanner and uploads SARIF so
findings appear in the repo's **Security → Code scanning** tab and on PRs. It
also self-tests the scanner against a bundled vulnerable app on every push.

### Hosted dashboard (Vercel)

A one-box web UI for **passive** scans. The hosted mode is deliberately
constrained (see Safety):

```bash
uvicorn api.index:app --port 8778      # run locally
# or deploy to Vercel — see DEPLOY.md
```

### End-to-end demo + report

A bundled vulnerable demo site (`demo/target_app.py`, **local only — never
deploy**) lets you see the whole flow produce a real deliverable:

```bash
python demo/run_demo.py           # boots the target, active-scans 7 routes
```

It writes a full assessment report to `demo/report/`:

- **`report.html`** — executive summary, overall risk rating, severity
  breakdown, per-endpoint scope table, and every finding with evidence, CWE, and
  remediation. (A committed sample is in [`demo/report/`](demo/report/).)
- **`report.json`** — machine-readable, and **`report.sarif`** for code scanning.

The multi-endpoint report generator (`webfusion/scanner/report_bundle.py`) is
reusable for any real assessment — aggregate several `scan()` results and call
`report_bundle.to_html / to_json / to_sarif`.

## 2. Interactive proxy (local)

```bash
pip install -r requirements-proxy.txt   # adds mitmproxy
python run.py                            # http://127.0.0.1:8777
```

Start the proxy from the UI, point your browser at `127.0.0.1:8080`, install the
CA (Download CA button), and browse. **History → Send to Repeater / Fuzzer** for
manual testing; **Intercept** to pause/edit/forward requests; **Scope** to
restrict which hosts the tools will touch. Full details below under *Proxy*.

---

## Safety design

- **Public/hosted scanner is passive-only.** Active payload injection exists only
  in the local CLI (`--active`), never on the hosted site.
- **SSRF guard:** the hosted scanner refuses localhost, private, link-local, and
  reserved address ranges (e.g. it blocks `169.254.169.254`).
- **Scope allow-list** in the proxy: Repeater/Fuzzer refuse out-of-scope hosts.
- Every entrypoint prints/points to an "authorized targets only" warning.

## Quality gate (loop-engineered)

`GOAL.md` defines a six-dimension rubric; `eval/run_eval.py` boots a bundled
vulnerable app, scans it plus a clean route, and scores detection recall,
precision, shift-left fit, safety, deployability, and usability. The build was
iterated until the eval reached **100/100** (recall & precision 100%).

```bash
python eval/run_eval.py
```

## Architecture

```
 webfusion/
   scanner/     passive.py · active.py · engine.py (SSRF guard) · report.py (SARIF/JSON/HTML)
   scan.py      CLI  (python -m webfusion.scan)
   proxy/       mitmproxy addon + manager (local interactive)
   core/        Repeater / Fuzzer / scoped httpx sender
   api/         local proxy UI + API (server.py)
   ui/ ui_scan/ web front-ends
 api/index.py   Vercel serverless entry (hosted passive scanner)
 eval/          vulnerable_app.py + run_eval.py (self-scoring loop)
 .github/       CI workflow (scan + SARIF upload)
```

## Deploy

See [DEPLOY.md](DEPLOY.md) for Vercel and GitHub setup.

## Legal

For authorized security testing and education only. You are responsible for
having permission to test any target and for complying with applicable law.
