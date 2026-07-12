# Deploying WebFusion

The **hosted scanner** (passive-only dashboard + `/api/scan`) is what deploys to
Vercel. The interactive proxy is a local-only tool and is **not** deployed
(a MITM proxy can't run on serverless).

## Vercel

The repo is Vercel-ready:

- `api/index.py` — ASGI app (FastAPI) exposing the dashboard and `/api/scan`.
- `vercel.json` — routes all traffic to the Python function and bundles the
  `webfusion/` package via `includeFiles`.
- `requirements.txt` — slim (fastapi, httpx, uvicorn); no mitmproxy, so the
  serverless bundle stays small.

Deploy:

```bash
npm i -g vercel      # if needed
vercel login
vercel --prod        # from the repo root
```

Vercel auto-detects the Python function. After deploy you get a public URL
serving the passive scanner.

### Notes / limits

- Serverless execution time is capped (10s on Hobby). The hosted scan uses a
  12s client timeout and is passive-only, so it stays well within limits.
- The hosted scanner **blocks internal/private targets** (SSRF guard). This is
  intentional and should stay on for any public deployment.

## GitHub

```bash
git init && git add -A && git commit -m "WebFusion: shift-left scanner + proxy"
gh repo create webfusion --public --source=. --push
```

Once pushed, `.github/workflows/security-scan.yml`:

- runs the self-eval on every push/PR (gates that the scanner works), and
- on manual dispatch with a `target` input, scans that URL and uploads SARIF to
  the repo's **Security → Code scanning** tab.

To connect GitHub → Vercel for automatic deploys, import the repo from the
Vercel dashboard (New Project → Import Git Repository).
