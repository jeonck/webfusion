"""Vercel serverless entrypoint — the hosted, passive-only scanner + dashboard.

Safety posture (see GOAL.md):
  * PASSIVE ONLY. Active payload injection is never available here.
  * SSRF-guarded: refuses localhost / private / link-local targets.
  * Rate/size bounded by a short timeout.

Exposes an ASGI `app`; Vercel's @vercel/python runtime serves it directly.
"""
from __future__ import annotations

import os
import sys

# Make the repo root importable when Vercel runs this file from /api.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI  # noqa: E402
from fastapi.responses import HTMLResponse, JSONResponse  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from webfusion.scanner import report  # noqa: E402
from webfusion.scanner.engine import ScanError, SsrfBlocked, scan  # noqa: E402

app = FastAPI(title="WebFusion Scanner (hosted)")

_UI_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "webfusion", "ui_scan", "index.html",
)


class ScanReq(BaseModel):
    url: str


@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "mode": "passive-only"}


@app.post("/api/scan")
async def api_scan(req: ScanReq):
    try:
        # allow_private=False -> SSRF guard on; active always False here.
        result = await scan(req.url, active=False, allow_private=False, timeout=12.0)
    except SsrfBlocked as exc:
        return JSONResponse(status_code=400, content={"error": f"blocked: {exc}"})
    except ScanError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})
    if result.error:
        return JSONResponse(status_code=502, content={"error": result.error})
    import json as _json
    return _json.loads(report.to_json(result))


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    try:
        with open(_UI_PATH, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return "<h1>WebFusion Scanner</h1><p>UI asset missing.</p>"
