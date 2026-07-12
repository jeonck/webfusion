"""FastAPI app: history, proxy control, scope, intercept, Repeater, Fuzzer."""
from __future__ import annotations

import asyncio
import os
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .. import config, db
from ..core import fuzzer, repeater
from ..core.httpsend import ScopeError
from ..proxy.manager import ProxyManager
from ..state import STATE

app = FastAPI(title="WebFusion", version="0.1.0")

UI_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ui")


@app.on_event("startup")
def _startup() -> None:
    db.init()
    STATE.proxy = ProxyManager()


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #
class ProxyStartReq(BaseModel):
    port: int = config.DEFAULT_PROXY_PORT


class ScopeReq(BaseModel):
    enabled: bool = False
    hosts: list[str] = []


class ToggleReq(BaseModel):
    enabled: bool


class EditReq(BaseModel):
    method: Optional[str] = None
    url: Optional[str] = None
    headers: Optional[dict[str, str]] = None
    body: Optional[str] = None


class RepeaterReq(BaseModel):
    method: str = "GET"
    url: str
    headers: dict[str, str] = {}
    body: str = ""


class FuzzReq(BaseModel):
    method: str = "GET"
    url: str
    headers: dict[str, str] = {}
    body: str = ""
    marker: str = fuzzer.DEFAULT_MARKER
    payloads: list[str] = []
    concurrency: int = 20


# --------------------------------------------------------------------------- #
# History
# --------------------------------------------------------------------------- #
@app.get("/api/flows")
def api_flows(limit: int = 200, offset: int = 0, host: Optional[str] = None) -> Any:
    return db.list_flows(limit=limit, offset=offset, host=host)


@app.get("/api/flows/{flow_id}")
def api_flow(flow_id: int) -> Any:
    rec = db.get_flow(flow_id)
    if not rec:
        raise HTTPException(404, "flow not found")
    return rec


@app.delete("/api/flows")
def api_clear() -> Any:
    db.clear()
    return {"ok": True}


# --------------------------------------------------------------------------- #
# Proxy control
# --------------------------------------------------------------------------- #
@app.get("/api/proxy/status")
def proxy_status() -> Any:
    return STATE.proxy.status()


@app.post("/api/proxy/start")
def proxy_start(req: ProxyStartReq) -> Any:
    return STATE.proxy.start(req.port)


@app.post("/api/proxy/stop")
def proxy_stop() -> Any:
    return STATE.proxy.stop()


@app.get("/api/proxy/ca")
def proxy_ca() -> Any:
    exists = os.path.exists(config.CA_CERT_PATH)
    return {"path": config.CA_CERT_PATH, "exists": exists}


@app.get("/api/proxy/ca/download")
def proxy_ca_download() -> Any:
    if not os.path.exists(config.CA_CERT_PATH):
        raise HTTPException(404, "CA cert not generated yet — start the proxy first")
    return FileResponse(config.CA_CERT_PATH, filename="webfusion-ca.pem")


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #
@app.get("/api/scope")
def scope_get() -> Any:
    return STATE.scope.as_dict()


@app.post("/api/scope")
def scope_set(req: ScopeReq) -> Any:
    STATE.scope.set(req.enabled, req.hosts)
    return STATE.scope.as_dict()


# --------------------------------------------------------------------------- #
# Intercept
# --------------------------------------------------------------------------- #
@app.get("/api/intercept")
def intercept_get() -> Any:
    return {"enabled": STATE.intercept.enabled, "pending": STATE.intercept.list()}


@app.post("/api/intercept/toggle")
def intercept_toggle(req: ToggleReq) -> Any:
    STATE.intercept.enabled = req.enabled
    # If turning off, release everything currently held.
    if not req.enabled:
        for pf in STATE.intercept.list():
            _resume(pf["id"], action="forward")
    return {"enabled": STATE.intercept.enabled}


@app.post("/api/intercept/{pid}/forward")
def intercept_forward(pid: int, edit: EditReq) -> Any:
    edited = {k: v for k, v in edit.dict().items() if v is not None} or None
    if not _resume(pid, action="forward", edited=edited):
        raise HTTPException(404, "no such pending flow")
    return {"ok": True}


@app.post("/api/intercept/{pid}/drop")
def intercept_drop(pid: int) -> Any:
    if not _resume(pid, action="drop"):
        raise HTTPException(404, "no such pending flow")
    return {"ok": True}


def _resume(pid: int, action: str, edited: Optional[dict] = None) -> bool:
    pf = STATE.intercept.get(pid)
    if not pf:
        return False
    pf.action = action
    pf.edited = edited
    STATE.proxy.resume_flow(pf._resume)
    return True


# --------------------------------------------------------------------------- #
# Repeater
# --------------------------------------------------------------------------- #
@app.post("/api/repeater/send")
async def repeater_send(req: RepeaterReq) -> Any:
    try:
        return await repeater.repeat(req.method, req.url, req.headers, req.body)
    except ScopeError as exc:
        raise HTTPException(403, str(exc))
    except Exception as exc:
        return JSONResponse(status_code=502, content={"error": str(exc)})


# --------------------------------------------------------------------------- #
# Fuzzer
# --------------------------------------------------------------------------- #
@app.post("/api/fuzzer/start")
async def fuzzer_start(req: FuzzReq) -> Any:
    if not req.payloads:
        raise HTTPException(400, "no payloads provided")
    marker = req.marker or fuzzer.DEFAULT_MARKER
    template = {"method": req.method, "url": req.url, "headers": req.headers, "body": req.body}
    if marker not in (req.url + "".join(req.headers.values()) + req.body):
        raise HTTPException(400, f"marker '{marker}' not found in request template")
    job_id = fuzzer.start(template, req.payloads, marker=marker, concurrency=req.concurrency)
    return {"job_id": job_id}


@app.get("/api/fuzzer/{job_id}")
def fuzzer_status(job_id: int) -> Any:
    job = fuzzer.get_job(job_id)
    if not job:
        raise HTTPException(404, "no such job")
    return job


# --------------------------------------------------------------------------- #
# UI (mounted last so /api/* wins)
# --------------------------------------------------------------------------- #
@app.get("/")
def index() -> Any:
    return FileResponse(os.path.join(UI_DIR, "index.html"))


app.mount("/static", StaticFiles(directory=UI_DIR), name="static")
