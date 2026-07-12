"""mitmproxy addon: captures every flow into the history DB and, when
intercept mode is on, pauses in-scope requests until the user forwards/drops.
"""
from __future__ import annotations

import asyncio
import json

from mitmproxy import http

from .. import db
from ..state import STATE, PendingFlow


def _headers_dict(headers) -> dict[str, str]:
    return {k: v for k, v in headers.items()}


class CaptureAddon:
    # ---- request side: intercept ----
    async def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.host
        in_scope = STATE.scope.is_allowed(host)

        if not (STATE.intercept.enabled and in_scope):
            return

        loop = asyncio.get_running_loop()
        pid = STATE.intercept.next_id()
        pf = PendingFlow(
            id=pid,
            method=flow.request.method,
            url=flow.request.pretty_url,
            host=host,
            headers=_headers_dict(flow.request.headers),
            body=flow.request.get_text(strict=False) or "",
        )
        pf._resume = asyncio.Event()
        pf._loop = loop
        STATE.intercept.add(pf)

        # Block this flow's hook until the API sets the resume event.
        await pf._resume.wait()
        STATE.intercept.pop(pid)

        if pf.action == "drop":
            flow.response = http.Response.make(
                444, b"Dropped by WebFusion", {"Content-Type": "text/plain"}
            )
            return

        if pf.edited:
            self._apply_edit(flow, pf.edited)

    @staticmethod
    def _apply_edit(flow: http.HTTPFlow, edited: dict) -> None:
        req = flow.request
        if edited.get("method"):
            req.method = edited["method"]
        if edited.get("url"):
            req.url = edited["url"]
        if isinstance(edited.get("headers"), dict):
            req.headers.clear()
            for k, v in edited["headers"].items():
                req.headers[k] = v
        if edited.get("body") is not None:
            req.text = edited["body"]

    # ---- response side: record ----
    def response(self, flow: http.HTTPFlow) -> None:
        self._record(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        # Connection errors etc. — still record the request that was attempted.
        if flow.response is None:
            self._record(flow, status=0)

    @staticmethod
    def _record(flow: http.HTTPFlow, status: int | None = None) -> None:
        req = flow.request
        resp = flow.response
        duration = None
        if resp is not None and req.timestamp_start and resp.timestamp_end:
            duration = (resp.timestamp_end - req.timestamp_start) * 1000.0

        resp_body = resp.get_text(strict=False) if resp is not None else ""
        rec = {
            "method": req.method,
            "scheme": req.scheme,
            "host": req.host,
            "port": req.port,
            "path": req.path,
            "url": req.pretty_url,
            "req_headers": json.dumps(_headers_dict(req.headers)),
            "req_body": req.get_text(strict=False) or "",
            "status": resp.status_code if resp is not None else (status or 0),
            "resp_headers": json.dumps(_headers_dict(resp.headers)) if resp else "{}",
            "resp_body": resp_body or "",
            "resp_length": len(resp.raw_content or b"") if resp is not None else 0,
            "duration_ms": duration,
            "in_scope": 1 if STATE.scope.is_allowed(req.host) else 0,
        }
        try:
            db.insert_flow(rec)
        except Exception:  # never let a DB hiccup break the proxy path
            pass
