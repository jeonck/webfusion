"""Fuzzer — Burp Intruder-style payload injection, without Community's rate cap.

A request template contains a marker (default ``§FUZZ§``) somewhere in the URL,
a header value, or the body. Each payload is substituted for the marker and the
requests are fired concurrently. Results are collected in an in-memory job so
the UI can poll progress.
"""
from __future__ import annotations

import asyncio
import itertools
import time
from typing import Any, Optional

import httpx

from . import httpsend

DEFAULT_MARKER = "§FUZZ§"

_jobs: dict[int, dict[str, Any]] = {}
_job_ids = itertools.count(1)


def get_job(job_id: int) -> Optional[dict]:
    return _jobs.get(job_id)


def _substitute(template: dict, marker: str, payload: str) -> dict:
    method = template["method"]
    url = template["url"].replace(marker, payload)
    headers = {
        k: v.replace(marker, payload) for k, v in (template.get("headers") or {}).items()
    }
    body = (template.get("body") or "").replace(marker, payload)
    return {"method": method, "url": url, "headers": headers, "body": body}


async def _run(job_id: int, template: dict, marker: str, payloads: list[str], concurrency: int) -> None:
    job = _jobs[job_id]
    sem = asyncio.Semaphore(max(1, concurrency))
    async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=30.0) as client:

        async def one(idx: int, payload: str) -> None:
            req = _substitute(template, marker, payload)
            async with sem:
                entry: dict[str, Any] = {"index": idx, "payload": payload}
                try:
                    r = await httpsend.send(
                        client, req["method"], req["url"], req["headers"], req["body"]
                    )
                    entry.update(
                        status=r["status"],
                        length=r["length"],
                        duration_ms=r["duration_ms"],
                        error=None,
                    )
                except Exception as exc:
                    entry.update(status=None, length=0, duration_ms=None, error=str(exc))
                job["results"].append(entry)
                job["done"] += 1

        await asyncio.gather(*(one(i, p) for i, p in enumerate(payloads)))

    job["results"].sort(key=lambda e: e["index"])
    job["status"] = "finished"
    job["finished_at"] = time.time()


def start(template: dict, payloads: list[str], marker: str = DEFAULT_MARKER, concurrency: int = 20) -> int:
    """Launch a fuzz job on the current event loop; returns its job id."""
    job_id = next(_job_ids)
    _jobs[job_id] = {
        "id": job_id,
        "status": "running",
        "total": len(payloads),
        "done": 0,
        "results": [],
        "started_at": time.time(),
        "finished_at": None,
        "marker": marker,
    }
    asyncio.create_task(_run(job_id, template, marker, payloads, concurrency))
    return job_id
