"""Repeater — send a single (usually hand-edited) request and return the
full response. This is the Burp Repeater workflow.
"""
from __future__ import annotations

from . import httpsend


async def repeat(method: str, url: str, headers: dict, body: str, timeout: float = 30.0) -> dict:
    return await httpsend.send_once(method, url, headers, body, timeout=timeout)
