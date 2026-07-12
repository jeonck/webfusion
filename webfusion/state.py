"""Shared application state (single-process singleton).

Holds the scope allow-list, intercept queue, and a reference to the running
proxy manager. Imported by both the API server and the proxy addon so they
can coordinate across threads.
"""
from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass, field
from typing import Any, Optional


class Scope:
    """Host allow-list. When disabled, everything is in scope (recorded).

    Repeater and Fuzzer refuse to send to out-of-scope hosts when enabled —
    this is the primary guard-rail against hitting unauthorized targets.
    """

    def __init__(self) -> None:
        self.enabled: bool = False
        self.hosts: set[str] = set()
        self._lock = threading.Lock()

    def is_allowed(self, host: str) -> bool:
        if not self.enabled:
            return True
        host = (host or "").lower()
        with self._lock:
            for h in self.hosts:
                if host == h or host.endswith("." + h):
                    return True
        return False

    def set(self, enabled: bool, hosts: list[str]) -> None:
        with self._lock:
            self.enabled = enabled
            self.hosts = {h.strip().lower() for h in hosts if h.strip()}

    def as_dict(self) -> dict[str, Any]:
        with self._lock:
            return {"enabled": self.enabled, "hosts": sorted(self.hosts)}


@dataclass
class PendingFlow:
    """A request paused by the interceptor, awaiting user decision."""

    id: int
    method: str
    url: str
    host: str
    headers: dict[str, str]
    body: str
    # Filled in when the user decides:
    action: Optional[str] = None  # "forward" | "drop"
    edited: Optional[dict[str, Any]] = None
    _resume: Any = None  # asyncio.Event (created on the proxy loop)
    _loop: Any = None  # the proxy's asyncio loop


class InterceptState:
    """Holds intercept on/off and the queue of paused flows."""

    def __init__(self) -> None:
        self.enabled: bool = False
        self.pending: dict[int, PendingFlow] = {}
        self._ids = itertools.count(1)
        self._lock = threading.Lock()

    def next_id(self) -> int:
        return next(self._ids)

    def add(self, pf: PendingFlow) -> None:
        with self._lock:
            self.pending[pf.id] = pf

    def pop(self, pid: int) -> Optional[PendingFlow]:
        with self._lock:
            return self.pending.pop(pid, None)

    def get(self, pid: int) -> Optional[PendingFlow]:
        with self._lock:
            return self.pending.get(pid)

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {
                    "id": pf.id,
                    "method": pf.method,
                    "url": pf.url,
                    "host": pf.host,
                    "headers": pf.headers,
                    "body": pf.body,
                }
                for pf in self.pending.values()
            ]


class AppState:
    def __init__(self) -> None:
        self.scope = Scope()
        self.intercept = InterceptState()
        self.proxy = None  # set by server to the ProxyManager instance


STATE = AppState()
