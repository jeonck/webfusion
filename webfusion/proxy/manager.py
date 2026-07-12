"""Runs mitmproxy's DumpMaster in a background thread with its own asyncio loop.

The API server (main thread) controls it via start()/stop() and resumes paused
flows by scheduling callbacks onto the proxy loop with call_soon_threadsafe.
"""
from __future__ import annotations

import asyncio
import threading
import time
from typing import Optional

from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from .. import config
from .addon import CaptureAddon


class ProxyManager:
    def __init__(self) -> None:
        self._thread: Optional[threading.Thread] = None
        self._master: Optional[DumpMaster] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self.running = False
        self.port: Optional[int] = None
        self._error: Optional[str] = None

    def status(self) -> dict:
        return {
            "running": self.running,
            "port": self.port,
            "host": config.PROXY_HOST,
            "error": self._error,
        }

    def start(self, port: int) -> dict:
        if self.running:
            return self.status()
        self._error = None
        self.port = port
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        # Wait briefly for the loop to come up (or fail).
        for _ in range(50):
            if self.running or self._error:
                break
            time.sleep(0.05)
        return self.status()

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop

        async def main() -> None:
            # DumpMaster must be constructed while an event loop is running.
            opts = Options(listen_host=config.PROXY_HOST, listen_port=self.port)
            opts.update(ssl_insecure=True)
            master = DumpMaster(opts, with_termlog=False, with_dumper=False)
            master.addons.add(CaptureAddon())
            self._master = master
            self.running = True
            await master.run()

        try:
            loop.run_until_complete(main())
        except Exception as exc:  # port in use, bind error, etc.
            self._error = f"{type(exc).__name__}: {exc}"
        finally:
            self.running = False
            self._master = None

    def stop(self) -> dict:
        if self._master and self._loop:
            self._loop.call_soon_threadsafe(self._master.shutdown)
        self.running = False
        return self.status()

    def resume_flow(self, event) -> None:
        """Set a PendingFlow's resume event from another thread safely."""
        if self._loop is not None:
            self._loop.call_soon_threadsafe(event.set)
        else:
            event.set()
