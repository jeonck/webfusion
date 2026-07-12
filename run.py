#!/usr/bin/env python3
"""WebFusion entrypoint — starts the web UI + API server.

    python run.py

Then open http://127.0.0.1:8777 and start the proxy from the UI.

FOR AUTHORIZED SECURITY TESTING ONLY.
"""
import uvicorn

from webfusion import config

if __name__ == "__main__":
    print("WebFusion — authorized security testing only.")
    print(f"  Web UI:  http://{config.API_HOST}:{config.API_PORT}")
    print(f"  Proxy:   start it from the UI (default {config.PROXY_HOST}:{config.DEFAULT_PROXY_PORT})")
    uvicorn.run("webfusion.api.server:app", host=config.API_HOST, port=config.API_PORT, reload=False)
