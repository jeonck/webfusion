"""A deliberately-vulnerable local app used ONLY to validate the scanner.

Never deploy this. It exists so active checks can be exercised against a target
we own, instead of probing third-party sites. Run:

    python eval/vulnerable_app.py --port 8091
"""
from __future__ import annotations

import argparse

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

app = FastAPI()

_MYSQL_ERROR = (
    "You have an error in your SQL syntax; check the manual that corresponds to "
    "your MySQL server version for the right syntax near \"'\" at line 1"
)
_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    # VULN: reflected XSS — q echoed unencoded. Missing all security headers.
    return f"<html><body><h1>Results for {q}</h1></body></html>"


@app.get("/user", response_class=HTMLResponse)
def user(id: str = "1"):
    # VULN: error-based SQLi — a quote breaks the "query".
    if "'" in id:
        return HTMLResponse(f"<pre>{_MYSQL_ERROR}</pre>", status_code=500)
    return f"<html><body>user {id}</body></html>"


@app.get("/go")
def go(url: str = "/"):
    # VULN: open redirect — no allow-list.
    return RedirectResponse(url)


@app.get("/file", response_class=HTMLResponse)
def file(name: str = "readme.txt"):
    # VULN: path traversal.
    if "etc/passwd" in name:
        return HTMLResponse(f"<pre>{_PASSWD}</pre>")
    return f"<html><body>file: {name}</body></html>"


@app.get("/set-cookie", response_class=HTMLResponse)
def set_cookie():
    # VULN: cookie without HttpOnly/Secure/SameSite.
    r = HTMLResponse("<html><body>ok</body></html>")
    r.headers["set-cookie"] = "session=abc123; Path=/"
    return r


@app.get("/api/data")
def api_data():
    # VULN: CORS wildcard + credentials, version disclosure.
    return Response(
        content='{"ok":true}', media_type="application/json",
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            "Server": "Apache/2.4.29",
            "X-Powered-By": "PHP/7.2.1",
        },
    )


@app.get("/clean", response_class=HTMLResponse)
def clean(q: str = ""):
    # CLEAN: output-encoded, all security headers set — must yield 0 findings.
    import html as _html
    body = f"<html><body><h1>Results for {_html.escape(q)}</h1></body></html>"
    return HTMLResponse(body, headers={
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=63072000",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    })


if __name__ == "__main__":
    import uvicorn
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8091)
    a = ap.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=a.port, log_level="warning")
