"""'Acme Store' — a deliberately-vulnerable demo web app.

  ⛔ DO NOT DEPLOY. LOCAL USE ONLY. ⛔

This is a purpose-built target so WebFusion can be demonstrated end-to-end
(scan -> report) against a site we own, instead of probing third parties. It
intentionally contains real vulnerability classes. It binds to 127.0.0.1 only.

Run:  python demo/target_app.py --port 8099
"""
from __future__ import annotations

import argparse
import html

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, RedirectResponse, Response

app = FastAPI(title="Acme Store (vulnerable demo)")

_MYSQL_ERROR = (
    "You have an error in your SQL syntax; check the manual that corresponds to "
    "your MySQL server version for the right syntax near \"'\" at line 1"
)
_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"

_NAV = """<nav style='font-family:system-ui;padding:8px 0'>
<a href='/'>Home</a> · <a href='/search?q=shoes'>Search</a> ·
<a href='/product?id=1'>Product</a> · <a href='/login'>Login</a> ·
<a href='/download?file=readme.txt'>Download</a></nav>"""


def _page(title: str, body: str, headers: dict | None = None, status: int = 200) -> HTMLResponse:
    doc = f"<!doctype html><html><head><title>{title}</title></head><body>{_NAV}{body}</body></html>"
    return HTMLResponse(doc, status_code=status, headers=headers or {})


@app.get("/", response_class=HTMLResponse)
def home():
    # No security headers set anywhere on the app (intentional).
    return _page("Acme Store", "<h1>Acme Store</h1><p>Welcome to the demo storefront.</p>")


@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    # VULN: reflected XSS — q echoed unencoded.
    return _page("Search", f"<h1>Results for {q}</h1><p>No products matched.</p>")


@app.get("/product", response_class=HTMLResponse)
def product(id: str = "1"):
    # VULN: error-based SQL injection.
    if "'" in id:
        return _page("Error", f"<pre>{_MYSQL_ERROR}</pre>", status=500)
    return _page("Product", f"<h1>Product #{html.escape(id)}</h1><p>A fine product.</p>")


@app.get("/login", response_class=HTMLResponse)
def login():
    # VULN: session cookie without HttpOnly/Secure/SameSite.
    body = "<h1>Login</h1><form><input name=user><input name=pass type=password></form>"
    return _page("Login", body, headers={"set-cookie": "SESSIONID=demo-abc-123; Path=/"})


@app.get("/redirect")
def redirect(url: str = "/"):
    # VULN: open redirect.
    return RedirectResponse(url)


@app.get("/download", response_class=HTMLResponse)
def download(file: str = "readme.txt"):
    # VULN: path traversal.
    if "etc/passwd" in file:
        return _page("File", f"<pre>{_PASSWD}</pre>")
    return _page("Download", f"<h1>Downloading {html.escape(file)}</h1>")


@app.get("/api/orders")
def api_orders():
    # VULN: CORS wildcard + credentials, plus version disclosure.
    return Response(
        content='{"orders":[]}', media_type="application/json",
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            "Server": "Apache/2.4.29",
            "X-Powered-By": "PHP/7.2.1",
        },
    )


# Routes WebFusion should crawl for the demo report.
ROUTES = [
    "/",
    "/search?q=shoes",
    "/product?id=1",
    "/login",
    "/redirect?url=/account",
    "/download?file=readme.txt",
    "/api/orders",
]


if __name__ == "__main__":
    import uvicorn
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8099)
    a = ap.parse_args()
    print("⛔ Vulnerable demo target — LOCAL ONLY, DO NOT DEPLOY ⛔")
    uvicorn.run(app, host="127.0.0.1", port=a.port, log_level="warning")
