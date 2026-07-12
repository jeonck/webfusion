"""End-to-end demo: boot the vulnerable target, scan every route with WebFusion,
and write a full report (HTML + JSON + SARIF).

    python demo/run_demo.py [--outdir demo/report] [--keep-open]

Everything runs against 127.0.0.1 (a target we own), so active checks are safe.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from demo.target_app import ROUTES  # noqa: E402
from webfusion.scanner import report_bundle  # noqa: E402
from webfusion.scanner.engine import scan  # noqa: E402

PORT = 8099
BASE = f"http://127.0.0.1:{PORT}"


def _wait_port(port: int, timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            s.settimeout(0.3)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


async def _scan_all() -> list:
    results = []
    for route in ROUTES:
        res = await scan(BASE + route, active=True, allow_private=True)
        results.append(res)
        n = len(res.findings)
        worst = res.max_severity()
        print(f"  scanned {route:32s} {n} finding(s)"
              + (f", worst={worst.value}" if worst else ""))
    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default=os.path.join(os.path.dirname(__file__), "report"))
    ap.add_argument("--keep-open", action="store_true", help="leave target running")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    print("Booting vulnerable demo target (Acme Store)…")
    proc = subprocess.Popen(
        [sys.executable, os.path.join(os.path.dirname(__file__), "target_app.py"), "--port", str(PORT)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        if not _wait_port(PORT):
            print("target did not start", file=sys.stderr)
            return 1
        print(f"Scanning {len(ROUTES)} endpoints of {BASE} (active)…")
        results = asyncio.run(_scan_all())

        title = "Acme Store — demo assessment"
        html_path = os.path.join(args.outdir, "report.html")
        json_path = os.path.join(args.outdir, "report.json")
        sarif_path = os.path.join(args.outdir, "report.sarif")
        _w(html_path, report_bundle.to_html(results, title, BASE))
        _w(json_path, report_bundle.to_json(results, title, BASE))
        _w(sarif_path, report_bundle.to_sarif(results))

        summ = report_bundle.aggregate(results)
        print("\n=== Report summary ===")
        print(f"  risk: {summ['risk_rating']}  |  {summ['total_findings']} findings across "
              f"{summ['endpoints_scanned']} endpoints")
        print(f"  counts: {summ['counts']}")
        print(f"\n  HTML : {html_path}\n  JSON : {json_path}\n  SARIF: {sarif_path}")
        if args.keep_open:
            print(f"\nTarget still running at {BASE} (Ctrl-C to stop).")
            proc.wait()
        return 0
    finally:
        if not args.keep_open:
            proc.terminate()


def _w(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


if __name__ == "__main__":
    raise SystemExit(main())
