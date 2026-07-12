"""WebFusion scanner CLI — the shift-left / CI entrypoint.

    python -m webfusion.scan https://target.example --active \\
        --fail-on high --sarif report.sarif --json report.json

Exit codes: 0 = clean / below threshold, 1 = usage/scan error,
2 = findings at or above --fail-on (fails the CI job).
"""
from __future__ import annotations

import argparse
import asyncio
import sys

from .scanner import report
from .scanner.engine import ScanError, SsrfBlocked, scan
from .scanner.findings import Severity, rank

_BANNER = (
    "WebFusion scanner — AUTHORIZED TESTING ONLY. Scan only systems you own or "
    "have explicit written permission to test.\n"
)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="webfusion.scan", description="Shift-left web security scanner")
    p.add_argument("url", help="target URL")
    p.add_argument("--active", action="store_true",
                   help="enable intrusive active checks (XSS/SQLi/redirect/traversal)")
    p.add_argument("--fail-on", choices=[s.value for s in Severity], default=None,
                   help="exit 2 if any finding is at or above this severity")
    p.add_argument("--json", metavar="PATH", help="write JSON report")
    p.add_argument("--sarif", metavar="PATH", help="write SARIF 2.1.0 report (GitHub code scanning)")
    p.add_argument("--html", metavar="PATH", help="write HTML report")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--quiet", action="store_true", help="suppress the console report")
    return p.parse_args(argv)


async def _run(args: argparse.Namespace) -> int:
    try:
        result = await scan(args.url, active=args.active, allow_private=True, timeout=args.timeout)
    except (SsrfBlocked, ScanError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not args.quiet:
        print(report.to_console(result, color=not args.no_color))
    if args.json:
        _write(args.json, report.to_json(result))
    if args.sarif:
        _write(args.sarif, report.to_sarif(result))
    if args.html:
        _write(args.html, report.to_html(result))

    if result.error:
        print(f"error: {result.error}", file=sys.stderr)
        return 1
    if args.fail_on:
        threshold = Severity(args.fail_on)
        worst = result.max_severity()
        if worst is not None and rank(worst) >= rank(threshold):
            print(f"\nFAIL: found {worst.value} finding(s) at or above '{args.fail_on}'.", file=sys.stderr)
            return 2
    return 0


def _write(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    print(f"  wrote {path}")


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    sys.stderr.write(_BANNER)
    args = _parse_args(argv)
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
