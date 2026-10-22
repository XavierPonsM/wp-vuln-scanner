#!/usr/bin/env python3
"""
scanner.py  —  WordPress & PHP vulnerability scanner.

Usage:
    python3 scanner.py <domain>
    python3 scanner.py example.com
    python3 scanner.py https://example.com --wpscan-key TOKEN
    python3 scanner.py example.com --out ~/Desktop/report.html
"""

import argparse
import platform
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests  # noqa: F401 — early check before heavy imports
except ImportError:
    sys.exit("Missing dependencies. Run: pip3 install requests beautifulsoup4")

from core.vulns import run_scan
from core.report import generate_html

REPORTS_DIR = Path(__file__).parent


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Scan a site for vulnerabilities and generate an HTML report."
    )
    p.add_argument("target", help="Domain or URL to scan (e.g. example.com)")
    p.add_argument(
        "--wpscan-key",
        default="",
        metavar="TOKEN",
        help="WPScan API token for richer WordPress plugin coverage (free, 50 req/day)",
    )
    p.add_argument(
        "--out",
        default="",
        metavar="FILE",
        help="Output path for the HTML report (default: auto-named in the script directory)",
    )
    return p.parse_args()


def open_in_browser(path: Path) -> None:
    """Open the generated report in the system's default browser."""
    try:
        system = platform.system()
        if system == "Darwin":
            subprocess.run(["open", str(path)], check=True)
        elif system == "Windows":
            subprocess.run(["start", str(path)], shell=True, check=True)
        else:
            subprocess.run(["xdg-open", str(path)], check=True)
    except Exception:
        pass


def main() -> None:
    args   = parse_args()
    target = args.target
    if not target.startswith("http"):
        target = "http://" + target

    scan = run_scan(target, wpscan_key=args.wpscan_key)
    html = generate_html(scan)

    if args.out:
        out_path = Path(args.out)
    else:
        hostname = urlparse(target).hostname or "report"
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = REPORTS_DIR / f"report_{hostname}_{ts}.html"

    out_path.write_text(html, encoding="utf-8")

    s = scan["summary"]
    print(f"\n✅  Report saved  →  {out_path}")
    print(f"    CVEs found   :  {s['total']}  "
          f"(Critical: {s['critical']}  High: {s['high']})")
    print("    Opening in browser…")
    open_in_browser(out_path)


if __name__ == "__main__":
    main()
