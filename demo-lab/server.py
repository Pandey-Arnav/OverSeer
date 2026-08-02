#!/usr/bin/env python3
"""
Sentinel demo-lab static server.

Serves the three runtime-behavior demo fixtures on separate localhost
ports so cross-origin popups/iframes/redirects behave realistically:

  8001  01-phishing   (popup spam + notification request + delayed redirect)
  8002  02-tracking   (hidden iframe + fingerprinting + cookie access)
  8003  03-normal     (benign control page — should score low risk)

Everything here is a local fixture. No requests ever leave localhost.

Usage:
    python3 server.py
"""
import http.server
import socketserver
import threading
from pathlib import Path

BASE = Path(__file__).parent / "sites"

SITES = {
    8001: "01-phishing",
    8002: "02-tracking",
    8003: "03-normal",
}


def make_handler(directory: Path):
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(directory), **kwargs)

        def log_message(self, fmt, *args):
            print(f"[:{directory.name}] {fmt % args}")

    return Handler


def serve(port: int, site_dir: str):
    handler = make_handler(BASE / site_dir)
    with socketserver.ThreadingTCPServer(("127.0.0.1", port), handler) as httpd:
        print(f"Serving {site_dir} at http://localhost:{port}/")
        httpd.serve_forever()


def main():
    threads = []
    for port, site_dir in SITES.items():
        t = threading.Thread(target=serve, args=(port, site_dir), daemon=True)
        t.start()
        threads.append(t)

    print("\nSentinel demo-lab running. All fixtures are localhost-only simulations.\n")
    for port, site_dir in SITES.items():
        print(f"  http://localhost:{port}/  ->  {site_dir}")
    print("\nPress Ctrl+C to stop.\n")

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\nStopping demo-lab.")


if __name__ == "__main__":
    main()
