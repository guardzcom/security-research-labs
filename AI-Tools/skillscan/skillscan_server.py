#!/usr/bin/env python3
"""skillscan web server - serves the HTML frontend and provides a URL fetch API.

Usage:
    python skillscan_server.py [--port 8080] [--bind 127.0.0.1]

Opens skillscan_web.html in the browser and provides /api/fetch for URL scanning.
"""

import http.server
import json
import os
import sys
import urllib.error
import urllib.request
import webbrowser
from argparse import ArgumentParser
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
HTML_FILE = SCRIPT_DIR / "skillscan_web.html"


class SkillScanHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler that serves the HTML UI and a URL-fetch API."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(SCRIPT_DIR), **kwargs)

    def do_GET(self):
        if self.path == "/" or self.path == "":
            self.path = "/skillscan_web.html"
        super().do_GET()

    def do_POST(self):
        if self.path == "/api/fetch":
            self._handle_fetch()
        else:
            self.send_error(404)

    def _handle_fetch(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            data = json.loads(body)
            url = data.get("url", "")

            if not url.startswith(("http://", "https://")):
                self._json_response(400, {"error": "URL must start with http:// or https://"})
                return

            req = urllib.request.Request(url, headers={
                "User-Agent": "skillscan/1.0",
                "Accept": "text/plain, text/html, text/markdown, */*",
            })
            with urllib.request.urlopen(req, timeout=30) as resp:
                content = resp.read().decode("utf-8", errors="replace")

            self._json_response(200, {"content": content, "url": url})

        except urllib.error.HTTPError as e:
            self._json_response(502, {"error": f"Remote server returned HTTP {e.code}"})
        except urllib.error.URLError as e:
            self._json_response(502, {"error": f"Failed to connect: {e.reason}"})
        except json.JSONDecodeError:
            self._json_response(400, {"error": "Invalid JSON body"})
        except Exception as e:
            self._json_response(500, {"error": str(e)})

    def _json_response(self, status, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        sys.stderr.write(f"[skillscan] {args[0]}\n")


def main():
    parser = ArgumentParser(description="SkillScan web server")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    parser.add_argument("--bind", default="127.0.0.1", help="Address to bind to (default: 127.0.0.1)")
    parser.add_argument("--no-open", action="store_true", help="Don't open browser automatically")
    args = parser.parse_args()

    if not HTML_FILE.exists():
        print(f"Error: {HTML_FILE} not found", file=sys.stderr)
        sys.exit(1)

    server = http.server.HTTPServer((args.bind, args.port), SkillScanHandler)
    url = f"http://{args.bind}:{args.port}"
    print(f"SkillScan server running at {url}")
    print("Press Ctrl+C to stop\n")

    if not args.no_open:
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
