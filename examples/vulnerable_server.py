"""A deliberately insecure local HTTP server, for demoing the scanner.

It serves a site with missing security headers, a verbose Server banner,
flag-less cookies, a weak CSP, a telling robots.txt and several "exposed"
sensitive files (/.git/config, /.env, backup.zip, ...). Unknown paths get a
real 404, so soft-404 calibration behaves naturally.

Usage:
    python examples/vulnerable_server.py --port 8099
Then, in another shell:
    websec-scan http://127.0.0.1:8099 --authorized --html report.html --json report.json

This is for local demonstration only. Do not expose it to a network.
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOME_BODY = b"""<!doctype html><html><head><title>Vulnerable Demo App</title></head>
<body><h1>Vulnerable Demo App</h1><p>Intentionally insecure site for scanner demos.</p></body></html>"""

ROBOTS = b"""User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /config/
Disallow: /public/
"""

# Map of "exposed" files -> body served with HTTP 200.
EXPOSED = {
    "/.git/config": b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n",
    "/.env": b"APP_KEY=base64:deadbeef\nDB_PASSWORD=SuperSecret123\nSTRIPE_KEY=sk_live_x\n",
    "/backup.zip": b"PK\x03\x04" + b"\x00" * 300,  # pretend ZIP
    "/wp-config.php": b"<?php define('DB_PASSWORD', 'secret'); // exposed\n",
    "/composer.json": b'{"name":"demo/app","require":{"php":">=8.1"}}\n',
}


class Handler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.52"
    sys_version = "(Unix) PHP/8.1.2"

    def log_message(self, *args):  # silence console noise
        pass

    def _send(self, status: int, body: bytes, extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "PHP/8.1.2")
        # Weak CSP and flag-less cookie on the home page only.
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(
                200,
                HOME_BODY,
                {
                    "Content-Security-Policy": "default-src * 'unsafe-inline'; script-src 'self' 'unsafe-inline'",
                    "Set-Cookie": "session=abc123; Path=/",
                },
            )
        elif path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(ROBOTS)))
            self.end_headers()
            self.wfile.write(ROBOTS)
        elif path in EXPOSED:
            self._send(200, EXPOSED[path])
        else:
            body = b"<html><body><h1>404 Not Found</h1></body></html>"
            self._send(404, body)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8099)
    args = ap.parse_args()
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Serving vulnerable demo on http://{args.host}:{args.port} (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()

# GROGNON
