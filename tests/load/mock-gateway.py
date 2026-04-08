#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Minimal mock gateway for OHTTP relay load testing.

Returns dummy responses for POST /v2/ohttp and GET /v2/ohttp-key.
No real OHTTP decryption — just echoes back opaque bytes.
"""

import http.server
import sys


class MockGateway(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/v2/ohttp":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length > 0 else b""
            # Echo back the body as an opaque "encrypted response"
            self.send_response(200)
            self.send_header("Content-Type", "message/ohttp-res")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def do_GET(self):
        if self.path == "/v2/ohttp-key":
            # Return a dummy OHTTP key config (32 random-looking bytes)
            key_body = bytes(range(32))
            self.send_response(200)
            self.send_header("Content-Type", "application/ohttp-keys")
            self.send_header("Key-Fingerprint", "mock-fingerprint-abc123")
            self.send_header("Content-Length", str(len(key_body)))
            self.end_headers()
            self.wfile.write(key_body)
        elif self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_error(404)

    def log_message(self, format, *args):
        # Suppress request logging to keep CI output clean
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9090
    server = http.server.HTTPServer(("127.0.0.1", port), MockGateway)
    print(f"Mock gateway listening on 127.0.0.1:{port}", flush=True)
    server.serve_forever()
