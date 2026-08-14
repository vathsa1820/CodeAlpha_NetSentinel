"""
NetSentinel — Controlled Test HTTP Server
Phase 3 — Controlled Attack Simulation

A minimal, safe HTTP server used exclusively for testing the NetSentinel
HTTP detection rule (SID 9000003).

Usage:
    python tests/test_http_server.py [port]
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import sys


class NetSentinelTestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Handle incoming HTTP GET requests."""
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        response_msg = f"NetSentinel Test Server OK. Received URI: {self.path}\n"
        self.wfile.write(response_msg.encode("utf-8"))

    def log_message(self, format, *args):
        """Custom clean log format."""
        print(f"[Test HTTP Server] {self.address_string()} - {args[0]}")


def run(server_class=HTTPServer, handler_class=NetSentinelTestHandler, port=8080):
    server_address = ("0.0.0.0", port)
    httpd = server_class(server_address, handler_class)
    print(f"[NetSentinel] Controlled Test HTTP Server running on http://127.0.0.1:{port}/")
    print("[NetSentinel] Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[NetSentinel] Test HTTP Server stopped.")
        httpd.server_close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run(port=port)
