import hmac
import json
import os
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlsplit

from worker import run_scan


def _request_path(value: str) -> str:
    return urlsplit(value).path


class handler(BaseHTTPRequestHandler):
    def _json(self, status: int, body: dict):
        encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _authorized(self) -> bool:
        expected = os.environ.get("USER_SCANNER_WORKER_TOKEN", "")
        if not expected:
            return True
        supplied = self.headers.get("Authorization", "")
        if not supplied.startswith("Bearer "):
            return False
        return hmac.compare_digest(supplied[7:], expected)

    def do_GET(self):
        if _request_path(self.path) == "/health":
            self._json(200, {"status": "ok", "service": "user-scanner"})
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self):
        if _request_path(self.path) != "/scan":
            self._json(404, {"error": "not_found"})
            return
        if not self._authorized():
            self._json(401, {"error": "unauthorized"})
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            self._json(415, {"error": "unsupported_media_type"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._json(400, {"error": "invalid_request"})
            return
        if length <= 0 or length > 4096:
            self._json(413 if length > 4096 else 400, {"error": "payload_too_large" if length > 4096 else "invalid_request"})
            return
        try:
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError("invalid_request")
            result = run_scan(payload)
        except ValueError as exc:
            self._json(400, {"error": str(exc)})
            return
        except Exception:
            self._json(500, {"error": "scan_failed"})
            return
        self._json(200, result)
