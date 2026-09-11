import hmac
import json
import os
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlsplit

from worker import run_scan


VERCEL_ISSUER = "https://oidc.vercel.com/geri6"
VERCEL_AUDIENCE = "https://vercel.com/geri6"
VERCEL_SUBJECT = "owner:geri6:project:para11ax:environment:production"
VERCEL_OWNER_ID = "team_hXokufMlDFuhPPT5r8jPf4aH"
VERCEL_PROJECT_ID = "prj_ojUpOTw8x8KOj9CrTs8jih1mrPjo"
_JWKS_CLIENT = None


def _verify_vercel_oidc(token: str) -> bool:
    global _JWKS_CLIENT
    try:
        import jwt
        from jwt import PyJWKClient

        if _JWKS_CLIENT is None:
            _JWKS_CLIENT = PyJWKClient(f"{VERCEL_ISSUER}/.well-known/jwks")
        key = _JWKS_CLIENT.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=VERCEL_ISSUER,
            audience=VERCEL_AUDIENCE,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
        return (
            hmac.compare_digest(str(claims.get("sub", "")), VERCEL_SUBJECT)
            and hmac.compare_digest(str(claims.get("owner_id", "")), VERCEL_OWNER_ID)
            and hmac.compare_digest(str(claims.get("project_id", "")), VERCEL_PROJECT_ID)
            and hmac.compare_digest(str(claims.get("environment", "")), "production")
        )
    except Exception:
        return False


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
        supplied = self.headers.get("Authorization", "")
        if not supplied.startswith("Bearer "):
            return False
        token = supplied[7:].strip()
        if not token:
            return False
        expected = os.environ.get("USER_SCANNER_WORKER_TOKEN", "").strip()
        if expected and hmac.compare_digest(token, expected):
            return True
        return _verify_vercel_oidc(token)

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
