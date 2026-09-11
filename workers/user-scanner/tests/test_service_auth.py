import os
import unittest
from unittest.mock import patch

import service_auth


VALID_CLAIMS = {
    "iss": "https://oidc.vercel.com/geri6",
    "aud": "https://vercel.com/geri6",
    "sub": "owner:geri6:project:para11ax:environment:production",
    "owner": "geri6",
    "owner_id": "team_hXokufMlDFuhPPT5r8jPf4aH",
    "project": "para11ax",
    "project_id": "prj_ojUpOTw8x8KOj9CrTs8jih1mrPjo",
    "environment": "production",
}


class ServiceAuthTests(unittest.TestCase):
    def test_worker_fails_closed_without_any_service_identity(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(service_auth.authorized({}))
            self.assertFalse(service_auth.authorized({"Authorization": "Bearer anything"}))

    def test_static_token_remains_constant_time_compatible_fallback(self):
        with patch.dict(os.environ, {"USER_SCANNER_WORKER_TOKEN": "expected"}, clear=True):
            self.assertTrue(service_auth.authorized({"Authorization": "Bearer expected"}))
            self.assertFalse(service_auth.authorized({"Authorization": "Bearer wrong"}))

    def test_vercel_oidc_header_is_accepted_only_after_signature_and_claim_validation(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(service_auth, "verify_vercel_oidc", return_value=True) as verify:
            self.assertTrue(service_auth.authorized({"X-Para11ax-Vercel-OIDC": "jwt-value"}))
            verify.assert_called_once_with("jwt-value")

    def test_exact_parent_production_identity_is_required(self):
        self.assertTrue(service_auth.claims_trusted(VALID_CLAIMS))
        for key, bad in [
            ("iss", "https://example.invalid"),
            ("aud", "https://example.invalid"),
            ("sub", "owner:geri6:project:other:environment:production"),
            ("owner", "other"),
            ("owner_id", "team_other"),
            ("project", "other"),
            ("project_id", "prj_other"),
            ("environment", "preview"),
        ]:
            changed = dict(VALID_CLAIMS)
            changed[key] = bad
            self.assertFalse(service_auth.claims_trusted(changed), key)

    def test_verifier_rejects_malformed_or_unverifiable_tokens(self):
        self.assertFalse(service_auth.verify_vercel_oidc(""))
        self.assertFalse(service_auth.verify_vercel_oidc("x" * 20000))
        with patch.object(service_auth, "_JWKS") as jwks:
            jwks.get_signing_key_from_jwt.side_effect = ValueError("bad token")
            self.assertFalse(service_auth.verify_vercel_oidc("a.b.c"))


if __name__ == "__main__":
    unittest.main()
