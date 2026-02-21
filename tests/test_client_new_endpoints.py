import unittest
from unittest.mock import MagicMock

from clawb_agent_sdk.client import ClawbClient


class TestClientNewEndpoints(unittest.TestCase):
    def test_identity_introspect_unsigned(self):
        c = ClawbClient(base_url="https://api.clawb.ai/api")
        c.post = MagicMock(return_value={"status": 200, "json": {"active": True}})

        out = c.identity_introspect(token="tok_123", scope_hash="h_1")

        self.assertTrue(out["active"])
        args, kwargs = c.post.call_args
        self.assertEqual(args[0], "/v1/identity/introspect")
        self.assertEqual(kwargs.get("signed"), False)
        self.assertEqual(kwargs.get("json"), {"token": "tok_123", "scope_hash": "h_1"})

    def test_well_known_endpoints_unsigned(self):
        c = ClawbClient(base_url="https://api.clawb.ai/api")
        c.get = MagicMock(return_value={"status": 200, "json": {"ok": True}})

        out1 = c.well_known_openid_configuration()
        out2 = c.well_known_jwks()

        self.assertTrue(out1["ok"])
        self.assertTrue(out2["ok"])
        calls = c.get.call_args_list
        self.assertEqual(calls[0][0][0], "/.well-known/openid-configuration")
        self.assertEqual(calls[0][1].get("signed"), False)
        self.assertEqual(calls[1][0][0], "/.well-known/clawb/jwks.json")
        self.assertEqual(calls[1][1].get("signed"), False)

    def test_request_claim_code_uses_agent_path(self):
        c = ClawbClient(
            base_url="https://api.clawb.ai/api",
            agent_id="agt_123",
            private_key_b64="priv",
        )
        c.post = MagicMock(return_value={"status": 200, "json": {"ok": True}})

        out = c.request_claim_code()

        self.assertTrue(out["ok"])
        args, kwargs = c.post.call_args
        self.assertEqual(args[0], "/v1/agents/agt_123/claim-code")
        self.assertEqual(kwargs.get("signed"), True)


if __name__ == "__main__":
    unittest.main()
