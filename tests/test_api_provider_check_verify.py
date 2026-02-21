import unittest
from unittest.mock import MagicMock

from clawb_agent_sdk.client import ClawbClient
from clawb_agent_sdk.providers import ApiProvider


class TestApiProviderCheckVerify(unittest.TestCase):
    def test_check_uses_api_key_header(self):
        c = ClawbClient(base_url="https://api.clawb.ai/api")
        c.post = MagicMock(return_value={"status": 200, "json": {"decision": "allow"}})

        p = ApiProvider(client=c, api_key="ck_live_123")
        out = p.check(agent_id="agt_123", policy_id="pol_default", action="refund")

        self.assertEqual(out["decision"], "allow")
        args, kwargs = c.post.call_args
        self.assertEqual(args[0], "/v1/check")
        self.assertEqual(kwargs.get("signed"), False)
        self.assertEqual(kwargs.get("headers"), {"X-Clawb-Api-Key": "ck_live_123"})
        self.assertEqual(kwargs.get("json")["agent_id"], "agt_123")

    def test_verify_uses_api_key_header(self):
        c = ClawbClient(base_url="https://api.clawb.ai/api")
        c.post = MagicMock(return_value={"status": 200, "json": {"valid": True}})

        p = ApiProvider(client=c, api_key="ck_live_123")
        out = p.verify(
            agent_id="agt_123",
            method="POST",
            path="/v1/refunds",
            timestamp_ms=1700000000000,
            nonce="n_1",
            body_sha256="abc",
            signature_b64="sig",
        )

        self.assertTrue(out["valid"])
        args, kwargs = c.post.call_args
        self.assertEqual(args[0], "/v1/verify")
        self.assertEqual(kwargs.get("headers"), {"X-Clawb-Api-Key": "ck_live_123"})
        self.assertEqual(kwargs.get("json")["path"], "/v1/refunds")

    def test_check_uses_bearer_header(self):
        c = ClawbClient(base_url="https://api.clawb.ai/api")
        c.post = MagicMock(return_value={"status": 200, "json": {"decision": "allow"}})

        p = ApiProvider(client=c, bearer_token="provider_token_123", auth_mode="bearer")
        out = p.check(agent_id="agt_123", policy_id="pol_default", action="refund")

        self.assertEqual(out["decision"], "allow")
        args, kwargs = c.post.call_args
        self.assertEqual(args[0], "/v1/check")
        self.assertEqual(kwargs.get("signed"), False)
        self.assertEqual(kwargs.get("headers"), {"Authorization": "Bearer provider_token_123"})

    def test_verify_uses_bearer_header(self):
        c = ClawbClient(base_url="https://api.clawb.ai/api")
        c.post = MagicMock(return_value={"status": 200, "json": {"valid": True}})

        p = ApiProvider(client=c, bearer_token="provider_token_123", auth_mode="bearer")
        out = p.verify(
            agent_id="agt_123",
            method="POST",
            path="/v1/refunds",
            timestamp_ms=1700000000000,
            nonce="n_1",
            body_sha256="abc",
            signature_b64="sig",
        )

        self.assertTrue(out["valid"])
        args, kwargs = c.post.call_args
        self.assertEqual(args[0], "/v1/verify")
        self.assertEqual(kwargs.get("headers"), {"Authorization": "Bearer provider_token_123"})
        self.assertEqual(kwargs.get("json")["path"], "/v1/refunds")


if __name__ == "__main__":
    unittest.main()
