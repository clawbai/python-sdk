import unittest
from unittest.mock import MagicMock

from clawb_agent_sdk.client import ClawbClient


class TestTokenExchangeClient(unittest.TestCase):
    def test_get_token_calls_exchange_endpoint(self):
        c = ClawbClient(base_url="https://api.clawb.ai/api", agent_id="agt_1", private_key_b64="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
        c.post = MagicMock(return_value={"status": 200, "json": {"ok": True, "token": "jwt", "expires_in": 120}})

        out = c.get_token(audience="aws", scopes=["s3:GetObject"], policy_id="pol_default")

        self.assertTrue(out["ok"])
        args, kwargs = c.post.call_args
        self.assertEqual(args[0], "/v1/token/exchange")
        self.assertEqual(kwargs.get("signed"), False)
        self.assertEqual(kwargs["json"]["audience"], "aws")
        self.assertEqual(kwargs["json"]["agent_id"], "agt_1")
        self.assertTrue(isinstance(kwargs["json"]["agent_request"]["signature_b64"], str))

    def test_get_token_uses_cache(self):
        c = ClawbClient(base_url="https://api.clawb.ai/api", agent_id="agt_1", private_key_b64="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
        c.post = MagicMock(return_value={"status": 200, "json": {"ok": True, "token": "jwt_cached", "expires_in": 600}})

        out1 = c.get_token(audience="aws", scopes=["s3:GetObject"])
        out2 = c.get_token(audience="aws", scopes=["s3:GetObject"])

        self.assertEqual(out1["token"], "jwt_cached")
        self.assertEqual(out2["token"], "jwt_cached")
        self.assertEqual(c.post.call_count, 1)


if __name__ == "__main__":
    unittest.main()

