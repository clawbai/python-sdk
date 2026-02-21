import unittest
from unittest.mock import MagicMock

from clawb_agent_sdk.client import ClawbClient
from clawb_agent_sdk.providers import ApiProvider


class TestApiProvider(unittest.TestCase):
    def test_email_send_uses_api_key_header_unsigned(self):
        c = ClawbClient(base_url="https://api.clawb.ai/api")
        c.post = MagicMock(return_value={"status": 200, "json": {"ok": True}})

        p = ApiProvider(client=c, api_key="ck_live_123")
        out = p.email_send(
            agent_id="agt_123",
            policy_id="pol_default",
            email={"to": ["a@example.com"], "subject": "hi", "text": "yo"},
        )

        self.assertTrue(out["ok"])
        c.post.assert_called_once()
        args, kwargs = c.post.call_args
        self.assertEqual(args[0], "/v1/email/send")
        self.assertEqual(kwargs.get("signed"), False)
        self.assertEqual(kwargs.get("headers"), {"X-Clawb-Api-Key": "ck_live_123"})

    def test_email_send_uses_bearer_header_unsigned(self):
        c = ClawbClient(base_url="https://api.clawb.ai/api")
        c.post = MagicMock(return_value={"status": 200, "json": {"ok": True}})

        p = ApiProvider(client=c, bearer_token="provider_token_123", auth_mode="bearer")
        out = p.email_send(
            agent_id="agt_123",
            policy_id="pol_default",
            email={"to": ["a@example.com"], "subject": "hi", "text": "yo"},
        )

        self.assertTrue(out["ok"])
        c.post.assert_called_once()
        args, kwargs = c.post.call_args
        self.assertEqual(args[0], "/v1/email/send")
        self.assertEqual(kwargs.get("signed"), False)
        self.assertEqual(kwargs.get("headers"), {"Authorization": "Bearer provider_token_123"})

    def test_constructor_rejects_multiple_auth_inputs(self):
        c = ClawbClient(base_url="https://api.clawb.ai/api")

        with self.assertRaises(ValueError):
            ApiProvider(
                client=c,
                api_key="ck_live_123",
                bearer_token="provider_token_123",
                auth_mode="api_key",
            )


if __name__ == "__main__":
    unittest.main()
