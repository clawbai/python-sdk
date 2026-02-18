import unittest
from unittest.mock import MagicMock

from clawb_agent_sdk.client import ClawbClient
from clawb_agent_sdk.providers import VaultProvider


class TestVaultProvider(unittest.TestCase):
    def test_policy_eval_signed(self):
        c = ClawbClient(base_url="https://api.clawb.ai/api", agent_id="agt_1", private_key_b64="priv")
        c.post = MagicMock(return_value={"status": 200, "json": {"ok": True}})

        v = VaultProvider(client=c)
        out = v.policy_eval(secret_set_id=123, action="export", keys=["A"], environment="dev", provider="openai")

        self.assertTrue(out["ok"])
        c.post.assert_called_once()
        args, kwargs = c.post.call_args
        self.assertEqual(args[0], "/v1/vault/policy/eval")
        self.assertEqual(kwargs.get("signed"), True)
        self.assertEqual(
            kwargs.get("json"),
            {"secret_set_id": 123, "action": "export", "keys": ["A"], "environment": "dev", "provider": "openai"},
        )

    def test_secrets_read_signed(self):
        c = ClawbClient(base_url="https://api.clawb.ai/api", agent_id="agt_1", private_key_b64="priv")
        c.post = MagicMock(return_value={"status": 200, "json": {"ok": True, "secrets": {"A": "x"}}})

        v = VaultProvider(client=c)
        out = v.secrets_read(request_lease_token="tok", secret_set_id=5, keys=["A"], environment="prod")

        self.assertTrue(out["ok"])
        args, kwargs = c.post.call_args
        self.assertEqual(args[0], "/v1/vault/secrets/read")
        self.assertEqual(kwargs.get("signed"), True)
        self.assertEqual(kwargs.get("json"), {"request_lease_token": "tok", "secret_set_id": 5, "keys": ["A"], "environment": "prod"})


if __name__ == "__main__":
    unittest.main()
