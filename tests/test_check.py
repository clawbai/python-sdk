import unittest
from unittest.mock import MagicMock

from clawb_agent_sdk.client import ClawbClient


class TestCheck(unittest.TestCase):
    def test_check_calls_unsigned(self):
        c = ClawbClient(base_url="https://api.clawb.ai/api")
        c.post = MagicMock(return_value={"status": 200, "json": {"decision": "allow"}})

        out = c.check(agent_id="agt_123", policy_id="pol_default")

        self.assertEqual(out["decision"], "allow")
        c.post.assert_called_once()
        args, kwargs = c.post.call_args
        self.assertEqual(args[0], "/v1/check")
        self.assertEqual(kwargs.get("signed"), False)
        self.assertEqual(kwargs.get("headers"), None)
        self.assertEqual(kwargs.get("json"), {"agent_id": "agt_123", "policy_id": "pol_default"})

    def test_check_with_api_key_sets_provider_header(self):
        c = ClawbClient(base_url="https://api.clawb.ai/api")
        c.post = MagicMock(return_value={"status": 200, "json": {"decision": "allow"}})

        c.check(agent_id="agt_123", policy_id="pol_default", api_key="  pk_test_123  ")

        _, kwargs = c.post.call_args
        self.assertEqual(kwargs.get("signed"), False)
        self.assertEqual(kwargs.get("headers"), {"X-Clawb-Api-Key": "pk_test_123"})


if __name__ == "__main__":
    unittest.main()
