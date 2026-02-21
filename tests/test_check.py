import unittest
import warnings
from unittest.mock import MagicMock

from clawb_agent_sdk.client import ClawbClient


class TestCheck(unittest.TestCase):
    def test_check_raises_without_api_key(self):
        c = ClawbClient(base_url="https://api.clawb.ai/api")

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", DeprecationWarning)
            with self.assertRaisesRegex(ValueError, "provider api_key is required"):
                c.check(agent_id="agt_123", policy_id="pol_default")

        self.assertTrue(any(isinstance(w.message, DeprecationWarning) for w in caught))

    def test_check_delegates_to_provider_flow(self):
        c = ClawbClient(base_url="https://api.clawb.ai/api")
        c.post = MagicMock(return_value={"status": 200, "json": {"decision": "allow"}})

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", DeprecationWarning)
            out = c.check(agent_id="agt_123", policy_id="pol_default", api_key="  pk_test_123  ")

        self.assertEqual(out["decision"], "allow")
        self.assertTrue(any(isinstance(w.message, DeprecationWarning) for w in caught))
        c.post.assert_called_once()
        args, kwargs = c.post.call_args
        self.assertEqual(args[0], "/v1/check")
        self.assertEqual(kwargs.get("signed"), False)
        self.assertEqual(kwargs.get("headers"), {"X-Clawb-Api-Key": "pk_test_123"})
        self.assertEqual(kwargs.get("json"), {"agent_id": "agt_123", "policy_id": "pol_default"})


if __name__ == "__main__":
    unittest.main()
