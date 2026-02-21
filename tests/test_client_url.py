import unittest

from clawb_agent_sdk.client import ClawbClient


class TestClientUrl(unittest.TestCase):
    def test_url_joins_against_api_root_without_double_slash(self):
        c = ClawbClient(base_url="https://api.clawb.ai/api/")

        self.assertEqual(c._url("v1/check"), "https://api.clawb.ai/api/v1/check")
        self.assertEqual(c._url("/v1/check"), "https://api.clawb.ai/api/v1/check")


if __name__ == "__main__":
    unittest.main()
