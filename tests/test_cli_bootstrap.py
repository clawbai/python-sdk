import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from clawb_agent_sdk.cli import cmd_bootstrap


class TestCliBootstrap(unittest.TestCase):
    @patch("clawb_agent_sdk.cli.ClawbClient")
    def test_bootstrap_print_json(self, MockClient):
        # Arrange
        MockClient.generate_ed25519_keypair_b64.return_value = ("priv_b64", "pub_b64")

        # First client instance: register
        c1 = MockClient.return_value
        c1.register.return_value = {
            "agent_id": "agent_123",
            "challenge_id": "chal_123",
            "challenge": "Y2hhbGxlbmdl",  # base64('challenge')
        }

        # Second client instance: attest + claim
        c2 = MockClient.return_value
        c2.attest.return_value = {"ok": True}
        c2.request_claim_code.return_value = {
            "claim_code": "code_123",
            "claim_url": "https://clawb.ai/claim/code_123",
            "expires_at": "2099-01-01T00:00:00Z",
        }

        buf = io.StringIO()

        # Act
        with redirect_stdout(buf):
            rc = cmd_bootstrap(["--name", "my-agent", "--print-json", "--base-url", "https://api.clawb.ai/api"])

        # Assert
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        self.assertEqual(out["agent_id"], "agent_123")
        self.assertEqual(out["public_key_b64"], "pub_b64")
        self.assertEqual(out["private_key_b64"], "priv_b64")
        self.assertEqual(out["claim"]["claim_code"], "code_123")


if __name__ == "__main__":
    unittest.main()
