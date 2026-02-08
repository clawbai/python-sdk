import base64
import unittest

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from clawb_agent_sdk.signing import canonical_bytes, generate_ed25519_keypair_b64, sign_canonical_b64


class TestSigning(unittest.TestCase):
    def test_canonical_format(self):
        c = canonical_bytes(
            method="POST",
            path="/v1/telemetry/heartbeat",
            timestamp_ms=1700000000000,
            nonce="abc123",
            body=b"{}",
        ).decode("utf-8")
        self.assertTrue(c.startswith("POST\n/v1/telemetry/heartbeat\n1700000000000\nabc123\n"))
        self.assertEqual(len(c.split("\n")), 5)

    def test_sign_and_verify(self):
        priv_b64, pub_b64 = generate_ed25519_keypair_b64()
        canonical = b"hello"
        sig_b64 = sign_canonical_b64(priv_b64, canonical)

        pub = ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
        pub.verify(base64.b64decode(sig_b64), canonical)


if __name__ == "__main__":
    unittest.main()
