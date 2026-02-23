import base64
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from clawb_agent_sdk.cloud import get_aws_credentials
from clawb_agent_sdk.identity import ClawbIdentity


class _FakeResp:
    def __init__(self, body: bytes):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class TestIdentityAndCloud(unittest.TestCase):
    def test_clawb_identity_sign_request(self):
        priv = Ed25519PrivateKey.generate()
        priv_raw = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        ident = ClawbIdentity(agent_id="agt_1", private_key_b64=base64.b64encode(priv_raw).decode("utf-8"))
        out = ident.sign_request(
            method="POST",
            path="/v1/token/exchange",
            timestamp_ms=1700000000000,
            nonce="n_1",
            body=b'{"ok":true}',
        )
        self.assertEqual(out["agent_id"], "agt_1")
        self.assertEqual(out["method"], "POST")
        self.assertTrue(isinstance(out["signature_b64"], str))

    def test_get_aws_credentials_parses_sts_xml(self):
        xml = b"""<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789012:assumed-role/demo/session</Arn>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>AKIA_TEST</AccessKeyId>
      <SecretAccessKey>SECRET_TEST</SecretAccessKey>
      <SessionToken>TOKEN_TEST</SessionToken>
      <Expiration>2026-02-22T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>"""
        with patch("urllib.request.urlopen", return_value=_FakeResp(xml)) as mocked:
            out = get_aws_credentials(
                clawb_jwt="jwt",
                role_arn="arn:aws:iam::123456789012:role/demo",
                role_session_name="session",
            )
        self.assertEqual(out["access_key_id"], "AKIA_TEST")
        self.assertEqual(out["secret_access_key"], "SECRET_TEST")
        self.assertEqual(out["session_token"], "TOKEN_TEST")
        self.assertEqual(out["assumed_role_arn"], "arn:aws:sts::123456789012:assumed-role/demo/session")
        self.assertTrue(mocked.called)


if __name__ == "__main__":
    unittest.main()

