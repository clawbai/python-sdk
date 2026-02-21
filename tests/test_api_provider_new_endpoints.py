import base64
import hashlib
import hmac
import json
import unittest
from unittest.mock import MagicMock

from clawb_agent_sdk.client import ClawbClient
from clawb_agent_sdk.providers import ApiProvider


class TestApiProviderNewEndpoints(unittest.TestCase):
    def test_provider_agents_upsert(self):
        c = ClawbClient(base_url="https://api.clawb.ai/api")
        c.post = MagicMock(return_value={"status": 200, "json": {"ok": True}})

        p = ApiProvider(client=c, api_key="ck_live_123")
        out = p.provider_agents_upsert(
            external_agent_key="ext_1",
            agent_id="agt_1",
            display_name="Demo",
            labels=["a", "b"],
            environment="prod",
            source="provider_api",
            status="active",
        )

        self.assertTrue(out["ok"])
        args, kwargs = c.post.call_args
        self.assertEqual(args[0], "/v1/provider/agents/upsert")
        self.assertEqual(kwargs.get("signed"), False)
        self.assertEqual(kwargs.get("headers"), {"X-Clawb-Api-Key": "ck_live_123"})

    def test_provider_agents_list_query(self):
        c = ClawbClient(base_url="https://api.clawb.ai/api")
        c.get = MagicMock(return_value={"status": 200, "json": {"ok": True}})

        p = ApiProvider(client=c, api_key="ck_live_123")
        out = p.provider_agents_list(environment="prod", status="active", label="team1")

        self.assertTrue(out["ok"])
        args, kwargs = c.get.call_args
        self.assertEqual(args[0], "/v1/provider/agents?environment=prod&status=active&label=team1")
        self.assertEqual(kwargs.get("signed"), False)
        self.assertEqual(kwargs.get("headers"), {"X-Clawb-Api-Key": "ck_live_123"})

    def test_provider_audit_events_query(self):
        c = ClawbClient(base_url="https://api.clawb.ai/api")
        c.get = MagicMock(return_value={"status": 200, "json": {"items": []}})

        p = ApiProvider(client=c, api_key="ck_live_123")
        out = p.provider_audit_events(start_ms=10, end_ms=20, agent_id="agt_1", action="read", limit=5)

        self.assertIn("items", out)
        args, kwargs = c.get.call_args
        self.assertEqual(
            args[0],
            "/v1/provider/audit/events?start_ms=10&end_ms=20&agent_id=agt_1&action=read&limit=5",
        )
        self.assertEqual(kwargs.get("signed"), False)
        self.assertEqual(kwargs.get("headers"), {"X-Clawb-Api-Key": "ck_live_123"})

    def test_provider_audit_export(self):
        c = ClawbClient(base_url="https://api.clawb.ai/api")
        c.post = MagicMock(return_value={"status": 200, "json": {"items": []}})

        p = ApiProvider(client=c, api_key="ck_live_123")
        out = p.provider_audit_export(format="json", filters={"agent_id": "agt_1"}, limit=100)

        self.assertIn("items", out)
        args, kwargs = c.post.call_args
        self.assertEqual(args[0], "/v1/provider/audit/export")
        self.assertEqual(kwargs.get("signed"), False)
        self.assertEqual(kwargs.get("headers"), {"X-Clawb-Api-Key": "ck_live_123"})

    def test_identity_credentials_mint(self):
        c = ClawbClient(base_url="https://api.clawb.ai/api")
        c.post = MagicMock(return_value={"status": 200, "json": {"ok": True}})

        p = ApiProvider(client=c, api_key="ck_live_123")
        out = p.identity_credentials_mint(
            agent_id="agt_1",
            ttl_seconds=120,
            one_time=True,
            scopes=["vault:read"],
            token_type="jwt",
        )

        self.assertTrue(out["ok"])
        args, kwargs = c.post.call_args
        self.assertEqual(args[0], "/v1/identity/credentials/mint")
        self.assertEqual(kwargs.get("signed"), False)
        self.assertEqual(kwargs.get("headers"), {"X-Clawb-Api-Key": "ck_live_123"})

    def test_identity_kill_switch_status(self):
        c = ClawbClient(base_url="https://api.clawb.ai/api")
        c.get = MagicMock(return_value={"status": 200, "json": {"ok": True}})

        p = ApiProvider(client=c, api_key="ck_live_123")
        out = p.identity_kill_switch_status()

        self.assertTrue(out["ok"])
        args, kwargs = c.get.call_args
        self.assertEqual(args[0], "/v1/identity/kill-switch/status")
        self.assertEqual(kwargs.get("signed"), False)
        self.assertEqual(kwargs.get("headers"), {"X-Clawb-Api-Key": "ck_live_123"})

    def test_reputation_feedback_signature_headers(self):
        c = ClawbClient(base_url="https://api.clawb.ai/api")
        c.post = MagicMock(return_value={"status": 200, "json": {"ok": True}})

        p = ApiProvider(client=c, api_key="ck_live_123")
        out = p.reputation_feedback(
            agent_id="agt_1",
            verdict="ok",
            evidence={"source": "test"},
            timestamp_ms=1700000000000,
            nonce="n1",
        )

        self.assertTrue(out["ok"])
        args, kwargs = c.post.call_args
        self.assertEqual(args[0], "/v1/reputation/feedback")
        headers = kwargs.get("headers") or {}

        # Expected signature
        body = json.dumps(
            {"agent_id": "agt_1", "verdict": "ok", "evidence": {"source": "test"}},
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        key_hex = hashlib.sha256(b"ck_live_123").hexdigest()
        key_bytes = bytes.fromhex(key_hex)
        msg = f"1700000000000\nn1\n{hashlib.sha256(body).hexdigest()}".encode("utf-8")
        sig_b64 = base64.b64encode(hmac.new(key_bytes, msg, hashlib.sha256).digest()).decode("utf-8")

        self.assertEqual(headers.get("X-Clawb-Api-Key"), "ck_live_123")
        self.assertEqual(headers.get("X-Clawb-Feedback-Timestamp"), "1700000000000")
        self.assertEqual(headers.get("X-Clawb-Feedback-Nonce"), "n1")
        self.assertEqual(headers.get("X-Clawb-Feedback-Signature"), sig_b64)


if __name__ == "__main__":
    unittest.main()
