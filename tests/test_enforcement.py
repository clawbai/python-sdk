import unittest

from clawb_agent_sdk.enforcement import (
    BlockedActionError,
    EnforcementConfig,
    EnforcementRequest,
    OutboundEnforcer,
)


class TestEnforcement(unittest.TestCase):
    def test_allow_and_trace_propagation(self):
        calls = []

        def fake_request(path, payload, *, timeout, provider_api_key):
            calls.append((path, payload, timeout, provider_api_key))
            if path == "/v1/verify":
                return {"decision": "allow"}
            return {"decision": "allow", "trace": {"trace_id": "trc_server"}}

        cfg = EnforcementConfig.for_profile(
            "prod",
            clawb_base_url="https://api.clawb.ai",
            provider_api_key="k_test",
        )
        enforcer = OutboundEnforcer(cfg, request_fn=fake_request)
        ctx = enforcer.build_context(
            provider_id="prv_1",
            workspace_id="wrk_1",
            agent_id="agt_1",
            action="tool.call",
            destination="tool://foo",
            method="invoke",
            resource_type="tool",
            trace_id="trc_inbound",
        )

        result = enforcer.enforce(
            EnforcementRequest(policy_id="pol_default", fail_open=False, context=ctx)
        )

        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["trace_id"], "trc_server")
        self.assertEqual(calls[0][0], "/v1/verify")
        self.assertEqual(calls[1][0], "/v1/check")
        self.assertEqual(calls[1][1]["context"]["trace_id"], "trc_inbound")

    def test_deny_raises_blocked_error(self):
        def fake_request(path, payload, *, timeout, provider_api_key):
            if path == "/v1/verify":
                return {"decision": "allow"}
            return {"decision": "deny", "trace": {"trace_id": "trc_deny"}}

        cfg = EnforcementConfig.for_profile(
            "prod",
            clawb_base_url="https://api.clawb.ai",
            provider_api_key="k_test",
        )
        enforcer = OutboundEnforcer(cfg, request_fn=fake_request)
        ctx = enforcer.build_context(
            provider_id="prv_1",
            workspace_id="wrk_1",
            agent_id="agt_1",
            action="resource.read",
            destination="https://example.com",
            method="GET",
            resource_type="http",
            trace_id="trc_deny",
        )

        with self.assertRaises(BlockedActionError) as err:
            enforcer.enforce(EnforcementRequest(policy_id="pol_default", fail_open=False, context=ctx))

        self.assertIn("trc_deny", str(err.exception))


if __name__ == "__main__":
    unittest.main()

class TestResilience(unittest.TestCase):
    def test_fail_open_on_unavailable_dev_profile(self):
        attempts = {"n": 0}

        def failing_request(path, payload, *, timeout, provider_api_key):
            attempts["n"] += 1
            raise RuntimeError("boom")

        cfg = EnforcementConfig.for_profile(
            "dev",
            clawb_base_url="https://api.clawb.ai",
            provider_api_key="k_test",
        )
        enforcer = OutboundEnforcer(cfg, request_fn=failing_request, sleep_fn=lambda _: None)
        ctx = enforcer.build_context(
            provider_id="prv_1",
            workspace_id="wrk_1",
            agent_id="agt_1",
            action="resource.read",
            destination="https://example.com",
            method="GET",
            resource_type="http",
            trace_id="trc_fallback",
        )

        result = enforcer.enforce(EnforcementRequest(policy_id="pol_default", fail_open=True, context=ctx))

        self.assertEqual(result["decision"], "allow")
        self.assertTrue(result["degraded"])
        self.assertGreaterEqual(attempts["n"], 2)
