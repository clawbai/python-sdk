#!/usr/bin/env python3
"""End-to-end SDK smoke test:

- generate keypair
- register
- attest
- call /v1/check (provider-key authenticated)

This is meant to be runnable against a local dev server.
"""

from __future__ import annotations

import argparse
import json

from clawb_agent_sdk import ApiProvider, ClawbClient


def main() -> int:
    ap = argparse.ArgumentParser(description="Clawb SDK example: register/attest then call /v1/check")
    ap.add_argument("--base-url", default="http://localhost:8000", help="Clawb API base url")
    ap.add_argument("--name", default="example-agent", help="Agent name")
    ap.add_argument("--policy-id", default="pol_default", help="Policy id")
    ap.add_argument("--api-key", required=True, help="Provider API key for /v1/check")
    args = ap.parse_args()

    priv_b64, pub_b64 = ClawbClient.generate_ed25519_keypair_b64()

    client = ClawbClient(base_url=args.base_url)
    reg = client.register(name=args.name, public_key_b64=pub_b64)

    agent_id = reg["agent_id"]

    attester = ClawbClient(base_url=args.base_url, agent_id=agent_id, private_key_b64=priv_b64)
    attester.attest(challenge_id=reg["challenge_id"], challenge_b64=reg["challenge"])

    provider = ApiProvider(client=ClawbClient(base_url=args.base_url), api_key=args.api_key)
    decision = provider.check(agent_id=agent_id, policy_id=args.policy_id)

    print(json.dumps({"agent_id": agent_id, "decision": decision}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
