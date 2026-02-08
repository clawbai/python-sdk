# Clawb Agent SDK (Python)

Minimal Python client for Clawb agent **registration**, **attestation**, and **request signing**.

## Install (dev)

```bash
cd sdk/python
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

## CLI (agent-first bootstrap)

```bash
# from repo root
cd sdk/python
python -m venv .venv && source .venv/bin/activate
pip install -e .

# Register → attest → request claim code
clawb-agent bootstrap --base-url https://clawb.ai/api --name "my-agent"
```

This prints:
- `agent_id`
- `public_key_b64`
- `private_key_b64` (store securely)
- a `claim_url` to paste into the dashboard

## Quickstart (Python)

```python
from clawb_agent_sdk import ClawbClient

base_url = "https://<your-clawb-host>"  # e.g. http://localhost:8000 or https://clawb.ai/api

# 1) Create keys (Ed25519)
priv_b64, pub_b64 = ClawbClient.generate_ed25519_keypair_b64()

# 2) Register to get a challenge
client = ClawbClient(base_url=base_url)
reg = client.register(name="my-agent", public_key_b64=pub_b64)

# 3) Attest (prove key ownership)
agent_id = reg["agent_id"]
client = ClawbClient(base_url=base_url, agent_id=agent_id, private_key_b64=priv_b64)
client.attest(challenge_id=reg["challenge_id"], challenge_b64=reg["challenge"])

# 4a) Signed agent-owned call (example)
resp = client.post("/v1/telemetry/heartbeat", json={"agent_id": agent_id, "status": "ok"})
print("heartbeat", resp["status"], resp["json"])

# 4b) Unsigned relying-service call (example): /v1/check
# Note: /v1/check is intentionally NOT signed.
checker = ClawbClient(base_url=base_url)
decision = checker.check(agent_id=agent_id, policy_id="pol_default")
print("check", decision)
```

### Runnable example

From the repo root (expects a local Clawb running at http://localhost:8000):

```bash
cd sdk/python
python -m venv .venv && source .venv/bin/activate
pip install -e .
python examples/check.py --base-url http://localhost:8000 --name "my-agent"
```

## Telemetry heartbeat (CLI)

If you exported the env vars printed by `clawb-agent bootstrap`, you can send a signed heartbeat like:

```bash
clawb-agent heartbeat --base-url https://clawb.ai/api --status ok --latency-ms 123
```

## Signing spec

Headers:
- `X-Clawb-Agent-Id`
- `X-Clawb-Timestamp` (unix ms)
- `X-Clawb-Nonce`
- `X-Clawb-Signature` (base64)

Canonical string:

```
METHOD\nPATH\nTIMESTAMP\nNONCE\nSHA256(body)
```
