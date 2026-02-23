<p align="center">
  <img src="https://clawb.ai/logo.png" alt="Clawb" width="520" />
</p>

# Clawb Agent SDK (Python)

Python SDK for Clawb agent **registration**, **attestation**, **request signing**, and provider-side **verify/check** helpers.

## Documentation (source of truth)

All step-by-step guides live in the docs (so we only maintain them in one place):

- Python SDK guide: https://docs.clawb.ai/sdk/python
- Provider flow (Verify → Check): https://docs.clawb.ai/integration/provider-flow

## Install

```bash
pip install clawb-agent-sdk
```

## Repository

- Repo: https://github.com/clawbai/python-sdk

## Development (editable install)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .

# run tests
python -m unittest discover -s tests -p 'test_*.py'
```

## CLI

`--base-url`/`base_url` should always be the Clawb API root (it already includes `/api`).

```bash
# Register → attest → claim-code
clawb-agent bootstrap --base-url https://api.clawb.ai/api --name "my-agent"

# Signed heartbeat
clawb-agent heartbeat --base-url https://api.clawb.ai/api --status ok --latency-ms 123
```

## Provider check (canonical flow)

`/v1/check` is a provider-authenticated server-to-server endpoint.
Use `ApiProvider.check(...)` with either an API key header (default) or bearer token:

```python
from clawb_agent_sdk import ApiProvider, ClawbClient

client = ClawbClient(base_url="https://api.clawb.ai/api")

# Default (backward-compatible): X-Clawb-Api-Key header
provider = ApiProvider(client=client, api_key="ck_live_...")
decision = provider.check(agent_id="agt_123", policy_id="pol_default")

# Optional: Authorization: Bearer ... header
provider_bearer = ApiProvider(
    client=client,
    bearer_token="provider_token_...",
    auth_mode="bearer",
)
decision = provider_bearer.check(agent_id="agt_123", policy_id="pol_default")
```

`ClawbClient.check(...)` is kept only as a deprecated compatibility shim and now
requires an `api_key`; prefer `ApiProvider.check(...)` in new code.

## Provider APIs (new)

The SDK now wraps additional provider-key endpoints:

- Agent identity mapping: `provider_agents_upsert(...)`, `provider_agents_list(...)`
- Audit queries/exports: `provider_audit_events(...)`, `provider_audit_export(...)`
- Minted credentials: `identity_credentials_mint(...)`, `identity_credentials_revoke(...)`,
  `identity_credentials_revoke_by_agent(...)`
- Kill switch controls: `identity_kill_switch_minting(...)`, `identity_kill_switch_revoke_all(...)`,
  `identity_kill_switch_status(...)`
- Reputation feedback (HMAC signed): `reputation_feedback(...)`

Example (mint credentials):

```python
from clawb_agent_sdk import ApiProvider, ClawbClient

client = ClawbClient(base_url="https://api.clawb.ai/api")
provider = ApiProvider(client=client, api_key="ck_live_...")

resp = provider.identity_credentials_mint(
    agent_id="agt_123",
    ttl_seconds=300,
    one_time=True,
    scopes=["vault:read"],
    token_type="jwt",
)
```

## Token exchange + identity helpers

Use `get_token(...)` to exchange a signed assertion for a short-lived OIDC JWT.
The SDK keeps a small local cache to avoid unnecessary exchange calls.

```python
from clawb_agent_sdk import ClawbClient

client = ClawbClient(
    base_url="https://api.clawb.ai/api",
    agent_id="agt_123",
    private_key_b64="<base64-ed25519-private-seed>",
)

token_resp = client.get_token(
    audience="aws",
    scopes=["s3:GetObject"],
    policy_id="pol_default",
)
jwt = token_resp["token"]
```

`ClawbIdentity.sign_request(...)` provides low-level canonical signing for custom runtimes:

```python
from clawb_agent_sdk import ClawbIdentity

identity = ClawbIdentity(agent_id="agt_123", private_key_b64="<base64-ed25519-private-seed>")
signed = identity.sign_request(
    method="POST",
    path="/v1/token/exchange",
    timestamp_ms=1740137855000,
    nonce="n_123",
    body=b'{"hello":"world"}',
)
```

AWS helper:

```python
from clawb_agent_sdk import get_aws_credentials

creds = get_aws_credentials(
    clawb_jwt=jwt,
    role_arn="arn:aws:iam::123456789012:role/demo",
    role_session_name="agent-session",
)
```

## Public metadata endpoints

```python
from clawb_agent_sdk import ClawbClient

client = ClawbClient(base_url="https://api.clawb.ai/api")
config = client.well_known_openid_configuration()
jwks = client.well_known_jwks()
```
