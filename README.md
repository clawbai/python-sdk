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
