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

```bash
# Register → attest → claim-code
clawb-agent bootstrap --base-url https://api.clawb.ai/api --name "my-agent"

# Signed heartbeat
clawb-agent heartbeat --base-url https://api.clawb.ai/api --status ok --latency-ms 123
```
