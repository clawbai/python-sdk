#!/usr/bin/env python3
"""Relying service example (FastAPI): call /v1/check before sensitive actions.

This is intentionally minimal. In a real relying service you MUST:
- verify the inbound agent signature (Ed25519) on the original request
- perform timestamp skew + nonce replay checks

Run:
  pip install fastapi uvicorn httpx
  uvicorn relying_service_fastapi:app --reload --port 9000

Then send a request with X-Clawb-Agent-Id set:
  curl -sS -X POST http://localhost:9000/agent/do-sensitive-thing \
    -H 'content-type: application/json' \
    -H 'X-Clawb-Agent-Id: agt_...' \
    -d '{}'
"""

from __future__ import annotations

import os

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request

CLAWB_BASE_URL = os.getenv("CLAWB_BASE_URL", "http://localhost:8000")
CLAWB_POLICY_ID = os.getenv("CLAWB_POLICY_ID", "pol_default")

app = FastAPI()


async def clawb_gate(request: Request):
    # (1) Verify inbound request signature here.
    agent_id = request.headers.get("X-Clawb-Agent-Id")
    if not agent_id:
        raise HTTPException(status_code=401, detail="missing_agent_id")

    # (2) Ask Clawb for a decision BEFORE doing sensitive work.
    async with httpx.AsyncClient(timeout=3.0) as client:
        resp = await client.post(
            f"{CLAWB_BASE_URL}/v1/check",
            json={"agent_id": agent_id, "policy_id": CLAWB_POLICY_ID},
        )

    data = {}
    try:
        if (resp.headers.get("content-type") or "").startswith("application/json"):
            data = resp.json() or {}
    except Exception:
        data = {}

    decision = data.get("decision")
    if decision == "allow":
        return data
    if decision == "challenge":
        raise HTTPException(status_code=401, detail={"error": "challenge_required", "clawb": data})

    raise HTTPException(status_code=403, detail={"error": "access_denied", "clawb": data})


@app.post("/agent/do-sensitive-thing")
async def do_sensitive_thing(clawb=Depends(clawb_gate)):
    # Do the sensitive action here.
    return {"ok": True, "clawb": clawb}
