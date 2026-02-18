from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..client import ClawbClient


@dataclass
class VaultProvider:
    """Agent-signed Vault endpoints.

    This wrapper covers the agent-signed Vault flow:
      1) policy eval (optional)             POST /v1/vault/policy/eval
      2) mint request lease from workflow   POST /v1/vault/leases/request/mint
      3) read secrets                       POST /v1/vault/secrets/read
      4) proxy request with injections      POST /v1/vault/proxy/request

    Dashboard-session Vault endpoints (secret-set CRUD, grants CRUD, workflow lease CRUD)
    are intentionally not supported here.
    """

    client: ClawbClient

    def policy_eval(
        self,
        *,
        secret_set_id: int,
        action: str,
        keys: Optional[List[str]] = None,
        environment: Optional[str] = None,
        provider: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "secret_set_id": int(secret_set_id),
            "action": action,
        }
        if keys is not None:
            payload["keys"] = list(keys)
        if environment is not None:
            payload["environment"] = environment
        if provider is not None:
            payload["provider"] = provider

        r = self.client.post("/v1/vault/policy/eval", signed=True, json=payload)
        if r["status"] >= 400:
            raise RuntimeError(f"vault policy_eval failed: status={r['status']} body={r.get('json') or r.get('body')}")
        return r["json"]

    def mint_request_lease(
        self,
        *,
        workflow_lease_token: str,
        secret_set_id: int,
        action: str,
        keys: Optional[List[str]] = None,
        ttl_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "workflow_lease_token": workflow_lease_token,
            "secret_set_id": int(secret_set_id),
            "action": action,
        }
        if keys is not None:
            payload["keys"] = list(keys)
        if ttl_seconds is not None:
            payload["ttl_seconds"] = int(ttl_seconds)

        r = self.client.post("/v1/vault/leases/request/mint", signed=True, json=payload)
        if r["status"] >= 400:
            raise RuntimeError(f"vault mint_request_lease failed: status={r['status']} body={r.get('json') or r.get('body')}")
        return r["json"]

    def secrets_read(
        self,
        *,
        request_lease_token: str,
        secret_set_id: int,
        keys: List[str],
        environment: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "request_lease_token": request_lease_token,
            "secret_set_id": int(secret_set_id),
            "keys": list(keys),
        }
        if environment is not None:
            payload["environment"] = environment

        r = self.client.post("/v1/vault/secrets/read", signed=True, json=payload)
        if r["status"] >= 400:
            raise RuntimeError(f"vault secrets_read failed: status={r['status']} body={r.get('json') or r.get('body')}")
        return r["json"]

    def proxy_request(
        self,
        *,
        request_lease_token: str,
        secret_set_id: int,
        profile: str,
        request: Dict[str, Any],
        environment: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "request_lease_token": request_lease_token,
            "secret_set_id": int(secret_set_id),
            "profile": profile,
            "request": dict(request or {}),
        }
        if environment is not None:
            payload["environment"] = environment

        r = self.client.post("/v1/vault/proxy/request", signed=True, json=payload)
        if r["status"] >= 400:
            raise RuntimeError(f"vault proxy_request failed: status={r['status']} body={r.get('json') or r.get('body')}")
        return r["json"]
