from __future__ import annotations

import base64
import hashlib
import json as _json
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, Literal, Optional

from ..client import ClawbClient
from ..signing import build_feedback_headers


@dataclass
class ApiProvider:
    """Provider-key authenticated endpoints (for relying services).

    This helper is for API providers calling Clawb from server-to-server code.

    Endpoints:
      - POST /v1/check  (policy decision)  -> requires provider API key
      - POST /v1/verify (online signature verification) -> requires provider API key
      - POST /v1/email/send (provider-key authenticated send)

    This helper does not manage dashboard-session endpoints such as
    /v1/provider/api-keys.
    """

    client: ClawbClient
    api_key: Optional[str] = None
    bearer_token: Optional[str] = None
    auth_mode: Literal["api_key", "bearer"] = "api_key"

    def __post_init__(self) -> None:
        if self.auth_mode not in ("api_key", "bearer"):
            raise ValueError("auth_mode must be either 'api_key' or 'bearer'")

        has_api_key = bool((self.api_key or "").strip())
        has_bearer = bool((self.bearer_token or "").strip())
        if has_api_key and has_bearer:
            raise ValueError("api_key and bearer_token are mutually exclusive")

        if self.auth_mode == "api_key" and not has_api_key:
            raise ValueError("api_key is required when auth_mode='api_key'")
        if self.auth_mode == "bearer" and not has_bearer:
            raise ValueError("bearer_token is required when auth_mode='bearer'")

    def _headers(self) -> Dict[str, str]:
        if self.auth_mode == "bearer":
            token = (self.bearer_token or "").strip()
            if not token:
                raise ValueError("bearer_token is required when auth_mode='bearer'")
            return {"Authorization": f"Bearer {token}"}

        k = (self.api_key or "").strip()
        if not k:
            raise ValueError("api_key is required when auth_mode='api_key'")
        return {"X-Clawb-Api-Key": k}

    @staticmethod
    def sha256_hex(body: bytes) -> str:
        return hashlib.sha256(body or b"").hexdigest()

    @staticmethod
    def sha256_b64(body: bytes) -> str:
        return base64.b64encode(hashlib.sha256(body or b"").digest()).decode("utf-8")

    @staticmethod
    def _encode_query(params: Dict[str, Any]) -> str:
        clean: Dict[str, Any] = {}
        for k, v in (params or {}).items():
            if v is None:
                continue
            clean[k] = v
        if not clean:
            return ""
        return "?" + urllib.parse.urlencode(clean, doseq=True)

    def _require_api_key(self) -> str:
        if self.auth_mode != "api_key":
            raise ValueError("api_key auth_mode is required for this endpoint")
        k = (self.api_key or "").strip()
        if not k:
            raise ValueError("api_key is required when auth_mode='api_key'")
        return k

    def check(
        self,
        *,
        agent_id: str,
        policy_id: str = "pol_default",
        action: Optional[str] = None,
        context: Optional[dict] = None,
        email: Optional[dict] = None,
        extra: Optional[dict] = None,
    ) -> Dict[str, Any]:
        """POST /v1/check (provider-key required).

        This is a server-to-server call made by a relying service/provider.
        """

        payload: Dict[str, Any] = {
            "agent_id": agent_id,
            "policy_id": policy_id,
        }
        if action is not None:
            payload["action"] = action
        if context is not None:
            payload["context"] = context
        if email is not None:
            payload["email"] = email
        if extra:
            payload.update(dict(extra))

        r = self.client.post(
            "/v1/check",
            signed=False,
            headers=self._headers(),
            json=payload,
        )
        if r["status"] >= 400:
            raise RuntimeError(f"check failed: status={r['status']} body={r.get('json') or r.get('body')}")
        return r["json"]

    def verify(
        self,
        *,
        agent_id: str,
        method: str,
        path: str,
        timestamp_ms: int,
        nonce: str,
        body_sha256: str,
        signature_b64: str,
    ) -> Dict[str, Any]:
        """POST /v1/verify (online signature verification).

        You compute the fields from the ORIGINAL inbound request and ask Clawb
        to validate the agent signature.
        """

        payload = {
            "agent_id": agent_id,
            "method": method,
            "path": path,
            "timestamp_ms": int(timestamp_ms),
            "nonce": nonce,
            "body_sha256": body_sha256,
            "signature_b64": signature_b64,
        }

        r = self.client.post(
            "/v1/verify",
            signed=False,
            headers=self._headers(),
            json=payload,
        )
        if r["status"] >= 400:
            raise RuntimeError(f"verify failed: status={r['status']} body={r.get('json') or r.get('body')}")
        return r["json"]

    def email_send(
        self,
        *,
        agent_id: str,
        email: Dict[str, Any],
        policy_id: str = "pol_default",
    ) -> Dict[str, Any]:
        """POST /v1/email/send (provider-key authenticated)."""

        payload = {
            "agent_id": agent_id,
            "policy_id": policy_id,
            "email": email,
        }
        r = self.client.post(
            "/v1/email/send",
            signed=False,
            headers=self._headers(),
            json=payload,
        )
        if r["status"] >= 400:
            raise RuntimeError(f"email_send failed: status={r['status']} body={r.get('json') or r.get('body')}")
        return r["json"]

    def provider_api_keys_list(self) -> Dict[str, Any]:
        raise NotImplementedError(
            "Listing/creating provider API keys requires dashboard session auth; not supported by ApiProvider."
        )

    def provider_api_keys_create(self, **_: Any) -> Dict[str, Any]:
        raise NotImplementedError(
            "Listing/creating provider API keys requires dashboard session auth; not supported by ApiProvider."
        )

    def provider_agents_upsert(
        self,
        *,
        external_agent_key: str,
        agent_id: str,
        display_name: Optional[str] = None,
        labels: Optional[list] = None,
        environment: Optional[str] = None,
        source: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "external_agent_key": external_agent_key,
            "agent_id": agent_id,
        }
        if display_name is not None:
            payload["display_name"] = display_name
        if labels is not None:
            payload["labels"] = labels
        if environment is not None:
            payload["environment"] = environment
        if source is not None:
            payload["source"] = source
        if status is not None:
            payload["status"] = status

        r = self.client.post(
            "/v1/provider/agents/upsert",
            signed=False,
            headers=self._headers(),
            json=payload,
        )
        if r["status"] >= 400:
            raise RuntimeError(
                f"provider_agents_upsert failed: status={r['status']} body={r.get('json') or r.get('body')}"
            )
        return r["json"]

    def provider_agents_list(
        self,
        *,
        environment: Optional[str] = None,
        status: Optional[str] = None,
        label: Optional[str] = None,
    ) -> Dict[str, Any]:
        query = self._encode_query(
            {
                "environment": environment,
                "status": status,
                "label": label,
            }
        )
        r = self.client.get(
            f"/v1/provider/agents{query}",
            signed=False,
            headers=self._headers(),
        )
        if r["status"] >= 400:
            raise RuntimeError(
                f"provider_agents_list failed: status={r['status']} body={r.get('json') or r.get('body')}"
            )
        return r["json"]

    def provider_audit_events(
        self,
        *,
        start_ms: Optional[int] = None,
        end_ms: Optional[int] = None,
        agent_id: Optional[str] = None,
        action: Optional[str] = None,
        decision: Optional[str] = None,
        trace_id: Optional[str] = None,
        limit: Optional[int] = None,
        cursor: Optional[int] = None,
    ) -> Dict[str, Any]:
        query = self._encode_query(
            {
                "start_ms": start_ms,
                "end_ms": end_ms,
                "agent_id": agent_id,
                "action": action,
                "decision": decision,
                "trace_id": trace_id,
                "limit": limit,
                "cursor": cursor,
            }
        )
        r = self.client.get(
            f"/v1/provider/audit/events{query}",
            signed=False,
            headers=self._headers(),
        )
        if r["status"] >= 400:
            raise RuntimeError(
                f"provider_audit_events failed: status={r['status']} body={r.get('json') or r.get('body')}"
            )
        return r["json"]

    def provider_audit_export(
        self,
        *,
        format: str = "json",
        filters: Optional[Dict[str, Any]] = None,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"format": format}
        if filters is not None:
            payload["filters"] = filters
        if limit is not None:
            payload["limit"] = limit

        r = self.client.post(
            "/v1/provider/audit/export",
            signed=False,
            headers=self._headers(),
            json=payload,
        )
        if r["status"] >= 400:
            raise RuntimeError(
                f"provider_audit_export failed: status={r['status']} body={r.get('json') or r.get('body')}"
            )
        return r["json"]

    def identity_credentials_mint(
        self,
        *,
        agent_id: str,
        provider: Optional[str] = None,
        audience: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
        one_time: Optional[bool] = None,
        scopes: Optional[list] = None,
        scope_hash: Optional[str] = None,
        policy_selector: Optional[Dict[str, Any]] = None,
        policy_id: Optional[str] = None,
        org_id: Optional[str] = None,
        destination: Optional[str] = None,
        destination_domain: Optional[str] = None,
        token_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"agent_id": agent_id}
        if provider is not None:
            payload["provider"] = provider
        if audience is not None:
            payload["audience"] = audience
        if ttl_seconds is not None:
            payload["ttl_seconds"] = ttl_seconds
        if one_time is not None:
            payload["one_time"] = one_time
        if scopes is not None:
            payload["scopes"] = scopes
        if scope_hash is not None:
            payload["scope_hash"] = scope_hash
        if policy_selector is not None:
            payload["policy_selector"] = policy_selector
        if policy_id is not None:
            payload["policy_id"] = policy_id
        if org_id is not None:
            payload["org_id"] = org_id
        if destination is not None:
            payload["destination"] = destination
        if destination_domain is not None:
            payload["destination_domain"] = destination_domain
        if token_type is not None:
            payload["token_type"] = token_type

        r = self.client.post(
            "/v1/identity/credentials/mint",
            signed=False,
            headers=self._headers(),
            json=payload,
        )
        if r["status"] >= 400:
            raise RuntimeError(
                f"identity_credentials_mint failed: status={r['status']} body={r.get('json') or r.get('body')}"
            )
        return r["json"]

    def identity_credentials_revoke(
        self,
        *,
        cred_id: Optional[str] = None,
        token: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {}
        if cred_id is not None:
            payload["cred_id"] = cred_id
        if token is not None:
            payload["token"] = token
        if reason is not None:
            payload["reason"] = reason

        r = self.client.post(
            "/v1/identity/credentials/revoke",
            signed=False,
            headers=self._headers(),
            json=payload,
        )
        if r["status"] >= 400:
            raise RuntimeError(
                f"identity_credentials_revoke failed: status={r['status']} body={r.get('json') or r.get('body')}"
            )
        return r["json"]

    def identity_credentials_revoke_by_agent(
        self,
        *,
        agent_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"agent_id": agent_id}
        if reason is not None:
            payload["reason"] = reason

        r = self.client.post(
            "/v1/identity/credentials/revoke-by-agent",
            signed=False,
            headers=self._headers(),
            json=payload,
        )
        if r["status"] >= 400:
            raise RuntimeError(
                f"identity_credentials_revoke_by_agent failed: status={r['status']} body={r.get('json') or r.get('body')}"
            )
        return r["json"]

    def identity_kill_switch_minting(self, *, paused: bool, reason: Optional[str] = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"paused": bool(paused)}
        if reason is not None:
            payload["reason"] = reason

        r = self.client.post(
            "/v1/identity/kill-switch/minting",
            signed=False,
            headers=self._headers(),
            json=payload,
        )
        if r["status"] >= 400:
            raise RuntimeError(
                f"identity_kill_switch_minting failed: status={r['status']} body={r.get('json') or r.get('body')}"
            )
        return r["json"]

    def identity_kill_switch_revoke_all(self, *, reason: Optional[str] = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {}
        if reason is not None:
            payload["reason"] = reason

        r = self.client.post(
            "/v1/identity/kill-switch/revoke-all",
            signed=False,
            headers=self._headers(),
            json=payload,
        )
        if r["status"] >= 400:
            raise RuntimeError(
                f"identity_kill_switch_revoke_all failed: status={r['status']} body={r.get('json') or r.get('body')}"
            )
        return r["json"]

    def identity_kill_switch_status(self) -> Dict[str, Any]:
        r = self.client.get(
            "/v1/identity/kill-switch/status",
            signed=False,
            headers=self._headers(),
        )
        if r["status"] >= 400:
            raise RuntimeError(
                f"identity_kill_switch_status failed: status={r['status']} body={r.get('json') or r.get('body')}"
            )
        return r["json"]

    def reputation_feedback(
        self,
        *,
        agent_id: str,
        verdict: str,
        evidence: Optional[Dict[str, Any]] = None,
        timestamp_ms: Optional[int] = None,
        nonce: Optional[str] = None,
    ) -> Dict[str, Any]:
        api_key = self._require_api_key()
        payload: Dict[str, Any] = {"agent_id": agent_id, "verdict": verdict}
        if evidence is not None:
            payload["evidence"] = evidence

        body_bytes = _json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        feedback_headers = build_feedback_headers(
            api_key=api_key,
            body=body_bytes,
            timestamp_ms=timestamp_ms,
            nonce=nonce,
        )
        headers = dict(self._headers())
        headers.update(feedback_headers)

        r = self.client.post(
            "/v1/reputation/feedback",
            signed=False,
            headers=headers,
            json=payload,
        )
        if r["status"] >= 400:
            raise RuntimeError(
                f"reputation_feedback failed: status={r['status']} body={r.get('json') or r.get('body')}"
            )
        return r["json"]
