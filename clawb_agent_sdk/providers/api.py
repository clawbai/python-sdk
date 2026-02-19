from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Optional

from ..client import ClawbClient


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
    api_key: str

    def _headers(self) -> Dict[str, str]:
        k = (self.api_key or "").strip()
        if not k:
            raise ValueError("api_key is required")
        # Backend accepts X-Clawb-Api-Key / Authorization as well, but we standardize on this.
        return {"X-Clawb-Api-Key": k}

    @staticmethod
    def sha256_hex(body: bytes) -> str:
        return hashlib.sha256(body or b"").hexdigest()

    @staticmethod
    def sha256_b64(body: bytes) -> str:
        return base64.b64encode(hashlib.sha256(body or b"").digest()).decode("utf-8")

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
