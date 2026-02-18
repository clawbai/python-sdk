from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from ..client import ClawbClient


@dataclass
class ApiProvider:
    """Provider-key authenticated endpoints (for relying services).

    Notes:
      - /v1/check is intentionally unsigned and does NOT use an API key.
      - Some provider endpoints (ex: /v1/email/send) use an API key via header
        `X-CLAWB-API-KEY`.

    This helper does not manage dashboard-session endpoints such as
    /v1/provider/api-keys.
    """

    client: ClawbClient
    api_key: str

    def _headers(self) -> Dict[str, str]:
        k = (self.api_key or "").strip()
        if not k:
            raise ValueError("api_key is required")
        return {"X-CLAWB-API-KEY": k}

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
