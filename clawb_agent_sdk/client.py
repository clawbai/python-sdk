import base64
import json as _json
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from .signing import build_signed_headers, generate_ed25519_keypair_b64, sign_canonical_b64


class ClawbClient:
    """Minimal Clawb API client.

    Dependency-light: uses stdlib `urllib` (no `requests`).
    """

    def __init__(
        self,
        *,
        base_url: str,
        agent_id: Optional[str] = None,
        private_key_b64: Optional[str] = None,
        timeout: float = 20.0,
    ):
        self.base_url = (base_url or "").rstrip("/")
        if not self.base_url:
            raise ValueError("base_url is required")

        self.agent_id = agent_id
        self.private_key_b64 = private_key_b64
        self.timeout = timeout

    # ---- key helpers
    @staticmethod
    def generate_ed25519_keypair_b64():
        return generate_ed25519_keypair_b64()

    # ---- low-level request helpers
    def _url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return self.base_url + path

    def _signed_headers(self, method: str, path: str, body: bytes) -> Dict[str, str]:
        if not self.agent_id or not self.private_key_b64:
            raise ValueError("agent_id and private_key_b64 are required for signed requests")
        return build_signed_headers(
            agent_id=self.agent_id,
            private_key_b64=self.private_key_b64,
            method=method,
            path=path,
            body=body,
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        signed: bool = True,
        headers: Optional[Dict[str, str]] = None,
        json: Any = None,
        data: Any = None,
    ) -> Dict[str, Any]:
        headers = dict(headers or {})

        if data is not None and json is not None:
            raise ValueError("Pass only one of json or data")

        body_bytes = b""
        if json is not None:
            body_bytes = _json.dumps(json, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
            data = body_bytes
        elif data is not None:
            if isinstance(data, (bytes, bytearray)):
                body_bytes = bytes(data)
            elif isinstance(data, str):
                body_bytes = data.encode("utf-8")
            else:
                raise ValueError("data must be bytes or str when signing")
            data = body_bytes

        if signed:
            headers.update(self._signed_headers(method, path, body_bytes))

        req = urllib.request.Request(
            self._url(path),
            data=data,
            method=method.upper(),
            headers=headers,
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read() or b""
                ct = resp.headers.get("Content-Type", "")
                out_json = None
                if "application/json" in ct and raw:
                    out_json = _json.loads(raw.decode("utf-8"))
                return {"status": resp.status, "headers": dict(resp.headers), "body": raw, "json": out_json}
        except urllib.error.HTTPError as e:
            raw = e.read() or b""
            out_json = None
            try:
                out_json = _json.loads(raw.decode("utf-8")) if raw else None
            except Exception:
                out_json = None
            return {"status": int(getattr(e, "code", 0) or 0), "headers": dict(getattr(e, "headers", {}) or {}), "body": raw, "json": out_json}

    def get(self, path: str, **kw) -> Dict[str, Any]:
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw) -> Dict[str, Any]:
        return self.request("POST", path, **kw)

    # ---- v1 convenience
    def register(self, *, name: str, public_key_b64: str, key_type: str = "ed25519", metadata: Optional[dict] = None):
        payload = {
            "name": name,
            "public_key": public_key_b64,
            "key_type": key_type,
            "metadata": metadata or {},
        }
        r = self.post("/v1/agents/register", signed=False, json=payload)
        if r["status"] >= 400:
            raise RuntimeError(f"register failed: status={r['status']} body={r.get('json') or r.get('body')}")
        return r["json"]

    def attest(self, *, challenge_id: str, challenge_b64: str):
        if not self.agent_id or not self.private_key_b64:
            raise ValueError("agent_id and private_key_b64 required")

        challenge_bytes = base64.b64decode(challenge_b64)
        sig_b64 = sign_canonical_b64(self.private_key_b64, challenge_bytes)

        payload = {
            "agent_id": self.agent_id,
            "challenge_id": challenge_id,
            "signature": sig_b64,
        }
        r = self.post("/v1/agents/attest", signed=False, json=payload)
        if r["status"] >= 400:
            raise RuntimeError(f"attest failed: status={r['status']} body={r.get('json') or r.get('body')}")
        return r["json"]

    def request_claim_code(self):
        """Request a one-time claim code for this agent (signed).

        Returns JSON containing: claim_code, claim_url, expires_at.
        """
        if not self.agent_id or not self.private_key_b64:
            raise ValueError("agent_id and private_key_b64 required")

        r = self.post("/v1/agents/claim-code", signed=True, json={})
        if r["status"] >= 400:
            raise RuntimeError(
                f"claim-code failed: status={r['status']} body={r.get('json') or r.get('body')}"
            )
        return r["json"]

    def check(self, *, agent_id: str, policy_id: str = "pol_default"):
        """Ask Clawb for a policy decision for an agent (NOT signed).

        This endpoint is intentionally unsigned so a relying service can call it server-to-server
        while it verifies the agent signature on the *original inbound request*.

        Returns JSON: {decision: allow|challenge|deny, reasons: [...], ...}
        """
        payload = {"agent_id": agent_id, "policy_id": policy_id}
        r = self.post("/v1/check", signed=False, json=payload)
        if r["status"] >= 400:
            raise RuntimeError(f"check failed: status={r['status']} body={r.get('json') or r.get('body')}")
        return r["json"]
