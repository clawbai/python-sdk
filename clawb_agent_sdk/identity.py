from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from .signing import sha256_hex, sign_canonical_b64


@dataclass
class ClawbIdentity:
    """High-level identity helper for signing outbound requests."""

    agent_id: str
    private_key_b64: str

    def sign_request(
        self,
        *,
        method: str,
        path: str,
        timestamp_ms: int,
        nonce: str,
        body: bytes = b"",
        body_sha256: Optional[str] = None,
    ) -> Dict[str, str]:
        if not self.agent_id or not self.private_key_b64:
            raise ValueError("agent_id and private_key_b64 are required")
        method = (method or "").strip().upper()
        path = (path or "").strip()
        if not method or not path:
            raise ValueError("method and path are required")
        if not nonce:
            raise ValueError("nonce is required")

        body_hash = body_sha256 or sha256_hex(body or b"")
        canonical = f"{method}\n{path}\n{int(timestamp_ms)}\n{nonce}\n{body_hash}".encode("utf-8")
        signature_b64 = sign_canonical_b64(self.private_key_b64, canonical)
        return {
            "agent_id": self.agent_id,
            "method": method,
            "path": path,
            "timestamp_ms": str(int(timestamp_ms)),
            "nonce": nonce,
            "body_sha256": body_hash,
            "signature_b64": signature_b64,
        }

