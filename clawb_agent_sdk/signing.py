import base64
import hashlib
import hmac
import time
import uuid
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def sha256_hex(body: bytes) -> str:
    return hashlib.sha256(body or b"").hexdigest()


def canonical_bytes(method: str, path: str, timestamp_ms: int, nonce: str, body: bytes) -> bytes:
    # Must match api/middleware.py
    canon = f"{method.upper()}\n{path}\n{int(timestamp_ms)}\n{nonce}\n{sha256_hex(body)}"
    return canon.encode("utf-8")


def _load_ed25519_private_key(private_key_b64: str) -> ed25519.Ed25519PrivateKey:
    raw = base64.b64decode(private_key_b64)
    if len(raw) == 32:
        return ed25519.Ed25519PrivateKey.from_private_bytes(raw)

    # Allow PEM as a convenience (base64-encoded or raw string), but keep primary format raw32 b64.
    try:
        return serialization.load_pem_private_key(raw, password=None)
    except Exception as e:
        raise ValueError("Invalid private key: expected base64 of 32 raw bytes (or PEM bytes)") from e


def generate_ed25519_keypair_b64() -> Tuple[str, str]:
    """Return (private_key_b64, public_key_b64) as base64-encoded raw bytes.

    - private: 32 bytes seed
    - public: 32 bytes
    """
    priv = ed25519.Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(priv_raw).decode("utf-8"), base64.b64encode(pub_raw).decode("utf-8")


def sign_canonical_b64(private_key_b64: str, canonical: bytes) -> str:
    priv = _load_ed25519_private_key(private_key_b64)
    sig = priv.sign(canonical)
    return base64.b64encode(sig).decode("utf-8")


def new_nonce() -> str:
    # Nonce is treated as an opaque string by server.
    return uuid.uuid4().hex


@dataclass
class SignedHeaders:
    agent_id: str
    timestamp_ms: int
    nonce: str
    signature_b64: str

    def as_dict(self) -> Dict[str, str]:
        return {
            "X-Clawb-Agent-Id": self.agent_id,
            "X-Clawb-Timestamp": str(int(self.timestamp_ms)),
            "X-Clawb-Nonce": self.nonce,
            "X-Clawb-Signature": self.signature_b64,
        }


def build_signed_headers(
    *,
    agent_id: str,
    private_key_b64: str,
    method: str,
    path: str,
    body: bytes = b"",
    timestamp_ms: Optional[int] = None,
    nonce: Optional[str] = None,
) -> Dict[str, str]:
    ts = int(timestamp_ms if timestamp_ms is not None else time.time() * 1000)
    n = nonce or new_nonce()
    canonical = canonical_bytes(method=method, path=path, timestamp_ms=ts, nonce=n, body=body)
    sig_b64 = sign_canonical_b64(private_key_b64, canonical)
    return SignedHeaders(agent_id=agent_id, timestamp_ms=ts, nonce=n, signature_b64=sig_b64).as_dict()


def build_feedback_headers(
    *,
    api_key: str,
    body: bytes = b"",
    timestamp_ms: Optional[int] = None,
    nonce: Optional[str] = None,
) -> Dict[str, str]:
    """Build headers for provider reputation feedback HMAC auth.

    Server uses HMAC-SHA256 with key=sha256(api_key) (hex -> bytes).
    Message format: "{ts}\n{nonce}\n{sha256(body)}"
    """
    ts = int(timestamp_ms if timestamp_ms is not None else time.time() * 1000)
    n = nonce or new_nonce()
    body_hash = sha256_hex(body)
    key_hex = hashlib.sha256((api_key or "").encode("utf-8")).hexdigest()
    key_bytes = bytes.fromhex(key_hex)
    msg = f"{ts}\n{n}\n{body_hash}".encode("utf-8")
    sig_b64 = base64.b64encode(hmac.new(key_bytes, msg, hashlib.sha256).digest()).decode("utf-8")
    return {
        "X-Clawb-Feedback-Timestamp": str(ts),
        "X-Clawb-Feedback-Nonce": n,
        "X-Clawb-Feedback-Signature": sig_b64,
    }
