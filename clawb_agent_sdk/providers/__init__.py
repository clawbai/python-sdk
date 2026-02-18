"""High-level provider helpers for Clawb.

These are thin wrappers around :class:`clawb_agent_sdk.client.ClawbClient`.

Design goal: keep the core SDK dependency-light while providing ergonomic,
endpoint-specific methods.
"""

from .api import ApiProvider
from .vault import VaultProvider

__all__ = [
    "ApiProvider",
    "VaultProvider",
]
