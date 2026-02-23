from __future__ import annotations

import dataclasses
import json
import time
import urllib.error
import urllib.request
import uuid
from collections import deque
from typing import Any, Callable, Deque, Dict, Mapping, Optional

from .signing import canonical_bytes, sign_canonical_b64


class EnforcementError(RuntimeError):
    """Base error for outbound enforcement decisions."""


class EnforcementUnavailableError(EnforcementError):
    """Raised when policy checks are unavailable and fail-closed is configured."""


class BlockedActionError(EnforcementError):
    """Raised when the policy decision denies an outbound action."""


class ChallengedActionError(EnforcementError):
    """Raised when the policy decision requires a challenge before action execution."""


@dataclasses.dataclass(frozen=True)
class EnforcementContext:
    """Stable action envelope for outbound tool/resource calls."""

    provider_id: str
    workspace_id: str
    agent_id: str
    action: str
    destination: str
    method: str
    resource_type: str
    trace_id: str
    request_id: str
    timestamp_ms: int
    metadata: Dict[str, Any]


@dataclasses.dataclass(frozen=True)
class EnforcementRequest:
    policy_id: str
    fail_open: bool
    context: EnforcementContext

    def to_check_payload(self) -> Dict[str, Any]:
        return {
            "agent_id": self.context.agent_id,
            "policy_id": self.policy_id,
            "action": self.context.action,
            "context": {
                "provider_id": self.context.provider_id,
                "workspace_id": self.context.workspace_id,
                "resource_type": self.context.resource_type,
                "destination": self.context.destination,
                "method": self.context.method,
                "trace_id": self.context.trace_id,
                "request_id": self.context.request_id,
                "ts_ms": self.context.timestamp_ms,
                **self.context.metadata,
            },
            "enforcement": {
                "fail_open": self.fail_open,
                "contract_version": "v1",
            },
        }

    def to_verify_payload(self) -> Dict[str, Any]:
        return {
            "agent_id": self.context.agent_id,
            "policy_id": self.policy_id,
            "context": {
                "provider_id": self.context.provider_id,
                "workspace_id": self.context.workspace_id,
                "trace_id": self.context.trace_id,
                "request_id": self.context.request_id,
            },
        }


@dataclasses.dataclass(frozen=True)
class CircuitBreakerConfig:
    failure_threshold: int = 5
    recovery_timeout_s: float = 30.0


@dataclasses.dataclass(frozen=True)
class RetryConfig:
    max_attempts: int = 3
    base_backoff_s: float = 0.05
    timeout_s: float = 2.0


@dataclasses.dataclass(frozen=True)
class EnforcementConfig:
    clawb_base_url: str
    provider_api_key: str
    profile: str
    policy_id: str = "pol_default"
    fail_open: bool = False
    retry: RetryConfig = dataclasses.field(default_factory=RetryConfig)
    circuit_breaker: CircuitBreakerConfig = dataclasses.field(default_factory=CircuitBreakerConfig)
    telemetry_signing_key_b64: Optional[str] = None

    @staticmethod
    def for_profile(
        profile: str,
        *,
        clawb_base_url: str,
        provider_api_key: str,
        policy_id: str = "pol_default",
        telemetry_signing_key_b64: Optional[str] = None,
    ) -> "EnforcementConfig":
        profile_name = profile.strip().lower()
        if profile_name == "dev":
            return EnforcementConfig(
                clawb_base_url=clawb_base_url,
                provider_api_key=provider_api_key,
                policy_id=policy_id,
                profile=profile_name,
                fail_open=True,
                retry=RetryConfig(max_attempts=2, base_backoff_s=0.02, timeout_s=1.0),
                telemetry_signing_key_b64=telemetry_signing_key_b64,
            )
        if profile_name == "staging":
            return EnforcementConfig(
                clawb_base_url=clawb_base_url,
                provider_api_key=provider_api_key,
                policy_id=policy_id,
                profile=profile_name,
                fail_open=True,
                retry=RetryConfig(max_attempts=3, base_backoff_s=0.05, timeout_s=1.5),
                telemetry_signing_key_b64=telemetry_signing_key_b64,
            )
        if profile_name == "prod":
            return EnforcementConfig(
                clawb_base_url=clawb_base_url,
                provider_api_key=provider_api_key,
                policy_id=policy_id,
                profile=profile_name,
                fail_open=False,
                retry=RetryConfig(max_attempts=4, base_backoff_s=0.08, timeout_s=2.0),
                telemetry_signing_key_b64=telemetry_signing_key_b64,
            )
        raise ValueError("profile must be one of: dev, staging, prod")


class OutboundEnforcer:
    def __init__(
        self,
        config: EnforcementConfig,
        *,
        request_fn: Optional[Callable[..., Dict[str, Any]]] = None,
        now_fn: Callable[[], float] = time.time,
        sleep_fn: Callable[[float], None] = time.sleep,
    ):
        self.config = config
        self._request_fn = request_fn or self._default_request_fn
        self._now_fn = now_fn
        self._sleep_fn = sleep_fn
        self._failure_timestamps: Deque[float] = deque(maxlen=max(config.circuit_breaker.failure_threshold * 2, 10))
        self._circuit_open_until: float = 0.0

    def build_context(
        self,
        *,
        provider_id: str,
        workspace_id: str,
        agent_id: str,
        action: str,
        destination: str,
        method: str,
        resource_type: str,
        trace_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> EnforcementContext:
        now_ms = int(self._now_fn() * 1000)
        return EnforcementContext(
            provider_id=provider_id,
            workspace_id=workspace_id,
            agent_id=agent_id,
            action=action,
            destination=destination,
            method=method.upper(),
            resource_type=resource_type,
            trace_id=trace_id or f"trc_{uuid.uuid4().hex}",
            request_id=request_id or f"req_{uuid.uuid4().hex}",
            timestamp_ms=now_ms,
            metadata=dict(metadata or {}),
        )

    def enforce(self, request: EnforcementRequest) -> Dict[str, Any]:
        check_payload = request.to_check_payload()
        verify_payload = request.to_verify_payload()

        if self._is_circuit_open():
            return self._handle_unavailable(request, "circuit_open")

        try:
            verify_result = self._call_with_retry("/v1/verify", verify_payload)
            check_result = self._call_with_retry("/v1/check", check_payload)
            self._record_success()
        except Exception as exc:
            self._record_failure()
            return self._handle_unavailable(request, str(exc))

        decision = (check_result.get("decision") or verify_result.get("decision") or "deny").lower()
        trace = check_result.get("trace") if isinstance(check_result.get("trace"), dict) else {}
        trace_id = trace.get("trace_id") or request.context.trace_id
        telemetry = self._build_signed_telemetry(
            request=request,
            decision=decision,
            trace_id=trace_id,
            reason_codes=check_result.get("reason_codes") or check_result.get("reasons") or [],
            challenge=check_result.get("challenge"),
        )

        result = {
            "decision": decision,
            "trace_id": trace_id,
            "check": check_result,
            "verify": verify_result,
            "telemetry": telemetry,
        }

        if decision == "allow":
            return result
        if decision == "challenge":
            raise ChallengedActionError(json.dumps(result, separators=(",", ":"), sort_keys=True))
        raise BlockedActionError(json.dumps(result, separators=(",", ":"), sort_keys=True))

    def _call_with_retry(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        last_error: Optional[Exception] = None
        for attempt in range(1, self.config.retry.max_attempts + 1):
            try:
                res = self._request_fn(
                    path,
                    payload,
                    timeout=self.config.retry.timeout_s,
                    provider_api_key=self.config.provider_api_key,
                )
                return res
            except Exception as exc:  # noqa: PERF203
                last_error = exc
                if attempt >= self.config.retry.max_attempts:
                    break
                self._sleep_fn(self.config.retry.base_backoff_s * attempt)
        raise RuntimeError(f"request_failed path={path} err={last_error}")

    def _is_circuit_open(self) -> bool:
        now = self._now_fn()
        if now < self._circuit_open_until:
            return True
        if self._circuit_open_until:
            self._circuit_open_until = 0.0
        return False

    def _record_success(self):
        self._failure_timestamps.clear()

    def _record_failure(self):
        now = self._now_fn()
        self._failure_timestamps.append(now)
        if len(self._failure_timestamps) >= self.config.circuit_breaker.failure_threshold:
            recent = list(self._failure_timestamps)[-self.config.circuit_breaker.failure_threshold :]
            if recent[-1] - recent[0] <= self.config.circuit_breaker.recovery_timeout_s:
                self._circuit_open_until = now + self.config.circuit_breaker.recovery_timeout_s

    def _handle_unavailable(self, request: EnforcementRequest, reason: str) -> Dict[str, Any]:
        if request.fail_open:
            return {
                "decision": "allow",
                "trace_id": request.context.trace_id,
                "degraded": True,
                "reason": reason,
                "telemetry": self._build_signed_telemetry(
                    request=request,
                    decision="allow",
                    trace_id=request.context.trace_id,
                    reason_codes=["policy_service_unavailable"],
                    challenge=None,
                ),
            }
        raise EnforcementUnavailableError(reason)

    def _build_signed_telemetry(
        self,
        *,
        request: EnforcementRequest,
        decision: str,
        trace_id: str,
        reason_codes: Any,
        challenge: Any,
    ) -> Dict[str, Any]:
        payload = {
            "version": "v1",
            "profile": self.config.profile,
            "decision": decision,
            "trace_id": trace_id,
            "policy_id": request.policy_id,
            "action": request.context.action,
            "destination": request.context.destination,
            "resource_type": request.context.resource_type,
            "reason_codes": reason_codes,
            "challenge": challenge,
            "ts_ms": int(self._now_fn() * 1000),
        }
        out = {"payload": payload}
        if self.config.telemetry_signing_key_b64:
            out["signature"] = sign_canonical_b64(
                self.config.telemetry_signing_key_b64,
                canonical_bytes(payload),
            )
            out["algorithm"] = "ed25519"
        return out

    def _default_request_fn(
        self,
        path: str,
        payload: Dict[str, Any],
        *,
        timeout: float,
        provider_api_key: str,
    ) -> Dict[str, Any]:
        base_url = self.config.clawb_base_url.rstrip("/")
        url = f"{base_url}{path}"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-CLAWB-API-KEY": provider_api_key,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read() or b"{}"
                return json.loads(body.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read() or b"{}"
            raise RuntimeError(f"http_error status={exc.code} body={body.decode('utf-8', errors='ignore')}")
