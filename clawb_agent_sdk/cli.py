from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

from .client import ClawbClient


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--base-url",
        default="https://api.clawb.ai/api",
        help=(
            "Clawb API root URL, including /api "
            "(default: https://api.clawb.ai/api)"
        ),
    )


def cmd_bootstrap(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="clawb-agent bootstrap",
        description=(
            "Register → attest → request a claim code, then print copy/paste instructions.\n\n"
            "This is an agent-first flow: it generates an Ed25519 keypair locally and never sends the private key."
        ),
    )
    _add_common(ap)
    ap.add_argument("--name", required=True, help="Agent name to register")
    ap.add_argument(
        "--print-json",
        action="store_true",
        help="Print machine-readable JSON output to stdout (still prints warnings to stderr)",
    )

    args = ap.parse_args(argv)

    # 1) keys
    priv_b64, pub_b64 = ClawbClient.generate_ed25519_keypair_b64()

    # 2) register
    client = ClawbClient(base_url=args.base_url)
    reg = client.register(name=args.name, public_key_b64=pub_b64, metadata={"source": "cli"})

    # 3) attest
    agent_id = reg["agent_id"]
    client = ClawbClient(base_url=args.base_url, agent_id=agent_id, private_key_b64=priv_b64)
    client.attest(challenge_id=reg["challenge_id"], challenge_b64=reg["challenge"])  # type: ignore[arg-type]

    # 4) claim code
    claim = client.request_claim_code()

    out = {
        "agent_id": agent_id,
        "private_key_b64": priv_b64,
        "public_key_b64": pub_b64,
        "claim": claim,
    }

    if args.print_json:
        sys.stdout.write(json.dumps(out, indent=2, sort_keys=True) + "\n")
        return 0

    claim_url = (claim or {}).get("claim_url")
    claim_code = (claim or {}).get("claim_code")

    sys.stdout.write("\n")
    sys.stdout.write("✅ Agent bootstrapped\n")
    sys.stdout.write("\n")
    sys.stdout.write(f"agent_id: {agent_id}\n")
    sys.stdout.write(f"public_key_b64: {pub_b64}\n")
    sys.stdout.write(f"private_key_b64: {priv_b64}\n")
    sys.stdout.write("\n")

    sys.stdout.write("Next steps\n")
    sys.stdout.write("1) Export credentials (for your agent runtime):\n")
    sys.stdout.write("\n")
    sys.stdout.write(f"  export CLAWB_BASE_URL=\"{args.base_url.rstrip('/')}\"\n")
    sys.stdout.write(f"  export CLAWB_AGENT_ID=\"{agent_id}\"\n")
    sys.stdout.write(f"  export CLAWB_PRIVATE_KEY_B64=\"{priv_b64}\"\n")
    sys.stdout.write("\n")

    sys.stdout.write("2) Claim the agent in the dashboard:\n")
    if claim_url:
        sys.stdout.write(f"  Open: {claim_url}\n")
    elif claim_code:
        sys.stdout.write(f"  Claim code: {claim_code}\n")
    else:
        sys.stdout.write("  (No claim URL returned)\n")

    sys.stdout.write("\n")
    sys.stdout.write("Security note: store your private key securely; Clawb will never show it again.\n")
    return 0


def cmd_heartbeat(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="clawb-agent heartbeat",
        description="Post a lightweight signed telemetry heartbeat to Clawb.",
    )
    _add_common(ap)
    ap.add_argument("--agent-id", default=None, help="Agent id (defaults to $CLAWB_AGENT_ID)")
    ap.add_argument(
        "--private-key-b64",
        default=None,
        help="Ed25519 private key (base64). Defaults to $CLAWB_PRIVATE_KEY_B64",
    )
    ap.add_argument(
        "--status",
        default="ok",
        help="Heartbeat status (ok|error). Default: ok",
    )
    ap.add_argument("--latency-ms", type=int, default=None, help="Optional latency in ms")
    ap.add_argument("--print-json", action="store_true", help="Print JSON response")

    args = ap.parse_args(argv)

    agent_id = (args.agent_id or (os.environ.get("CLAWB_AGENT_ID") or "")).strip()
    priv_b64 = (args.private_key_b64 or (os.environ.get("CLAWB_PRIVATE_KEY_B64") or "")).strip()

    if not agent_id:
        raise SystemExit("Missing --agent-id (or set $CLAWB_AGENT_ID)")
    if not priv_b64:
        raise SystemExit("Missing --private-key-b64 (or set $CLAWB_PRIVATE_KEY_B64)")

    client = ClawbClient(base_url=args.base_url, agent_id=agent_id, private_key_b64=priv_b64)
    payload = {"agent_id": agent_id, "status": args.status}
    if args.latency_ms is not None:
        payload["latency_ms"] = int(args.latency_ms)

    resp = client.post("/v1/telemetry/heartbeat", json=payload)
    if args.print_json:
        sys.stdout.write(json.dumps(resp.get("json"), indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write("✅ Heartbeat sent\n")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    ap = argparse.ArgumentParser(prog="clawb-agent")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_boot = sub.add_parser("bootstrap", help="Register → attest → claim-code and print instructions")
    p_boot.set_defaults(_fn=cmd_bootstrap)

    p_hb = sub.add_parser("heartbeat", help="Send a signed telemetry heartbeat")
    p_hb.set_defaults(_fn=cmd_heartbeat)

    args, rest = ap.parse_known_args(argv)
    return int(args._fn(rest))


if __name__ == "__main__":
    raise SystemExit(main())
