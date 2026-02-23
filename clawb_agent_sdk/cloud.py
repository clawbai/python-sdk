from __future__ import annotations

import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any, Dict, Optional


def get_aws_credentials(
    *,
    clawb_jwt: str,
    role_arn: str,
    role_session_name: str,
    duration_seconds: int = 900,
    region: Optional[str] = None,
    timeout: float = 15.0,
) -> Dict[str, Any]:
    """Exchange a Clawb JWT for temporary AWS credentials via STS.

    Uses AssumeRoleWithWebIdentity.
    """
    token = (clawb_jwt or "").strip()
    role = (role_arn or "").strip()
    session = (role_session_name or "").strip()
    if not token:
        raise ValueError("clawb_jwt is required")
    if not role:
        raise ValueError("role_arn is required")
    if not session:
        raise ValueError("role_session_name is required")

    dur = int(duration_seconds)
    if dur <= 0:
        raise ValueError("duration_seconds must be > 0")

    host = "sts.amazonaws.com" if not region else f"sts.{region}.amazonaws.com"
    endpoint = f"https://{host}/"
    query = urllib.parse.urlencode(
        {
            "Action": "AssumeRoleWithWebIdentity",
            "Version": "2011-06-15",
            "RoleArn": role,
            "RoleSessionName": session,
            "WebIdentityToken": token,
            "DurationSeconds": dur,
        }
    )
    req = urllib.request.Request(f"{endpoint}?{query}", method="GET")

    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read() or b""

    root = ET.fromstring(raw.decode("utf-8"))
    namespaces = {}
    prefix = ""
    if root.tag.startswith("{") and "}" in root.tag:
        uri = root.tag.split("}", 1)[0][1:]
        namespaces = {"ns": uri}
        prefix = "ns:"

    def _find(path: str) -> str:
        node = root.find(path, namespaces=namespaces)
        return (node.text or "").strip() if node is not None else ""

    access_key_id = _find(f".//{prefix}Credentials/{prefix}AccessKeyId")
    secret_access_key = _find(f".//{prefix}Credentials/{prefix}SecretAccessKey")
    session_token = _find(f".//{prefix}Credentials/{prefix}SessionToken")
    expiration = _find(f".//{prefix}Credentials/{prefix}Expiration")
    assumed_role_arn = _find(f".//{prefix}AssumedRoleUser/{prefix}Arn")

    if not access_key_id or not secret_access_key or not session_token:
        raise RuntimeError("AssumeRoleWithWebIdentity response missing credentials")

    return {
        "access_key_id": access_key_id,
        "secret_access_key": secret_access_key,
        "session_token": session_token,
        "expiration": expiration,
        "assumed_role_arn": assumed_role_arn,
    }
