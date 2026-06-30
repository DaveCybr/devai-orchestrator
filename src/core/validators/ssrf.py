"""SSRF validator — OOB callback, content-based, error-based."""
from __future__ import annotations

import re

CLOUD_METADATA = [
    ("ami-id", "AWS metadata"),
    ("instance-id", "AWS metadata"),
    ("public-keys", "AWS metadata"),
    ("security-credentials", "AWS IAM role"),
    ("project/", "GCP metadata"),
    ("computeMetadata", "GCP metadata"),
    ("vm/", "Azure metadata"),
]

INTERNAL_MARKERS = [
    "root:x:0:0",
    "404 Not Found",
    "nginx",
    "Apache",
    "IIS",
    "SSH-2.",
    "redis",
    "ok",
    "PING",
]


def validate(url: str, callback_url: str = "", evidence_text: str = "", **kwargs) -> dict:
    if not evidence_text:
        return {"confirmed": False, "type": "unconfirmed", "evidence": "No response to validate"}

    # 1. OOB callback confirmation
    if callback_url and callback_url in evidence_text:
        return {"confirmed": True, "type": "oob_callback", "evidence": f"Callback URL reflected: {callback_url}"}

    # 2. Cloud metadata service response
    for marker, desc in CLOUD_METADATA:
        if marker in evidence_text:
            return {"confirmed": True, "type": "cloud_metadata", "evidence": f"Cloud metadata: {desc}"}

    # 3. Internal service banner
    banners_found = [m for m in INTERNAL_MARKERS if m in evidence_text]
    if len(banners_found) >= 2:
        return {"confirmed": True, "type": "internal_banner", "evidence": f"Internal service banners: {banners_found}"}

    # 4. Protocol smuggling — file://, gopher:// content
    if "file://" in url and len(evidence_text) > 100:
        return {"confirmed": True, "type": "file_read", "evidence": f"File content via SSRF ({len(evidence_text)} bytes)"}

    # 5. Collaborator/burp echo
    if "collaborator" in evidence_text.lower():
        return {"confirmed": True, "type": "oob_echo", "evidence": "Collaborator interaction echoed"}

    return {"confirmed": False, "type": "unconfirmed", "evidence": "No SSRF evidence found"}
