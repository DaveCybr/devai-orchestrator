"""XSS validator — reflected, stored, DOM-based, context-aware."""
from __future__ import annotations

import html
import re


def validate(url: str, param: str = "", payload: str = "", evidence_text: str = "", **kwargs) -> dict:
    if not payload or not evidence_text:
        return {"confirmed": False, "type": "unconfirmed", "evidence": "Missing payload or evidence"}

    # 1. Check raw payload reflection
    if payload in evidence_text:
        # Check encoding context
        if html.escape(payload) in evidence_text and payload not in evidence_text:
            return {"confirmed": False, "type": "encoded", "evidence": "Payload HTML-encoded (&lt; &gt;)"}

        # Check if reflected inside script context
        if f"</script>{payload}" in evidence_text or f"{payload}</script>" in evidence_text:
            return {"confirmed": True, "type": "script_context", "evidence": "Payload reflected inside <script>"}

        return {"confirmed": True, "type": "reflected", "evidence": f"Payload found in response"}

    # 2. Stored XSS — payload appears on a different page
    if "alert(" in evidence_text and ("xss" in evidence_text.lower() or "cookie" in evidence_text.lower()):
        return {"confirmed": True, "type": "stored", "evidence": "alert/cookie reference in stored response"}

    # 3. DOM-based — URL fragment in response
    if "#" in payload:
        fragment = payload.split("#")[1][:30]
        if fragment and fragment in evidence_text:
            return {"confirmed": True, "type": "dom", "evidence": f"Fragment found in response: #{fragment}"}

    # 4. Attribute context — check for quote break
    if '"' in payload and payload.split('"')[0] in evidence_text:
        return {"confirmed": True, "type": "attribute_break", "evidence": "Quote break detected"}
    if "'" in payload and payload.split("'")[0] in evidence_text:
        return {"confirmed": True, "type": "attribute_break", "evidence": "Single-quote break detected"}

    return {"confirmed": False, "type": "unconfirmed", "evidence": "Payload not reflected in response"}
