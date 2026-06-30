"""Deterministic validator registry.

Each module exports a single `validate(**kwargs) -> dict` function.
All validators are pure, deterministic code — NO LLM calls.
"""
from __future__ import annotations

from src.core.validators import sqli, xss, ssrf, rce, lfi, idor

VALIDATORS = {
    "sqli": sqli.validate,
    "xss": xss.validate,
    "ssrf": ssrf.validate,
    "rce": rce.validate,
    "lfi": lfi.validate,
    "idor": idor.validate,
}


def validate_finding(vuln_type: str, **kwargs) -> dict:
    validator = VALIDATORS.get(vuln_type)
    if not validator:
        return {"confirmed": False, "type": "unknown", "evidence": f"No validator module for '{vuln_type}'"}
    return validator(**kwargs)


def list_validators() -> list[str]:
    return list(VALIDATORS.keys())
