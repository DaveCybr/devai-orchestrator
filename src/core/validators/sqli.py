"""SQL Injection validator — error-based, time-based, boolean-based."""
from __future__ import annotations

import re

ERROR_PATTERNS = [
    (r"SQL syntax.*MySQL", "MySQL syntax error"),
    (r"Warning.*mysql_", "MySQL function warning"),
    (r"ORA-[0-9]{5}", "Oracle error code"),
    (r"PostgreSQL.*ERROR", "PostgreSQL error"),
    (r"SQLite.*Exception", "SQLite exception"),
    (r"Unclosed quotation mark", "Unclosed quote"),
    (r"Microsoft OLE DB.*SQL Server", "MSSQL driver error"),
    (r"driver.*in 'select'", "Driver error in SELECT"),
    (r"You have an error in your SQL syntax", "Generic SQL syntax error"),
    (r"Division by zero in SQL", "SQL divide-by-zero"),
    (r"Unknown column", "Unknown column in query"),
    (r"Table.*doesn't exist", "Missing table"),
]

TIME_MARKERS = ["sleep", "delay", "waitfor", "timing", "pg_sleep"]
BOOLEAN_MARKERS = ["true", "false", "1=1", "1=2"]


def validate(url: str, param: str = "", payload: str = "", evidence_text: str = "", **kwargs) -> dict:
    evidence_lower = evidence_text.lower()

    # 1. Error-based detection
    for pattern, desc in ERROR_PATTERNS:
        if re.search(pattern, evidence_text, re.IGNORECASE):
            return {"confirmed": True, "type": "error_based", "evidence": f"{desc}: {pattern}"}

    # 2. Time-based detection
    for marker in TIME_MARKERS:
        if marker in evidence_lower:
            return {"confirmed": True, "type": "time_based", "evidence": f"Timing marker: {marker}"}

    # 3. Boolean-based via response length difference (caller provides A/B comparison)
    if "_cond_true" in evidence_text and "_cond_false" in evidence_text:
        return {"confirmed": True, "type": "boolean", "evidence": "Conditional response difference detected"}

    # 4. Stacked query indicator
    if payload and ";" in payload and ";" in evidence_text:
        return {"confirmed": True, "type": "stacked", "evidence": "Stacked query leaked in response"}

    return {"confirmed": False, "type": "unconfirmed", "evidence": "No SQLi indicator found"}
