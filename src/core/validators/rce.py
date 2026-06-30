"""RCE validator — command output, error disclosure, blind OOB."""
from __future__ import annotations

import re

OUTPUT_MARKERS = [
    ("uid=", "Command output: uid="),
    ("gid=", "Command output: gid="),
    ("uid=", "Command output: uid/gid"),
    ("www-data", "Common web user"),
    ("root", "Root user"),
    ("bin/bash", "Shell path"),
    ("/bin/", "Filesystem path"),
    ("drwxr", "Directory listing"),
    ("-rwxr", "File permissions"),
    ("total ", "ls output"),
    ("Linux ", "uname output"),
    ("Microsoft Windows", "Windows system info"),
]

ERROR_DISCLOSURE = [
    "Warning: exec(",
    "Warning: system(",
    "Warning: shell_exec(",
    "Warning: passthru(",
    "Warning: popen(",
    "Warning: proc_open(",
    "Fatal error: Uncaught Exception: shell_exec",
    "SyntaxError: Unexpected eval",
]


def validate(url: str, command: str = "", evidence_text: str = "", **kwargs) -> dict:
    if not evidence_text:
        return {"confirmed": False, "type": "unconfirmed", "evidence": "No response"}

    # 1. Command output visible in response
    for marker, desc in OUTPUT_MARKERS:
        if marker in evidence_text:
            return {"confirmed": True, "type": "output_visible", "evidence": f"{desc}: '{marker}' in response"}

    # 2. RCE function disclosure via error
    for marker in ERROR_DISCLOSURE:
        if marker in evidence_text:
            return {"confirmed": True, "type": "error_disclosure", "evidence": f"RCE function in error: {marker}"}

    # 3. File write detection
    if "written" in evidence_text.lower() and "bytes" in evidence_text.lower():
        return {"confirmed": True, "type": "file_write", "evidence": "File write confirmed"}

    return {"confirmed": False, "type": "unconfirmed", "evidence": "No RCE output visible"}
