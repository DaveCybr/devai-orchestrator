"""LFI / Path Traversal validator — file content markers, error messages."""
from __future__ import annotations
import re

FILE_MARKERS = {
    "root:x:0:0": "/etc/passwd (Linux)",
    "root:$6$": "/etc/shadow hash",
    "root:$y$": "/etc/shadow yescrypt hash",
    "<?php": "PHP source code",
    "<?=": "PHP short tag",
    "<?xml": "XML document",
    "[boot loader]": "boot.ini (Windows)",
    "[fonts]": "win.ini (Windows)",
    "; for 16-bit app support": "system.ini (Windows)",
    "Windows Registry Editor": "Windows registry export",
    "#!/bin/": "Shell script",
    "127.0.0.1": "hosts file content",
    "localhost": "hosts file content",
    "daemon:x:1:1": "/etc/passwd continuation",
    "bin:x:2:2": "/etc/passwd continuation",
    "ssh-rsa": "SSH authorized_keys",
    "PRIVATE KEY": "Private key disclosure (CRITICAL)",
}

ERROR_MARKERS = [
    "failed to open stream: No such file",
    "failed to open stream: Permission denied",
    "include(",
    "require(",
    "file_get_contents(",
    "java.io.FileNotFoundException",
    "FileNotFoundException",
    "No such file or directory",
]


def validate(url: str, file_path: str = "", evidence_text: str = "", **kwargs) -> dict:
    if not evidence_text:
        return {"confirmed": False, "type": "unconfirmed", "evidence": "No response"}

    # 1. Known file content markers
    for marker, description in FILE_MARKERS.items():
        if marker in evidence_text:
            severity = "critical" if "PRIVATE KEY" in description else "high"
            return {"confirmed": True, "type": "file_read", "evidence": f"Read {description}", "severity": severity}

    # 2. Multiple passwd lines
    passwd_matches = re.findall(r'[a-zA-Z0-9_.-]+:x:\d+:\d+:', evidence_text)
    if len(passwd_matches) >= 3:
        return {"confirmed": True, "type": "file_read", "evidence": f"/etc/passwd ({len(passwd_matches)} users)"}

    # 3. Error shows file path
    for marker in ERROR_MARKERS:
        if marker in evidence_text:
            return {"confirmed": True, "type": "error_disclosure", "evidence": f"File path in error: {marker}"}

    # 4. PHP filter base64 indicator
    if len(evidence_text) > 200 and re.match(r'^[A-Za-z0-9+/=]+$', evidence_text.strip()[:50]):
        return {"confirmed": True, "type": "php_filter", "evidence": "Base64-encoded PHP source via filter"}

    return {"confirmed": False, "type": "unconfirmed", "evidence": "No known file content markers"}
