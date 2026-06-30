from __future__ import annotations

import os
import re
from typing import Any

from src.core.agent_base import BaseAgent


SAST_PATTERNS = {
    "sqli": [
        r"SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*=\s*['\"]?\s*\$_(GET|POST|REQUEST|COOKIE)",
        r"mysql_query\s*\(.*\$_(GET|POST|REQUEST)",
        r"->query\s*\(.*\$_(GET|POST|REQUEST)",
        r"db\.execute\(f\".*\{",
        r"cursor\.execute\(f\".*\{",
    ],
    "rce": [
        r"(eval|system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
        r"(eval|exec)\(.*request",
        r"subprocess\.(call|Popen|run)\(.*request",
        r"os\.system\(.*request",
    ],
    "xss": [
        r"(echo|print)\s*\$_(GET|POST|REQUEST)",
        r"innerHTML\s*=.*\$_(GET|POST|REQUEST)",
        r"dangerouslySetInnerHTML",
        r"response\.write\(.*\$_(GET|POST|REQUEST)",
    ],
    "lfi": [
        r"(include|require|include_once|require_once)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
        r"(open|read|file_get_contents)\(.*\$_(GET|POST|REQUEST)",
    ],
    "ssrf": [
        r"(curl_exec|file_get_contents|fopen|fsockopen)\(.*\$_(GET|POST|REQUEST)",
        r"requests\.(get|post)\(.*request",
        r"httpx\.(get|post|put|delete)\(.*request",
        r"urlopen\(.*request",
    ],
    "idor": [
        r"/api/.*/\d+",
        r"/(user|profile|account|order|invoice)/\d+",
        r"SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+(id|user_id)\s*=\s*\d+",
    ],
}


class SASTAgent(BaseAgent):
    name = "sast"
    description = "Static analysis: scan source code for vulnerability patterns"
    phase = "recon"

    async def run(self, params: dict[str, Any]) -> dict[str, Any]:
        target_dir = params.get("source_path", params.get("target", ""))
        if not os.path.isdir(target_dir):
            return {"status": "skip", "message": "No source code directory available"}

        self.log(f"Scanning source code in {target_dir}")

        findings = []
        for root, _, files in os.walk(target_dir):
            for fname in files:
                if not fname.endswith((".php", ".py", ".js", ".ts", ".java", ".rb", ".go", ".asp", ".aspx")):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue

                for vuln_type, patterns in SAST_PATTERNS.items():
                    for i, line in enumerate(content.splitlines(), 1):
                        for pattern in patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                relative = os.path.relpath(fpath, target_dir)
                                findings.append({
                                    "type": vuln_type,
                                    "file": relative,
                                    "line": i,
                                    "code": line.strip()[:120],
                                    "severity": "high" if vuln_type in ("rce", "sqli") else "medium",
                                })
                                # One finding per line is enough
                                break

        self.set_fact("sast_findings", findings, confidence=0.8)
        self.set_fact("sast_complete", True)

        if findings:
            self.log(f"Found {len(findings)} potential vulnerabilities")
            # Group by type for display
            by_type: dict[str, int] = {}
            for f in findings:
                by_type[f["type"]] = by_type.get(f["type"], 0) + 1
            for t, c in by_type.items():
                self.log(f"  {t}: {c}")

        return {"status": "success", "findings": findings}
