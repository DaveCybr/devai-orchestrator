from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


CHAIN_PATTERNS = [
    {
        "name": "LFI -> RCE (log poisoning)",
        "chain": ["lfi", "rce"],
        "description": "LFI untuk baca log server -> inject PHP ke log via User-Agent -> LFI lagi ke log -> RCE",
        "conditions": [
            "LFI confirmed bisa baca file",
            "Log file accessible via LFI (/var/log/apache/access.log, /var/log/nginx/access.log)",
            "User-Agent atau header lain tercatat di log",
        ],
        "impact_boost": 2,
    },
    {
        "name": "SQLi -> RCE (into outfile)",
        "chain": ["sqli", "rce"],
        "description": "SQL injection + INTO OUTFILE -> tulis webshell ke webroot",
        "conditions": [
            "SQLi confirmed (error/union-based)",
            "MySQL user punya FILE privilege",
            "Webroot path diketahui atau bisa ditebak",
        ],
        "impact_boost": 2,
    },
    {
        "name": "File Upload -> RCE",
        "chain": ["file_upload", "rce"],
        "description": "Upload file berbahaya (PHP/JSP/ASP) -> akses langsung -> eksekusi kode",
        "conditions": [
            "Upload endpoint ditemukan",
            "File dapat diakses via URL langsung",
            "Ekstensi tidak divalidasi strict",
        ],
        "impact_boost": 2,
    },
    {
        "name": "SSRF -> Internal Service PWN",
        "chain": ["ssrf", "idor"],
        "description": "SSRF ke internal service (Redis, ES, DB) -> baca/modifikasi data internal",
        "conditions": [
            "SSRF confirmed ke internal",
            "Internal service listening (6379, 9200, 3306, dll)",
            "Service tidak pake auth",
        ],
        "impact_boost": 2,
    },
    {
        "name": "IDOR -> Account Takeover",
        "chain": ["idor", "xss"],
        "description": "IDOR baca data user lain -> inject XSS di profile/field -> ATO",
        "conditions": [
            "IDOR confirmed bisa baca data user lain",
            "Data user bisa dimodifikasi via profile update",
            "XSS bisa di inject di field yang dirender",
        ],
        "impact_boost": 2,
    },
    {
        "name": "SSRF -> Cloud Metadata -> IAM Credentials",
        "chain": ["ssrf", "idor"],
        "description": "SSRF ke metadata cloud -> dapat IAM credentials -> akses cloud resources",
        "conditions": [
            "SSRF confirmed",
            "Target di cloud (AWS/GCP/Azure)",
            "Metadata endpoint accessible (169.254.169.254)",
        ],
        "impact_boost": 3,
    },
]


class ChainPlanner:
    def __init__(self):
        self.chains = CHAIN_PATTERNS

    def find_chains(self, confirmed_findings: list[dict]) -> list[dict]:
        """Find which chain patterns match the confirmed findings."""
        matched_chains = []
        finding_types = [f.get("vuln_type", "") for f in confirmed_findings]
        finding_titles = [f.get("title", "").lower() for f in confirmed_findings]

        for pattern in self.chains:
            required = pattern["chain"]
            if all(vt in finding_types for vt in required):
                boost = pattern.get("impact_boost", 1)
                matched_chains.append({
                    "name": pattern["name"],
                    "description": pattern["description"],
                    "conditions": pattern["conditions"],
                    "impact_boost": boost,
                    "matched_findings": [
                        f for f in confirmed_findings if f.get("vuln_type") in required
                    ],
                    "complete": True,
                })

        return matched_chains

    def suggest_next_agent(self, confirmed_findings: list[dict], available_agents: list[str]) -> dict | None:
        """Based on current findings, suggest what agent should run next to enable a chain."""
        finding_types = [f.get("vuln_type", "") for f in confirmed_findings]

        for pattern in self.chains:
            required = pattern["chain"]
            missing = [vt for vt in required if vt not in finding_types]
            if missing and any(vt in finding_types for vt in required):
                # Partial match — suggest the missing piece
                next_type = missing[0]
                agent_map = {
                    "sqli": "exploit_sqli",
                    "xss": "exploit_xss",
                    "ssrf": "exploit_ssrf",
                    "rce": "exploit_rce",
                    "lfi": "exploit_lfi",
                    "idor": "exploit_idor",
                    "file_upload": "exploit_upload",
                }
                agent_name = agent_map.get(next_type)
                if agent_name and agent_name in available_agents:
                    return {
                        "chain_name": pattern["name"],
                        "next_agent": agent_name,
                        "rationale": f"Need {next_type} to complete chain: {pattern['name']}",
                        "priority": 9,
                    }
        return None

    def calculate_chain_impact(self, chain: dict, base_cvss: float = 6.0) -> float:
        """Boost CVSS based on chain impact multiplier."""
        boost = chain.get("impact_boost", 1)
        boosted = base_cvss + (boost * 1.5)
        return min(boosted, 10.0)

    def describe_chain_poc(self, chain: dict) -> str:
        steps = []
        for i, f in enumerate(chain.get("matched_findings", []), 1):
            poc = f.get("poc", "")[:100]
            steps.append(f"Step {i}: {f['title']}")
            if poc:
                steps.append(f"  PoC: {poc}")
        steps.append(f"\nImpact: {chain['description']}")
        steps.append(f"CVSS Boost: +{chain.get('impact_boost', 1) * 1.5}")
        return "\n".join(steps)
