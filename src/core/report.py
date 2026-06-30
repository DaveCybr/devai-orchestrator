from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any


CVSS_MAP = {
    "critical": (9.0, 10.0),
    "high": (7.0, 8.9),
    "medium": (4.0, 6.9),
    "low": (0.1, 3.9),
    "info": (0.0, 0.0),
}

FINDING_TEMPLATE = """## [{severity}] {title}

**Target:** {target}
**Type:** {vuln_type}
**CVSS 3.1:** {cvss_score} ({severity})
**Date:** {timestamp}

### Description
{description}

### Evidence
{evidence}

### Proof of Concept
{poc}

### Chain Analysis
{chain_info}

### Recommendation
{recommendation}

---

"""

RECOMMENDATIONS = {
    "sqli": "Use parameterized queries / prepared statements. Implement WAF rules to block SQL error patterns.",
    "xss": "Implement Content-Security-Policy. Encode output contextually (HTML entity, JS unicode, CSS escape).",
    "ssrf": "Implement URL allowlist. Block metadata IP ranges (169.254.169.254, 100.100.100.200). Use network policies.",
    "rce": "Never execute user input as code. Use allowlist for allowed commands. Run services with least privilege.",
    "lfi": "Validate file paths against an allowlist. Use chroot jail or restricted filesystem access.",
    "idor": "Implement object-level access control. Use UUID instead of sequential IDs. Validate ownership server-side.",
    "file_upload": "Validate file extension + MIME + magic bytes. Store files outside webroot. Serve via script with access control.",
}


class ReportAgent:
    def __init__(self, output_dir: str = "./workspace/reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def cvss_score(self, severity: str) -> float:
        lo, hi = CVSS_MAP.get(severity.lower(), (0, 0))
        return round((lo + hi) / 2, 1)

    def generate_markdown(self, findings: list[dict], chains: list[dict] | None = None) -> str:
        sections = [
            "# Security Assessment Report",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Findings:** {len(findings)}",
            "",
            "---",
            "",
        ]

        # Executive summary
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in sev_counts:
                sev_counts[sev] += 1

        sections.append("## Executive Summary\n")
        for sev, count in sev_counts.items():
            if count > 0:
                sections.append(f"- **{sev.capitalize()}:** {count}")
        if chains:
            sections.append(f"\n**Exploit Chains Identified:** {len(chains)}\n")
            for c in chains:
                sections.append(f"- {c['name']} ({len(c['matched_findings'])} findings)")
        sections.append("")

        # Individual findings
        if findings:
            sections.append("---\n## Findings\n")
            for f in findings:
                title = f.get("title", "Unknown")
                severity = f.get("severity", "info").capitalize()
                vuln_type = f.get("vuln_type", "unknown")
                target = f.get("target", "N/A")
                timestamp = f.get("timestamp", "")
                description = f.get("description", "No description")
                poc = f.get("poc", "")
                evidence = (f.get("evidence") or f.get("_validation", {}).get("evidence", ""))[:500]
                score = self.cvss_score(severity)

                # Chain info for this finding
                chain_info = "None"
                if chains:
                    related = [c for c in chains if any(
                        m.get("vuln_type") == vuln_type for m in c.get("matched_findings", [])
                    )]
                    if related:
                        chain_info = "; ".join(f"{c['name']} (+{c.get('impact_boost',1)*1.5} CVSS)" for c in related)

                recommendation = RECOMMENDATIONS.get(vuln_type, "Review and fix the identified vulnerability.")

                sections.append(FINDING_TEMPLATE.format(
                    title=title,
                    severity=severity,
                    target=target,
                    vuln_type=vuln_type,
                    cvss_score=score,
                    timestamp=timestamp,
                    description=description,
                    evidence=evidence[:500],
                    poc=(poc or "N/A")[:300],
                    chain_info=chain_info,
                    recommendation=recommendation,
                ))

        # Chain section
        if chains:
            sections.append("---\n## Exploit Chains\n")
            for c in chains:
                sections.append(f"### {c['name']}\n")
                sections.append(f"{c['description']}\n")
                sections.append("**Prerequisites:**\n")
                for cond in c.get("conditions", []):
                    sections.append(f"- {cond}")
                sections.append(f"\n**Impact Boost:** +{c.get('impact_boost', 1) * 1.5} CVSS\n")

                sections.append("**Steps:**\n")
                for i, f in enumerate(c.get("matched_findings", []), 1):
                    sections.append(f"{i}. {f['title']}")
                    poc_cmd = f.get("poc", "")
                    if poc_cmd:
                        sections.append(f"   `{poc_cmd[:100]}`")
                sections.append("")

        return "\n".join(sections)

    def generate_json(self, findings: list[dict], chains: list[dict] | None = None) -> dict:
        return {
            "report_metadata": {
                "generated": datetime.now(timezone.utc).isoformat(),
                "total_findings": len(findings),
                "total_chains": len(chains or []),
            },
            "severity_summary": {
                sev: len([f for f in findings if f.get("severity", "").lower() == sev])
                for sev in ["critical", "high", "medium", "low", "info"]
            },
            "findings": findings,
            "chains": chains or [],
        }

    def save_report(self, findings: list[dict], chains: list[dict] | None = None, formats: list[str] | None = None) -> dict[str, str]:
        if formats is None:
            formats = ["md", "json"]

        saved = {}
        session_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        if "md" in formats:
            md = self.generate_markdown(findings, chains)
            md_path = os.path.join(self.output_dir, f"report_{session_id}.md")
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(md)
            saved["markdown"] = md_path

        if "json" in formats:
            data = self.generate_json(findings, chains)
            json_path = os.path.join(self.output_dir, f"report_{session_id}.json")
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            saved["json"] = json_path

        return saved
