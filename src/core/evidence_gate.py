from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone
from typing import Any


EVIDENCE_DIR = "./workspace/evidence"


class EvidencePackage:
    def __init__(self, finding: dict[str, Any]):
        self.finding_id = finding.get("_id", datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")[:20])
        self.title: str = finding.get("title", "unknown")
        self.severity: str = finding.get("severity", "info")
        self.vuln_type: str = finding.get("vuln_type", "")
        self.timestamp: str = finding.get("timestamp", datetime.now(timezone.utc).isoformat())
        self.target: str = finding.get("target", "")
        self.description: str = finding.get("description", "")

        self.requests: list[dict] = []
        self.responses: list[dict] = []
        self.screenshots: list[str] = []
        self.poc_commands: list[str] = []
        self.validation_result: dict = finding.get("_validation", {})
        self.notes: str = ""

    def add_request(self, method: str, url: str, headers: dict | None = None, body: str | None = None) -> None:
        self.requests.append({
            "method": method,
            "url": url,
            "headers": {k: v for k, v in (headers or {}).items() if k.lower() not in ("authorization", "cookie", "set-cookie")},
            "body": (body or "")[:2000],
        })

    def add_response(self, status: int, headers: dict | None = None, body: str | None = None) -> None:
        self.responses.append({
            "status": status,
            "headers": {k: v for k, v in (headers or {}).items() if k.lower() not in ("set-cookie",)},
            "body_preview": (body or "")[:1000],
            "body_length": len(body or ""),
        })

    def add_screenshot(self, path: str) -> None:
        if os.path.exists(path):
            self.screenshots.append(path)

    def add_poc(self, command: str) -> None:
        if command not in self.poc_commands:
            self.poc_commands.append(command)

    def add_note(self, note: str) -> None:
        self.notes += note + "\n"

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "vuln_type": self.vuln_type,
            "target": self.target,
            "timestamp": self.timestamp,
            "description": self.description,
            "requests": self.requests,
            "responses": self.responses,
            "screenshots": self.screenshots,
            "poc": self.poc_commands,
            "validation": self.validation_result,
            "notes": self.notes.strip(),
        }


class EvidenceGate:
    def __init__(self, output_dir: str = EVIDENCE_DIR):
        self.output_dir = output_dir
        self._packages: dict[str, EvidencePackage] = {}
        os.makedirs(output_dir, exist_ok=True)

    def create_package(self, finding: dict[str, Any]) -> EvidencePackage:
        pkg = EvidencePackage(finding)
        self._packages[pkg.finding_id] = pkg
        return pkg

    def get_package(self, finding_id: str) -> EvidencePackage | None:
        return self._packages.get(finding_id)

    def save_package(self, pkg: EvidencePackage) -> str:
        fpath = os.path.join(self.output_dir, f"{pkg.finding_id}.json")
        with open(fpath, "w", encoding="utf-8") as f:
            json.dump(pkg.to_dict(), f, indent=2, ensure_ascii=False)
        return fpath

    def save_all(self) -> list[str]:
        paths = []
        for pkg in self._packages.values():
            paths.append(self.save_package(pkg))
        return paths

    def export_poc_script(self, pkg: EvidencePackage, format: str = "bash") -> str:
        lines = [
            f"# PoC: {pkg.title}",
            f"# Target: {pkg.target}",
            f"# Severity: {pkg.severity}",
            f"# Vuln Type: {pkg.vuln_type}",
            f"# Date: {pkg.timestamp}",
            "",
        ]
        for cmd in pkg.poc_commands:
            lines.append(f"# {cmd}")
            lines.append(cmd)
            lines.append("")
        return "\n".join(lines)

    def export_all_poc(self, output_file: str = "./workspace/poc_all.sh") -> str:
        all_lines = ["#!/bin/bash", "# Overseer PoC Collection", f"# Generated: {datetime.now(timezone.utc).isoformat()}", ""]
        for pkg in self._packages.values():
            all_lines.append(f"# === {pkg.title} ({pkg.severity}) ===")
            all_lines.append(f"# Target: {pkg.target}")
            for cmd in pkg.poc_commands:
                all_lines.append(cmd)
            all_lines.append("")
        content = "\n".join(all_lines)
        with open(output_file, "w") as f:
            f.write(content)
        return output_file

    def get_confirmed_findings(self) -> list[dict]:
        return [pkg.to_dict() for pkg in self._packages.values()
                if pkg.validation_result.get("confirmed", False)]

    def get_all_packages(self) -> list[EvidencePackage]:
        return list(self._packages.values())
