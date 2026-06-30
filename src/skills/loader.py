from __future__ import annotations

import os
import re
from typing import Any

import yaml


class Skill:
    def __init__(self, data: dict[str, Any]):
        self.name: str = data.get("name", "unknown")
        self.description: str = data.get("description", "")
        self.phase: str = data.get("phase", "exploit")
        self.priority: int = data.get("priority", 5)
        self.conditions: dict = data.get("conditions", {})
        self.payloads: dict = data.get("payloads", {})
        self.tools: dict = data.get("tools", {})
        self.validation: dict = data.get("validation", {})
        self.examples: list = data.get("examples", [])

    def matches_target(self, facts: dict[str, Any], findings: list[dict]) -> bool:
        triggers = self.conditions.get("triggers", [])
        if not triggers:
            return False

        # Check if any trigger condition is satisfied by current facts
        fact_values = " ".join(str(v).lower() for v in facts.values())
        finding_titles = " ".join(f.get("title", "").lower() for f in findings)
        combined = fact_values + " " + finding_titles

        for trigger in triggers:
            trigger_lower = trigger.lower()
            # Direct keyword match
            keywords = re.findall(r'\b\w+\b', trigger_lower)
            if any(kw in combined for kw in keywords):
                return True
            # Pattern match
            if "parameter" in trigger_lower and "parameter" in combined:
                return True
            if "upload" in trigger_lower and "upload" in combined:
                return True

        return False

    def to_prompt_block(self) -> str:
        lines = [
            f"## Skill: {self.name} ({self.priority})",
            f"Description: {self.description}",
            "",
            "### Payloads:",
        ]
        for category, payload_list in self.payloads.items():
            lines.append(f"  {category}:")
            for p in payload_list[:5]:
                lines.append(f"    - {p[:80]}")

        lines.append("")
        lines.append("### Tools:")
        for role, tool_list in self.tools.items():
            if isinstance(tool_list, list):
                lines.append(f"  {role}: {', '.join(tool_list)}")

        lines.append("")
        lines.append("### Validation:")
        for rule in self.validation.get("rules", []):
            lines.append(f"  - {rule.get('type', 'unknown')}: {rule.get('method', '')[:60]}")

        return "\n".join(lines)

    def __repr__(self) -> str:
        return f"<Skill {self.name} ({self.phase}, p={self.priority})>"


class SkillLibrary:
    def __init__(self, skills_dir: str | None = None):
        self._skills: dict[str, Skill] = {}
        self._load_skills(skills_dir or os.path.join(os.path.dirname(__file__)))

    def _load_skills(self, directory: str) -> None:
        if not os.path.isdir(directory):
            print(f"[Skills] Directory not found: {directory}")
            return
        for fname in os.listdir(directory):
            if fname.endswith((".yaml", ".yml")):
                fpath = os.path.join(directory, fname)
                try:
                    with open(fpath, encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                    if data and "name" in data:
                        skill = Skill(data)
                        self._skills[skill.name] = skill
                except Exception as e:
                    print(f"[Skills] Error loading {fname}: {e}")

    def get(self, name: str) -> Skill | None:
        return self._skills.get(name)

    def list_all(self) -> list[Skill]:
        return list(self._skills.values())

    def find_matching(self, facts: dict[str, Any], findings: list[dict]) -> list[Skill]:
        """Return skills whose trigger conditions match current state."""
        matched = []
        for skill in self._skills.values():
            if skill.matches_target(facts, findings):
                matched.append(skill)
        # Sort by priority descending
        matched.sort(key=lambda s: s.priority, reverse=True)
        return matched

    def get_all_prompt_blocks(self) -> str:
        return "\n\n".join(s.to_prompt_block() for s in self._skills.values())
