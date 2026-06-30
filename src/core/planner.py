from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.core.blackboard import Blackboard
    from src.core.llm import LLMClient


OBSERVE_PROMPT = """You are the Observe phase of an OODA loop for a pentesting orchestrator.
Analyze the current blackboard state and identify:
1. New information discovered
2. Changes in target behavior
3. Gaps in current knowledge
4. Potential attack vectors that haven't been explored

Blackboard facts:
{facts}

Completed intents:
{intents_history}

Output JSON with structure:
{{
  "observations": ["list of key observations"],
  "gaps": ["list of knowledge gaps"],
  "confidence": 0.0-1.0
}}
"""

ORIENT_PROMPT = """You are the Orient phase of an OODA loop.
Based on observations, update the mental model and identify patterns.

Observations:
{observations}

Existing findings:
{findings}

Output JSON with structure:
{{
  "updated_model": "description of current understanding",
  "patterns": ["list of identified patterns"],
  "threats": ["list of potential threats/vulnerabilities"],
  "priority_targets": ["what to focus on"]
}}
"""

DECIDE_PROMPT = """You are the Decide phase of an OODA loop.
Based on the current understanding, decide the next actions.

Model: {model}
Patterns: {patterns}
Threats: {threats}
Available agents: {available_agents}

Output JSON with structure:
{{
  "actions": [
    {{
      "agent": "agent_name",
      "params": {{"key": "value"}},
      "priority": 1-10,
      "rationale": "why this action"
    }}
  ]
}}
"""


class Planner:
    def __init__(self, llm: LLMClient, blackboard: Blackboard):
        self.llm = llm
        self.blackboard = blackboard
        self._loop_count = 0

    async def observe(self) -> dict:
        facts = self.blackboard.get_all_facts()
        intents = self.blackboard.get_intent_history()
        facts_str = "\n".join(f"- {k}: {v}" for k, v in facts.items())
        intents_str = "\n".join(f"- {i['action']} [{i['status']}]" for i in intents[-10:])
        result = await self.llm.chat_json([
            {"role": "system", "content": OBSERVE_PROMPT.format(facts=facts_str, intents_history=intents_str)},
        ])
        for obs in result.get("observations", []):
            self.blackboard.set_fact(f"obs_{self._loop_count}_{obs[:40]}", obs, source="planner.observe", confidence=0.7)
        return result

    async def orient(self, observations: dict) -> dict:
        findings = self.blackboard.get_findings()
        result = await self.llm.chat_json([
            {"role": "system", "content": ORIENT_PROMPT.format(
                observations=json.dumps(observations),
                findings=json.dumps(findings),
            )},
        ])
        if result.get("updated_model"):
            self.blackboard.set_fact("current_model", result["updated_model"], source="planner.orient", confidence=0.6)
        return result

    async def decide(self, oriented: dict, available_agents: list[str]) -> list[dict]:
        result = await self.llm.chat_json([
            {"role": "system", "content": DECIDE_PROMPT.format(
                model=oriented.get("updated_model", "unknown"),
                patterns=json.dumps(oriented.get("patterns", [])),
                threats=json.dumps(oriented.get("threats", [])),
                available_agents=json.dumps(available_agents),
            )},
        ])
        self._loop_count += 1
        return result.get("actions", [])

    async def run_cycle(self, available_agents: list[str]) -> list[dict]:
        obs = await self.observe()
        oriented = await self.orient(obs)
        actions = await self.decide(oriented, available_agents)
        return actions
