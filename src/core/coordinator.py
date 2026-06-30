from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.core.blackboard import Blackboard
    from src.core.llm import LLMClient
    from src.skills.loader import SkillLibrary


OBSERVE_PROMPT = """You are the Observe phase of an OODA loop for a pentesting orchestrator.
Analyze the current blackboard state and identify:
1. New information discovered (SAST findings, DAST results)
2. Knowledge gaps
3. Potential exploit chain connections between findings
4. What attack vectors haven't been tested

Blackboard facts:
{facts}

Completed intents:
{intents_history}

Confirmed findings:
{findings}

Output JSON:
{{
  "observations": ["list of key observations"],
  "gaps": ["list of what we don't know yet"],
  "chain_opportunities": ["potential connections between findings"],
  "confidence": 0.0-1.0
}}
"""

ORIENT_PROMPT = """You are the Orient phase. Build a mental model of the target's weaknesses.
Identify patterns and potential exploit chains.

Observations: {observations}
Existing findings: {findings}
SAST hints: {sast_hints}

Output JSON:
{{
  "model": "current understanding of target security posture",
  "patterns": ["identified vulnerability patterns"],
  "chains": [{{"from": "finding_a", "to": "finding_b", "rationale": "why this chain works"}}],
  "priority_vectors": ["what to attack next"]
}}
"""

DECIDE_PROMPT = """You are the Decide phase. Pick the NEXT action only.
Prefer short-lived specialist agents over complex multi-step actions.

Model: {model}
Chains: {chains}
Priority vectors: {vectors}
Available agents: {agents}

Available skills (attack techniques):
{skills}

Rules:
- Each action must be ONE simple task for ONE specialist agent
- Prefer agents that haven't run yet
- If a chain is available, dispatch the agent needed to advance it
- Use skills above to guide payload/tool selection

Output JSON:
{{
  "actions": [
    {{
      "agent": "agent_name",
      "params": {{"vuln_type": "skill_name", "payloads": [...], "target_url": "..."}},
      "priority": 1-10,
      "rationale": "why this action now"
    }}
  ]
}}
"""

ACT_PROMPT = """You are the Act phase. Process the result of agent execution.

Agent: {agent_name}
Result: {result}

Update the understanding:
1. Does this result confirm or deny any hypotheses?
2. What new facts should be recorded?
3. Is there a chain opportunity from this result?

Output JSON:
{{
  "new_facts": [{{"key": "fact_name", "value": "fact_value"}}],
  "hypotheses_status": "confirmed|denied|inconclusive",
  "chain_next": "what this result enables next",
  "confidence": 0.0-1.0
}}
"""


class Coordinator:
    def __init__(self, llm: LLMClient, blackboard: Blackboard, skills: SkillLibrary | None = None):
        self.llm = llm
        self.blackboard = blackboard
        self.skills = skills
        self._loop = 0
        self.deterministic = not llm.is_available()

    async def observe(self) -> dict:
        facts = self.blackboard.get_all_facts()
        intents = self.blackboard.get_intent_history()
        findings = self.blackboard.get_findings()

        result = await self.llm.chat_json([
            {"role": "system", "content": OBSERVE_PROMPT.format(
                facts="\n".join(f"- {k}: {v}" for k, v in facts.items()),
                intents_history="\n".join(f"- {i['action']} [{i['status']}]" for i in intents[-10:]),
                findings=json.dumps([f["title"] for f in findings[-5:]]),
            )},
        ])
        for obs in result.get("observations", []):
            self.blackboard.set_fact(f"obs_{self._loop}_{obs[:40]}", obs, source="coordinator", confidence=0.6)
        return result

    async def orient(self, observations: dict) -> dict:
        findings = self.blackboard.get_findings()
        sast_hints = self.blackboard.get_fact("sast_findings") or []
        result = await self.llm.chat_json([
            {"role": "system", "content": ORIENT_PROMPT.format(
                observations=json.dumps(observations),
                findings=json.dumps(findings),
                sast_hints=json.dumps(sast_hints[:5]),
            )},
        ])
        self.blackboard.set_fact("model", result.get("model", ""), source="coordinator", confidence=0.5)
        if result.get("chains"):
            self.blackboard.set_fact("exploit_chains", result["chains"], source="coordinator", confidence=0.5)
        return result

    async def decide(self, oriented: dict, available_agents: list[str]) -> list[dict]:
        skills_str = ""
        if self.skills:
            facts = self.blackboard.get_all_facts()
            findings = self.blackboard.get_findings()
            matched = self.skills.find_matching(facts, findings)
            skills_str = "\n".join(s.to_prompt_block() for s in matched) if matched else "No matching skills"

        result = await self.llm.chat_json([
            {"role": "system", "content": DECIDE_PROMPT.format(
                model=oriented.get("model", "unknown"),
                chains=json.dumps(oriented.get("chains", [])),
                vectors=json.dumps(oriented.get("priority_vectors", [])),
                agents=json.dumps(available_agents),
                skills=skills_str,
            )},
        ])
        return result.get("actions", [])

    async def act(self, agent_result: dict, agent_name: str) -> dict:
        if self.deterministic:
            return self._deterministic_act(agent_result, agent_name)
        try:
            result = await self.llm.chat_json([
                {"role": "system", "content": ACT_PROMPT.format(
                    agent_name=agent_name,
                    result=json.dumps(agent_result),
                )},
            ])
            for fact in result.get("new_facts", []):
                self.blackboard.set_fact(fact["key"], fact["value"],
                                         source=f"act.{agent_name}", confidence=result.get("confidence", 0.5))
            return result
        except Exception:
            return self._deterministic_act(agent_result, agent_name)

    def _deterministic_act(self, agent_result: dict, agent_name: str) -> dict:
        status = agent_result.get("status", "done")
        findings = agent_result.get("findings", [])
        if findings:
            for f in findings:
                self.blackboard.add_finding(
                    title=f.get("title", "Untitled"),
                    severity=f.get("severity", "info"),
                    description=f.get("description", ""),
                    vuln_type=f.get("vuln_type", ""),
                    evidence=f.get("evidence", ""),
                    poc=f.get("poc", ""),
                )
        chain_next = "none"
        if findings:
            chain_next = f"{len(findings)} findings - check chain planner"
        return {"new_facts": [], "hypotheses_status": "inconclusive",
                "chain_next": chain_next, "confidence": 0.5}

    async def run_cycle(self, available_agents: list[str]) -> tuple[list[dict], list[dict] | None]:
        if self.deterministic:
            return await self._deterministic_cycle(available_agents), None
        try:
            obs = await self.observe()
            oriented = await self.orient(obs)
            actions = await self.decide(oriented, available_agents)
            return actions, oriented
        except Exception:
            self.deterministic = True
            print("  [Coordinator] LLM failed, switching to deterministic mode")
            return await self._deterministic_cycle(available_agents), None

    async def _deterministic_cycle(self, available_agents: list[str]) -> list[dict]:
        self._loop += 1
        facts = self.blackboard.get_all_facts()
        findings = self.blackboard.get_findings()
        finding_types = [f.get("vuln_type", "") for f in findings]
        dispatched_key = "_dispatch_order"
        dispatched = self.blackboard.get_fact(dispatched_key) or []

        round_num = self._loop

        # Round 1: always start with recon
        if round_num == 1 and "recon" in available_agents and "recon" not in dispatched:
            dispatched.append("recon")
            self.blackboard.set_fact(dispatched_key, dispatched, source="coordinator", confidence=1.0)
            return [{"agent": "recon", "params": {}, "priority": 5, "rationale": "Initial recon"}]

        # Round 2: run SAST and DAST
        if round_num == 2:
            actions = []
            for a in ("sast", "dast"):
                if a in available_agents and a not in dispatched:
                    dispatched.append(a)
                    actions.append({"agent": a, "params": {}, "priority": 5, "rationale": f"{a.upper()} scan"})
            if actions:
                self.blackboard.set_fact(dispatched_key, dispatched, source="coordinator", confidence=1.0)
                return actions

        # Find untried exploit agents
        untried = [a for a in available_agents if a.startswith("exploit_") and a not in dispatched]

        # Prioritize based on existing findings
        if untried:
            vuln_map = {
                "exploit_sqli": "sqli", "exploit_xss": "xss", "exploit_ssrf": "ssrf",
                "exploit_rce": "rce", "exploit_lfi": "lfi",
                "exploit_idor": "idor", "exploit_upload": "file_upload",
            }
            # Try to match exploit to untested vuln type
            for agent_name in untried:
                vt = vuln_map.get(agent_name, "")
                if vt and vt not in finding_types:
                    dispatched.append(agent_name)
                    self.blackboard.set_fact(dispatched_key, dispatched, source="coordinator", confidence=1.0)
                    return [{"agent": agent_name, "params": {}, "priority": 5,
                             "rationale": f"Try {vt} exploitation"}]

            # All types tested or unknown — dispatch next untried
            next_agent = untried[0]
            dispatched.append(next_agent)
            self.blackboard.set_fact(dispatched_key, dispatched, source="coordinator", confidence=1.0)
            return [{"agent": next_agent, "params": {}, "priority": 5,
                     "rationale": f"Try {next_agent}"}]

        return []
