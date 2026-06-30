from __future__ import annotations

import os
import sys
from typing import Any

import yaml

from src.core.blackboard import Blackboard
from src.core.chain_planner import ChainPlanner
from src.core.coordinator import Coordinator
from src.core.evidence_gate import EvidenceGate
from src.core.llm import LLMClient
from src.core.registry import AgentRegistry
from src.core.report import ReportAgent
from src.core.session import Session
from src.core.validator import validate_finding
from src.skills.loader import SkillLibrary
from src.tools.registry import ToolRegistry


class Orchestrator:
    def __init__(self, config_path: str = ""):
        self.config = self._load_config(config_path)
        self.blackboard = Blackboard(
            persist_path=self.config.get("blackboard", {}).get("persist_path", "./workspace/state")
        )
        self.llm = LLMClient(self.config["llm"])
        self.tools = ToolRegistry(self.config)
        self.agents = AgentRegistry()
        self.skills = SkillLibrary(self._get_skills_dir())
        self.coordinator = Coordinator(self.llm, self.blackboard, skills=self.skills)
        self.evidence_gate = EvidenceGate(
            output_dir=os.path.join(
                self.config.get("orchestrator", {}).get("workspace_dir", "./workspace"),
                "evidence",
            )
        )
        self.chain_planner = ChainPlanner()
        self.report_agent = ReportAgent(
            output_dir=os.path.join(
                self.config.get("orchestrator", {}).get("workspace_dir", "./workspace"),
                "reports",
            )
        )
        self._register_agents()

    def _get_skills_dir(self) -> str:
        candidates = [
            os.path.join(os.path.dirname(__file__), "..", "skills"),
            os.path.join(os.getcwd(), "src", "skills"),
        ]
        for c in candidates:
            if os.path.isdir(c):
                return c
        return candidates[0]

    @staticmethod
    def _load_config(path: str) -> dict[str, Any]:
        paths_to_try = [
            path,
            "config/default.yaml",
            os.path.join(os.path.dirname(__file__), "..", "..", "config", "default.yaml"),
            os.path.join(os.getcwd(), "config", "default.yaml"),
        ]
        for p in paths_to_try:
            if p and os.path.exists(p):
                with open(p, encoding="utf-8") as f:
                    return yaml.safe_load(f) or {}
        print("[!] No config found, using defaults")
        return {}

    def _register_agents(self) -> None:
        from src.agents.recon.recon_agent import ReconAgent
        from src.agents.recon.sast_agent import SASTAgent
        from src.agents.recon.dast_agent import DASTAgent
        self.agents.register(ReconAgent)
        self.agents.register(SASTAgent)
        self.agents.register(DASTAgent)

        from src.agents.exploit.sqli_agent import ExploitSQLiAgent
        from src.agents.exploit.xss_agent import ExploitXSSAgent
        from src.agents.exploit.ssrf_agent import ExploitSSRFAgent
        from src.agents.exploit.rce_agent import ExploitRCEAgent
        from src.agents.exploit.lfi_agent import ExploitLFIAgent
        from src.agents.exploit.idor_agent import ExploitIDORAgent
        from src.agents.exploit.upload_agent import ExploitUploadAgent
        self.agents.register(ExploitSQLiAgent)
        self.agents.register(ExploitXSSAgent)
        self.agents.register(ExploitSSRFAgent)
        self.agents.register(ExploitRCEAgent)
        self.agents.register(ExploitLFIAgent)
        self.agents.register(ExploitIDORAgent)
        self.agents.register(ExploitUploadAgent)

    async def run(self, target: str) -> dict:
        session = Session(target, self.llm, self.blackboard, self.coordinator,
                          self.agents, self.tools, self.config, validate_finding,
                          self.evidence_gate, self.chain_planner)

        confirmed = await session.run()

        # Chain planner
        chains = self.chain_planner.find_chains(confirmed)
        if chains:
            print(f"\n[Chains] Identified {len(chains)} exploit chains:")
            for c in chains:
                print(f"  - {c['name']} ({len(c['matched_findings'])} findings, +{c['impact_boost']*1.5} CVSS)")

        # Report agent
        report_paths = self.report_agent.save_report(confirmed, chains)
        print(f"\n[Report] Generated:")
        for fmt, path in report_paths.items():
            print(f"  {fmt}: {path}")

        return {
            "findings": confirmed,
            "chains": chains,
            "reports": report_paths,
        }

    async def close(self):
        await self.llm.close()
        if self.config.get("orchestrator", {}).get("cleanup_on_exit", True):
            self.blackboard.save()

    def list_agents(self) -> dict[str, list[str]]:
        return self.agents.list_by_phase()

    def list_skills(self) -> list[str]:
        return [s.name for s in self.skills.list_all()]
