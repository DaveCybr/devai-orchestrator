from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from src.core.blackboard import Blackboard
    from src.core.chain_planner import ChainPlanner
    from src.core.coordinator import Coordinator
    from src.core.evidence_gate import EvidenceGate
    from src.core.llm import LLMClient
    from src.core.registry import AgentRegistry
    from src.tools.registry import ToolRegistry


class Session:
    def __init__(
        self,
        target: str,
        llm: LLMClient,
        blackboard: Blackboard,
        coordinator: Coordinator,
        agents: AgentRegistry,
        tools: ToolRegistry,
        config: dict[str, Any],
        validator_fn: Callable,
        evidence_gate: EvidenceGate,
        chain_planner: ChainPlanner,
    ):
        self.id = uuid.uuid4().hex[:12]
        self.target = target
        self.llm = llm
        self.blackboard = blackboard
        self.coordinator = coordinator
        self.agents = agents
        self.tools = tools
        self.config = config
        self.validator_fn = validator_fn
        self.evidence_gate = evidence_gate
        self.chain_planner = chain_planner
        self.started_at = datetime.now(timezone.utc)
        self.ended_at: datetime | None = None
        self.rounds = 0
        self.max_rounds = config.get("orchestrator", {}).get("max_rounds_per_target", 50)
        self._validated_findings: list[dict] = []

        self.blackboard.session_id = self.id
        self.blackboard.target = target
        self.blackboard.set_fact("target", target, source="session", confidence=1.0)
        self.blackboard.set_fact("session_started", self.started_at.isoformat(), source="session", confidence=1.0)

    async def _validate_and_gate(self) -> list[dict]:
        """Validate findings → Evidence Gate → only confirmed pass through."""
        findings = self.blackboard.get_findings()
        passed = []

        for f in findings:
            if f.get("_validated"):
                passed.append(f)
                continue

            vuln_type = f.get("vuln_type", "")
            result = {"confirmed": False, "type": "unknown", "evidence": "No validator"}
            if vuln_type:
                vargs = f.get("validation_args", {})
                if not vargs:
                    vargs = {
                        "url": f.get("url", self.target),
                        "param": f.get("param", "q"),
                        "payload": f.get("payload", ""),
                        "evidence_text": f.get("evidence", ""),
                        "file_path": f.get("file_path", ""),
                        "command": f.get("command", ""),
                        "callback_url": f.get("callback_url", ""),
                    }
                result = self.validator_fn(vuln_type, **vargs)

            if result["confirmed"]:
                f["_validated"] = True
                f["_validation"] = result

                # Evidence Gate: capture structured evidence
                pkg = self.evidence_gate.create_package(f)
                pkg.validation_result = result
                for req in f.get("_requests", []):
                    pkg.add_request(req.get("method", "GET"), req.get("url", ""),
                                    req.get("headers"), req.get("body"))
                for res in f.get("_responses", []):
                    pkg.add_response(res.get("status", 0), res.get("headers"), res.get("body"))
                for poc in f.get("_poc_commands", []):
                    pkg.add_poc(poc)
                if f.get("_screenshots"):
                    for ss in f["_screenshots"]:
                        pkg.add_screenshot(ss)

                self.evidence_gate.save_package(pkg)
                passed.append(f)
                print(f"    [GATED] {f['title']} ({result['type']}) - evidence saved")
            else:
                print(f"    [REJECTED] {f['title']} - {result['evidence']}")

        self._validated_findings = passed
        return passed

    async def run(self) -> list[dict]:
        print(f"\n{'='*60}")
        print(f"OVERSEER Session {self.id}")
        print(f"Target: {self.target}")
        print(f"Pipeline: Validate -> Evidence Gate -> Report")
        print(f"{'='*60}\n")

        while self.rounds < self.max_rounds:
            self.rounds += 1
            print(f"\n-- Round {self.rounds}/{self.max_rounds} --")

            actions, oriented = await self.coordinator.run_cycle(self.agents.list_available())

            if not actions:
                print("[OODA] No actions. Ending session.")
                break

            for action in actions:
                agent_cls = self.agents.get(action["agent"])
                if not agent_cls:
                    print(f"[OODA] Unknown agent: {action['agent']}")
                    continue

                params = action.get("params", {})
                params.setdefault("target", self.target)

                agent = agent_cls(self.llm, self.blackboard, self.tools, self.config)
                self.blackboard.add_intent(action["agent"], params, action.get("priority", 5))

                print(f"  [Act] {action['agent']} | {action.get('rationale', '')[:80]}")
                try:
                    agent_result = await agent.run(params)
                    status = agent_result.get("status", "done")

                    act_result = await self.coordinator.act(agent_result, action["agent"])
                    print(f"  [OK] {action['agent']}: {status} | chains: {act_result.get('chain_next', 'none')[:60]}")

                    # Validate + Evidence Gate immediately
                    if status == "success" and agent_result.get("findings"):
                        passed = await self._validate_and_gate()
                        for f in passed:
                            self.blackboard.add_intent(
                                "report_agent",
                                {"finding": f},
                                priority=9,
                                parent=action["agent"],
                            )

                except Exception as e:
                    print(f"  [FAIL] {action['agent']} failed: {e}")
                    self.blackboard.fail_intent(
                        self.blackboard.get_intent_history()[-1],
                        str(e),
                    )

            self.blackboard.save()

        # Final validation + evidence gate
        print(f"\n{'-'*60}")
        print("FINAL VALIDATION + EVIDENCE GATE")
        final = await self._validate_and_gate()

        # Export all PoCs
        poc_path = self.evidence_gate.export_all_poc()
        print(f"  PoC script: {poc_path}")

        self.ended_at = datetime.now(timezone.utc)
        print(f"\n{'='*60}")
        print(f"SESSION COMPLETE")
        print(f"Rounds: {self.rounds}")
        print(f"Confirmed findings: {len(final)}")
        for i, f in enumerate(final, 1):
            print(f"  {i}. [{f['severity']}] {f['title']}")
            pkg = self.evidence_gate.get_package(f.get("_id", ""))
            if pkg:
                print(f"     Evidence: {self.evidence_gate.save_package(pkg)}")
        print(f"{'='*60}\n")
        return final
