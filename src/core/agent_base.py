from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.core.blackboard import Blackboard
    from src.core.llm import LLMClient
    from src.tools.registry import ToolRegistry


class BaseAgent(ABC):
    """Base class for ALL agents. Short-lived — one task, one result."""

    name: str = ""
    description: str = ""
    phase: str = ""

    def __init__(self, llm: LLMClient, blackboard: Blackboard, tools: ToolRegistry, config: dict[str, Any]):
        self.llm = llm
        self.blackboard = blackboard
        self.tools = tools
        self.config = config

    @abstractmethod
    async def run(self, params: dict[str, Any]) -> dict[str, Any]:
        ...

    def log(self, message: str) -> None:
        print(f"[{self.name}] {message}")

    def set_fact(self, key: str, value: Any, confidence: float = 1.0) -> None:
        self.blackboard.set_fact(key, value, source=self.name, confidence=confidence)

    def add_finding(self, title: str, severity: str, description: str,
                    vuln_type: str = "", evidence: str = "", poc: str = "") -> None:
        self.blackboard.add_finding(title, severity, description, vuln_type=vuln_type, evidence=evidence, poc=poc)
        self.log(f"CANDIDATE: [{severity}] {title}")
