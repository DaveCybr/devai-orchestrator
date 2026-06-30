from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.core.agent_base import BaseAgent


class AgentRegistry:
    def __init__(self):
        self._agents: dict[str, type[BaseAgent]] = {}
        self._phase_order = ["recon", "exploit", "post_exploit"]

    def register(self, agent_cls: type[BaseAgent]) -> None:
        if not agent_cls.name:
            raise ValueError(f"Agent class {agent_cls.__name__} must set `name`")
        self._agents[agent_cls.name] = agent_cls

    def get(self, name: str) -> type[BaseAgent] | None:
        return self._agents.get(name)

    def list_available(self, phase: str | None = None) -> list[str]:
        if phase:
            return [n for n, a in self._agents.items() if a.phase == phase]
        return list(self._agents.keys())

    def list_by_phase(self) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        for name, cls in self._agents.items():
            result.setdefault(cls.phase, []).append(name)
        return result
