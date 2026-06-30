from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from typing import Any


class Fact:
    def __init__(
        self,
        key: str,
        value: Any,
        source: str = "",
        confidence: float = 1.0,
        ttl: int | None = None,
    ):
        self.key = key
        self.value = value
        self.source = source
        self.confidence = confidence
        self.created_at = datetime.now(timezone.utc)
        self.ttl = ttl

    @property
    def expired(self) -> bool:
        if self.ttl is None:
            return False
        elapsed = (datetime.now(timezone.utc) - self.created_at).total_seconds()
        return elapsed > self.ttl

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "value": self.value,
            "source": self.source,
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat(),
        }


class Intent:
    def __init__(self, action: str, params: dict[str, Any], priority: int = 5, parent: str | None = None):
        self.action = action
        self.params = params
        self.priority = priority
        self.parent = parent
        self.status = "pending"
        self.created_at = datetime.now(timezone.utc)
        self.result: Any = None
        self.error: str | None = None

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "params": self.params,
            "priority": self.priority,
            "parent": self.parent,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
        }


class Blackboard:
    def __init__(self, persist_path: str | None = None):
        self._facts: dict[str, Fact] = {}
        self._intents: list[Intent] = []
        self._findings: list[dict] = []
        self._lock = threading.Lock()
        self._session_id: str | None = None
        self._target: str | None = None
        self._metadata: dict[str, Any] = {}
        self.persist_path = persist_path

    @property
    def target(self) -> str | None:
        return self._target

    @target.setter
    def target(self, value: str) -> None:
        self._target = value

    @property
    def session_id(self) -> str | None:
        return self._session_id

    @session_id.setter
    def session_id(self, value: str) -> None:
        self._session_id = value

    # Facts
    def set_fact(self, key: str, value: Any, source: str = "", confidence: float = 1.0) -> None:
        with self._lock:
            self._facts[key] = Fact(key, value, source, confidence)

    def get_fact(self, key: str) -> Any | None:
        fact = self._facts.get(key)
        if fact is None or fact.expired:
            return None
        return fact.value

    def get_all_facts(self) -> dict[str, Any]:
        return {k: v.value for k, v in self._facts.items() if not v.expired}

    def fact_exists(self, key: str) -> bool:
        fact = self._facts.get(key)
        return fact is not None and not fact.expired

    def delete_fact(self, key: str) -> None:
        with self._lock:
            self._facts.pop(key, None)

    # Intents
    def add_intent(self, action: str, params: dict[str, Any] | None = None, priority: int = 5, parent: str | None = None) -> str:
        intent = Intent(action, params or {}, priority, parent)
        with self._lock:
            self._intents.append(intent)
        return f"{action}_{len(self._intents)}"

    def get_pending_intents(self) -> list[Intent]:
        with self._lock:
            pending = sorted(
                [i for i in self._intents if i.status == "pending"],
                key=lambda x: x.priority,
                reverse=True,
            )
            # Mark as in_progress atomically
            for intent in pending:
                intent.status = "in_progress"
            return pending

    def complete_intent(self, intent: Intent, result: Any = None) -> None:
        intent.status = "completed"
        intent.result = result

    def fail_intent(self, intent: Intent | dict, error: str) -> None:
        if isinstance(intent, dict):
            return
        intent.status = "failed"
        intent.error = error

    def get_intent_history(self) -> list[dict]:
        return [i.to_dict() for i in self._intents]

    # Findings
    def add_finding(self, title: str, severity: str, description: str, vuln_type: str = "", evidence: str | None = None, poc: str | None = None) -> None:
        with self._lock:
            self._findings.append({
                "title": title,
                "severity": severity,
                "description": description,
                "vuln_type": vuln_type,
                "evidence": evidence,
                "poc": poc,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "target": self._target,
            })

    def get_findings(self) -> list[dict]:
        return list(self._findings)

    # Metadata
    def set_metadata(self, key: str, value: Any) -> None:
        with self._lock:
            self._metadata[key] = value

    def get_metadata(self, key: str) -> Any | None:
        return self._metadata.get(key)

    # Persistence
    def save(self) -> None:
        if not self.persist_path:
            return
        os.makedirs(self.persist_path, exist_ok=True)
        data = {
            "facts": [f.to_dict() for f in self._facts.values()],
            "intents": [i.to_dict() for i in self._intents],
            "findings": self._findings,
            "metadata": self._metadata,
            "target": self._target,
            "session_id": self._session_id,
        }
        path = os.path.join(self.persist_path, f"blackboard_{self._session_id or 'default'}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def load(self, session_id: str) -> bool:
        if not self.persist_path:
            return False
        path = os.path.join(self.persist_path, f"blackboard_{session_id}.json")
        if not os.path.exists(path):
            return False
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        self._facts = {}
        for fd in data.get("facts", []):
            f = Fact(fd["key"], fd["value"], fd.get("source", ""), fd.get("confidence", 1.0))
            self._facts[fd["key"]] = f
        self._intents = []
        for id_ in data.get("intents", []):
            i = Intent(id_["action"], id_.get("params", {}), id_.get("priority", 5), id_.get("parent"))
            i.status = id_.get("status", "pending")
            self._intents.append(i)
        self._findings = data.get("findings", [])
        self._metadata = data.get("metadata", {})
        self._target = data.get("target")
        self._session_id = data.get("session_id")
        return True
