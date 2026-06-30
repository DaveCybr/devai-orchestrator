from __future__ import annotations

from typing import Any

from src.core.agent_base import BaseAgent

RECON_PROMPT = """You are a recon agent. Your goal is to gather information about the target.
Use the available tools to:

1. Resolve DNS
2. Check common web paths
3. Fetch the main page and analyze technologies
4. Identify potential attack surface

Target: {target}
Target type: {target_type}
Previous findings: {findings}

Available tools: {tools}

Return a JSON with:
{{
  "status": "success" or "error",
  "findings": ["list of findings"],
  "technologies": ["detected technologies"],
  "endpoints": ["interesting endpoints found"],
  "next_steps": ["suggested next actions"]
}}
"""


class ReconAgent(BaseAgent):
    name = "recon"
    description = "Gather initial information about the target"
    phase = "recon"

    async def run(self, params: dict[str, Any]) -> dict[str, Any]:
        target = params.get("target", "")
        if not target:
            return {"status": "error", "message": "No target provided"}

        self.log(f"Starting recon on {target}")

        # Step 1: DNS resolution
        dns_result = await self.tools.execute("dns_resolve", hostname=target)
        self.set_fact("dns_resolution", dns_result)

        # Step 2: Fetch main page
        fetch_result = await self.tools.execute("http_fetch", url=target)
        self.set_fact("main_page", fetch_result[:500], confidence=0.8)

        # Step 3: Dir enum
        dirs = await self.tools.execute("dir_enum", target=target)
        if dirs and "[!]" not in dirs:
            self.set_fact("interesting_paths", dirs)
            for line in dirs.splitlines():
                if "->" in line:
                    path = line.split("->")[0].strip()
                    self.blackboard.add_intent(
                        "exploit_web",
                        {"target": target, "path": path, "vector": "check"},
                        priority=7,
                    )

        # Step 4: Analyze with LLM
        result = await self.llm.chat_json([
            {"role": "system", "content": RECON_PROMPT.format(
                target=target,
                target_type=params.get("target_type", "web_application"),
                findings=len(self.blackboard.get_findings()),
                tools=", ".join(self.tools.list_tools()),
            )},
            {"role": "user", "content": f"DNS: {dns_result}\n\nPage: {fetch_result[:2000]}\n\nDirs: {dirs}"},
        ])

        for finding in result.get("findings", []):
            self.add_finding(f"Recon: {finding}", "info", finding, evidence=dns_result[:200])

        self.set_fact("recon_complete", True, confidence=0.9)
        self.set_fact("technologies", result.get("technologies", []), confidence=0.7)

        return result
