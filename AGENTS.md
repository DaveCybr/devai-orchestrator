# devai - Project Memory

## Core Architecture
- **Orchestrator**: `D:\hacktool\orchestrator\src\core\orchestrator.py` — 10 agents, 6 skills, 6 validators, 6 chain patterns
- **CLI**: 3 files — `colors.py` (8 color functions), `banner.py` (pyfiglet + colorama), `main.py` (menu + session + report)
- **Entry**: `devai.cmd` (batch), `overseer.py` (python)

## Key Features Built
1. **Deterministic mode** (no API key needed) — coordinator falls back to sequential agent dispatch
2. **API key validation** — real `test_connection()` call, loops until valid key or exit
3. **Ctrl+C handling** — `os._exit(0)`, no traceback, no "Terminate batch job" prompt
4. **Unicode fix** — all `→`/`✅`/`❌`/`⚡`/`║`/`═` replaced with ASCII for Windows cp1252 compat
5. **`BaseAgent.add_finding`** — passes `vuln_type` to blackboard correctly
6. **All agents return dict findings** — not string lists (sqli, xss, ssrf, rce, lfi, idor, upload, dast)
7. **LFI validator** — added missing `import re`
8. **All validators accept `**kwargs`** — for unknown parameter compatibility
9. **`fail_intent()`** — handles both `Intent` objects and dicts
10. **Session validation** — auto-fills `validation_args` from finding fields when not explicitly set

## Provider Support
| Provider | Env Var |
|---|---|
| DeepSeek | DEEPSEEK_API_KEY |
| OpenAI | OPENAI_API_KEY |
| Anthropic | ANTHROPIC_API_KEY |

## Files
- `src/cli/colors.py` — color output functions
- `src/cli/banner.py` — banner display
- `src/cli/main.py` — CLI entry, provider menu, session sim, report
- `src/core/coordinator.py` — OODA loop with deterministic fallback
- `src/core/llm.py` — LLM client with `test_connection()`, `is_available()`
- `src/core/session.py` — session pipeline
- `src/core/agent_base.py` — `add_finding()` passes `vuln_type`
- `src/core/validators/*.py` — 6 deterministic validators, all accept `**kwargs`
- `src/agents/recon/dast_agent.py` — returns dict findings
- `src/agents/exploit/*.py` — 7 exploit agents, all return dict findings
- `devai.cmd` — launcher
- `requirements.txt` — pyfiglet, termcolor, colorama
