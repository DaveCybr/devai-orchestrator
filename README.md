<div align="center">
  <img src="https://img.shields.io/badge/version-0.1.0-cyan?style=for-the-badge&labelColor=111" />
  <img src="https://img.shields.io/badge/python-3.11%2B-blue?style=for-the-badge&labelColor=111" />
  <img src="https://img.shields.io/badge/agents-10-green?style=for-the-badge&labelColor=111" />
  <img src="https://img.shields.io/badge/validators-6-yellow?style=for-the-badge&labelColor=111" />
  <img src="https://img.shields.io/badge/license-MIT-red?style=for-the-badge&labelColor=111" />
</div>

<br />

```ascii
       __                _
  ____/ /__ _   ______ _(_)
 / __  / _ \ | / / __ `/ /
/ /_/ /  __/ |/ / /_/ / /
\__,_/\___/|___/\__,_/_/

    v0.1.0  |  >> AI-Powered Autonomous Hacking Framework <<
    Agents: 10 | Skills: 6 | Validators: 6
```

<div align="center">
  <strong>devai</strong> — Multi-Agent Pentesting Orchestrator.<br />
  10 specialized agents, 6 deterministic validators, 6 exploit chain patterns.<br />
  OODA decision loop. No hallucination. Real payloads.
</div>

<br />

---

## Overview

**devai** combines 10 autonomous agents with deterministic validation in an OODA (Observe-Orient-Decide-Act) loop. Each agent is short-lived and single-purpose — recon, SAST, DAST, SQLi, XSS, SSRF, RCE, LFI, IDOR, File Upload.

```
                     +-----------+
                     |  TARGET   |
                     +-----+-----+
                           |
               +-----------v-----------+
               |   1. RECON AGENTS     |
               |  recon / sast / dast  |
               +-----------+-----------+
                           |
               +-----------v-----------+
               |   2. COORDINATOR      |
               |  OODA decision loop   |
               +-----------+-----------+
                           |
          +----------------v----------------+
          |       3. EXPLOIT AGENTS         |
          |  sqli / xss / ssrf / rce / lfi |
          |         idor / upload           |
          +----------------+----------------+
                           |
          +----------------v----------------+
          |   4. VALIDATOR GATE             |
          |  6 deterministic validators     |
          |  (NO LLM — pure code)           |
          +----------------+----------------+
                           |
          +----------------v----------------+
          |   5. EVIDENCE GATE              |
          |  PoC capture / request log      |
          +----------------+----------------+
                           |
          +----------------v----------------+
          |   6. CHAIN PLANNER              |
          |  6 chain patterns (LFI->RCE,    |
          |  SQLi->RCE, SSRF->Cloud, etc)   |
          +----------------+----------------+
                           |
          +----------------v----------------+
          |   7. REPORT AGENT               |
          |  CVSS 3.1 / Markdown + JSON     |
          +---------------------------------+
```

---

## Architecture

### Agents (10)

| Agent | Phase | Role |
|---|---|---|
| `recon` | Recon | DNS, HTTP probe, directory enum |
| `sast` | Recon | Static source code analysis |
| `dast` | Recon | Dynamic probing with payloads |
| `exploit_sqli` | Exploit | Error / time / union-based SQLi |
| `exploit_xss` | Exploit | Reflected / stored / DOM XSS |
| `exploit_ssrf` | Exploit | Cloud metadata / internal / OOB SSRF |
| `exploit_rce` | Exploit | Command injection / error-based RCE |
| `exploit_lfi` | Exploit | Path traversal / PHP filter |
| `exploit_idor` | Exploit | Horizontal / vertical IDOR |
| `exploit_upload` | Exploit | Webshell / polyglot / htaccess upload |

### Validators (6) — Deterministic, No LLM

| Validator | Technique |
|---|---|
| `sqli` | Error regex, time delay, UNION patterns |
| `xss` | Payload reflection, attribute break, DOM markers |
| `ssrf` | Cloud metadata, internal banners, OOB callback |
| `rce` | Command output (`uid=`, `root:`) |
| `lfi` | File markers (`root:x:0:0`), error disclosure |
| `idor` | Response diff, mass assignment detection |

### Chain Patterns (6)

| Pattern | Chain | CVSS Boost |
|---|---|---|
| LFI -> RCE (log poisoning) | `lfi` + `rce` | +3.0 |
| SQLi -> RCE (into outfile) | `sqli` + `rce` | +3.0 |
| File Upload -> RCE | `file_upload` + `rce` | +3.0 |
| SSRF -> Internal Service | `ssrf` + `idor` | +3.0 |
| IDOR -> Account Takeover | `idor` + `xss` | +3.0 |
| SSRF -> Cloud Metadata -> IAM | `ssrf` + `idor` | +4.5 |

---

## Quick Start

### Installation

```bash
git clone https://github.com/DaveCybr/devai-orchestrator.git
cd devai-orchestrator
pip install -r requirements.txt
```

### Usage

```bash
# List available agents
python overseer.py -l

# List attack skills
python overseer.py -s

# Run full scan (deterministic mode — no API key needed)
python overseer.py https://target.com

# Run with LLM (DeepSeek / OpenAI / Anthropic)
DEEPSEEK_API_KEY="sk-..." python overseer.py https://target.com
```

Or via the `devai` command (after adding `devai.cmd` to PATH):

```bash
devai https://target.com
```

### API Key Prompt

If no API key is detected, you'll be prompted interactively:

```
  [!] No LLM API key detected

  Choose provider:
    1. DeepSeek (DEEPSEEK_API_KEY)
    2. OpenAI   (OPENAI_API_KEY)
    3. Anthropic (ANTHROPIC_API_KEY)
    Enter = exit

  > 3
  Enter your ANTHROPIC_API_KEY: sk-ant-****
```

The key is validated with a real API call before the scan begins.

---

## File Structure

```
devai-orchestrator/
├── overseer.py                  # Entry point
├── devai.cmd                    # Windows launcher
├── config/
│   └── default.yaml             # Framework configuration
├── src/
│   ├── cli/
│   │   ├── main.py              # CLI entry, provider menu
│   │   ├── banner.py            # ASCII banner (pyfiglet)
│   │   └── colors.py            # Color output functions
│   ├── core/
│   │   ├── orchestrator.py      # Main orchestrator
│   │   ├── coordinator.py       # OODA decision loop
│   │   ├── session.py           # Session pipeline
│   │   ├── blackboard.py        # Shared state
│   │   ├── llm.py               # LLM client (DeepSeek/OpenAI/Anthropic)
│   │   ├── chain_planner.py     # Exploit chain patterns
│   │   ├── evidence_gate.py     # PoC capture & evidence
│   │   ├── report.py            # Report generator (MD + JSON)
│   │   ├── registry.py          # Agent registry
│   │   ├── agent_base.py        # Base agent class
│   │   ├── validator.py         # Validator dispatch
│   │   └── validators/
│   │       ├── sqli.py          # SQLi validator
│   │       ├── xss.py           # XSS validator
│   │       ├── ssrf.py          # SSRF validator
│   │       ├── rce.py           # RCE validator
│   │       ├── lfi.py           # LFI validator
│   │       └── idor.py          # IDOR validator
│   ├── agents/
│   │   ├── recon/
│   │   │   ├── recon_agent.py   # Recon agent
│   │   │   ├── sast_agent.py    # SAST agent
│   │   │   └── dast_agent.py    # DAST agent
│   │   └── exploit/
│   │       ├── sqli_agent.py    # SQLi exploitation
│   │       ├── xss_agent.py     # XSS exploitation
│   │       ├── ssrf_agent.py    # SSRF exploitation
│   │       ├── rce_agent.py     # RCE exploitation
│   │       ├── lfi_agent.py     # LFI exploitation
│   │       ├── idor_agent.py    # IDOR exploitation
│   │       └── upload_agent.py  # File upload exploitation
│   ├── skills/                  # YAML skill definitions (6)
│   ├── tools/
│   │   └── registry.py          # Tool registry (HTTP, DNS, Python exec)
│   └── sandbox/
│       └── manager.py           # Docker sandbox manager
├── requirements.txt
├── AGENTS.md                    # Project memory
└── USAGE.md                     # Usage documentation
```

---

## Deterministic Mode vs LLM Mode

| Feature | Deterministic | LLM (DeepSeek/OpenAI/Anthropic) |
|---|---|---|
| API Key | Not required | Required |
| Coordinator | Sequential dispatch | OODA decision loop |
| Recon analysis | Basic HTTP + DNS | LLM-powered analysis |
| Payload selection | Predefined lists | LLM-guided generation |
| Report | Structured only | Structured + narrative |
| Speed | Fast | Slower (API calls) |

---

## Screenshots

### Provider Selection
```
  =======================
  |  SELECT LLM PROVIDER  |
  =======================
  Choose your AI provider for this session

    1  DeepSeek       (DEEPSEEK_API_KEY)
    2  OpenAI         (OPENAI_API_KEY)
    3  Anthropic      (ANTHROPIC_API_KEY)
    0  Exit

```

### Session Progress
```
  =====================
  |  OVERSEER SESSION  |
  =====================
  Session ID:  a3f8c1e2
  Target:     https://target.com
  Pipeline:   Validate -> Evidence Gate -> Report

  [+] Starting reconnaissance module...
  [+] Subdomains discovered: 3
  [+] Endpoints discovered: 47
  [!] Potential SQLi endpoints: 2
  [+] XSS validation failed on /search
  [+] SSRF confirmed! PoC ready.
```

### Report Summary
```
  ====================
  |  REPORT SUMMARY  |
  ====================
  Total Findings:  3
  Critical:        1
  High:            2
  Medium:          0

  [+] Report generated: report_target_2026-06-30.html
```

---

## Requirements

- Python 3.11+
- Windows / Linux / macOS
- Docker (optional, for sandbox mode)

### Dependencies

```
pyfiglet
termcolor
colorama
```

---

## License

MIT

---

<div align="center">
  <sub>Built with Python + asyncio + pyfiglet + colorama</sub>
</div>
