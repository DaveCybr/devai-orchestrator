OVerseer — Multi-Agent Pentesting Orchestrator

Usage:
  python -m src.cli.main <target> [options]

Arguments:
  target            Target URL, IP, or hostname (optional with -l/-s)

Options:
  -c, --config      Path to YAML config file (default: config/default.yaml)
  -l, --list-agents Show available agents and exit
  -s, --list-skills Show loaded attack skills and exit

Examples:
  # List agents
  python -m src.cli.main -l

  # List skills
  python -m src.cli.main -s

  # Full scan
  python -m src.cli.main http://target.com

  # With custom config
  python -m src.cli.main http://target.com -c myconfig.yaml

Output:
  ./workspace/
  ├── evidence/       # JSON evidence packages (per finding)
  ├── reports/        # report_{timestamp}.md + .json
  ├── state/          # Blackboard session state
  └── poc_all.sh      # All PoC commands in one script

Pipeline:
  Coordinator → Agent → Validator → Evidence Gate → Chain Planner → Report
