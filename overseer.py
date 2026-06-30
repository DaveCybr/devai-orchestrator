"""Launcher — just runs src.cli.main."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.cli.main import main

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
