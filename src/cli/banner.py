from __future__ import annotations

import os
import pyfiglet
from colorama import Fore, Back, Style


def show_banner():
    os.system("cls" if os.name == "nt" else "clear")

    ascii_banner = pyfiglet.figlet_format("devai", font="slant")

    for line in ascii_banner.rstrip("\n").split("\n"):
        print(f"  {Fore.GREEN}{line}{Style.RESET_ALL}")

    ver = f"{Fore.CYAN}{Style.BRIGHT}v0.1.0{Style.RESET_ALL}"
    tag = f"{Fore.WHITE}{Style.BRIGHT}>> AI-Powered Autonomous Hacking Framework <<{Style.RESET_ALL}"
    stats = f"{Fore.YELLOW}Agents: 10 | Skills: 6 | Validators: 6{Style.RESET_ALL}"

    print(f"\n    {ver}  |  {tag}")
    print(f"    {stats}\n")
