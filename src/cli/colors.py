from __future__ import annotations

import sys
from colorama import init, Fore, Back, Style

init(autoreset=True)


def info(msg: str) -> None:
    print(f"  {Fore.GREEN}{Style.BRIGHT}[+]{Style.RESET_ALL} {msg}")


def warning(msg: str) -> None:
    print(f"  {Fore.YELLOW}{Style.BRIGHT}[!]{Style.RESET_ALL} {msg}")


def error(msg: str) -> None:
    print(f"  {Fore.RED}{Style.BRIGHT}[-]{Style.RESET_ALL} {msg}")


def target(msg: str) -> None:
    print(f"  {Fore.CYAN}{Style.BRIGHT}[*]{Style.RESET_ALL} {msg}")


def success(msg: str) -> None:
    print(f"  {Fore.GREEN}{Style.BRIGHT}[+]{Style.RESET_ALL} {msg}")


def fail(msg: str) -> None:
    print(f"  {Fore.RED}{Style.BRIGHT}[-]{Style.RESET_ALL} {msg}")


def separator() -> None:
    print(f"  {Style.DIM}{'-' * 60}{Style.RESET_ALL}")


def header(msg: str) -> None:
    pad = len(msg) + 4
    print(f"\n  {Fore.CYAN}{'=' * pad}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}|{Style.RESET_ALL}  {Fore.CYAN}{Style.BRIGHT}{msg}{Style.RESET_ALL}  {Fore.CYAN}|{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}{'=' * pad}{Style.RESET_ALL}")
