from __future__ import annotations

import asyncio
import os
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from colorama import Fore, Back, Style
from src.cli.banner import show_banner
from src.cli.colors import *


def select_provider():
    header("SELECT LLM PROVIDER")
    print(f"  {Style.DIM}Choose your AI provider for this session{Style.RESET_ALL}\n")
    print(f"    {Fore.GREEN}{Style.BRIGHT}1{Style.RESET_ALL}  {Fore.GREEN}DeepSeek{Style.RESET_ALL}       ({Fore.CYAN}DEEPSEEK_API_KEY{Style.RESET_ALL})")
    print(f"    {Fore.BLUE}{Style.BRIGHT}2{Style.RESET_ALL}  {Fore.BLUE}OpenAI{Style.RESET_ALL}         ({Fore.CYAN}OPENAI_API_KEY{Style.RESET_ALL})")
    print(f"    {Fore.MAGENTA}{Style.BRIGHT}3{Style.RESET_ALL}  {Fore.MAGENTA}Anthropic{Style.RESET_ALL}      ({Fore.CYAN}ANTHROPIC_API_KEY{Style.RESET_ALL})")
    print(f"    {Fore.RED}{Style.BRIGHT}0{Style.RESET_ALL}  {Fore.RED}Exit{Style.RESET_ALL}\n")

    provider_map = {
        "1": ("DeepSeek", "DEEPSEEK_API_KEY"),
        "2": ("OpenAI", "OPENAI_API_KEY"),
        "3": ("Anthropic", "ANTHROPIC_API_KEY"),
    }

    while True:
        try:
            choice = input(f"  {Fore.CYAN}{Style.BRIGHT}> {Style.RESET_ALL}").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            warning("Exiting.")
            sys.exit(0)

        if choice == "0":
            warning("Exiting.")
            sys.exit(0)

        if choice not in provider_map:
            error("Invalid choice. Select 1, 2, 3, or 0.")
            continue

        name, env_key = provider_map[choice]

        while True:
            key = input(f"  {Fore.CYAN}Enter your {Style.BRIGHT}{env_key}{Style.RESET_ALL}{Fore.CYAN}: {Style.RESET_ALL}").strip()
            if key:
                break
            error("API key cannot be empty.")

        os.environ[env_key] = key
        success(f"{name} API key set successfully.")
        return env_key


async def validate_key(env_key: str) -> bool:
    info("Testing API connection...")
    from src.core.llm import LLMClient

    config = {
        "llm": {
            "primary": {"provider": "deepseek", "model": "deepseek-chat", "api_key_env": "DEEPSEEK_API_KEY", "base_url": "https://api.deepseek.com", "temperature": 0.3, "max_tokens": 8192},
            "fallback": [
                {"provider": "openai", "model": "gpt-4o", "api_key_env": "OPENAI_API_KEY"},
                {"provider": "anthropic", "model": "claude-sonnet-4-20250514", "api_key_env": "ANTHROPIC_API_KEY"},
            ],
        },
    }
    llm = LLMClient(config["llm"])
    result = await llm.test_connection()
    if result == "ok":
        success("Connection established. Using LLM mode.")
        return True
    else:
        fail(f"Connection failed: {result}")
        return False


async def simulate_session(target: str):
    header("OVERSEER SESSION")

    session_id = uuid.uuid4().hex[:8]
    print(f"  {Fore.CYAN}{Style.BRIGHT}Session ID:{Style.RESET_ALL}  {Fore.CYAN}{session_id}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}{Style.BRIGHT}Target:{Style.RESET_ALL}     {Fore.CYAN}{target}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}{Style.BRIGHT}Pipeline:{Style.RESET_ALL}   {Fore.CYAN}Validate -> Evidence Gate -> Report{Style.RESET_ALL}")
    separator()
    print()

    info("Starting reconnaissance module...")
    await asyncio.sleep(0.8)
    success("Subdomains discovered: 3")
    await asyncio.sleep(0.4)
    success("Endpoints discovered: 47")
    await asyncio.sleep(0.5)
    warning("Potential SQLi endpoints: 2")
    await asyncio.sleep(0.3)
    target("Scanning http://target.com/admin")
    await asyncio.sleep(0.6)
    info("Testing XSS payloads...")
    await asyncio.sleep(0.4)
    fail("XSS validation failed on /search")
    await asyncio.sleep(0.3)
    info("Testing SSRF payloads...")
    await asyncio.sleep(0.5)
    success("SSRF confirmed! PoC ready.")
    await asyncio.sleep(0.3)
    info("Testing LFI payloads...")
    await asyncio.sleep(0.4)
    success("LFI confirmed on /download.php?file=")
    await asyncio.sleep(0.3)
    warning("RCE blocked by WAF on /ping")
    await asyncio.sleep(0.2)
    info("Testing race conditions...")
    await asyncio.sleep(0.4)
    success("Race condition found on coupon endpoint")
    await asyncio.sleep(0.3)
    separator()
    print()


def show_report():
    header("REPORT SUMMARY")
    print(f"  {Fore.WHITE}{Style.BRIGHT}{'Total Findings:':<20}{Style.RESET_ALL} {Fore.YELLOW}{Style.BRIGHT}3{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}{Style.BRIGHT}{'Critical:':<20}{Style.RESET_ALL} {Fore.RED}{Style.BRIGHT}1{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}{Style.BRIGHT}{'High:':<20}{Style.RESET_ALL} {Fore.YELLOW}{Style.BRIGHT}2{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}{Style.BRIGHT}{'Medium:':<20}{Style.RESET_ALL} {Fore.BLUE}{Style.BRIGHT}0{Style.RESET_ALL}")
    separator()
    success("Report generated: report_target_2026-06-30.html")
    print()


async def main():
    show_banner()

    env_key = select_provider()
    valid = await validate_key(env_key)

    if not valid:
        error("Exiting due to invalid API key.")
        sys.exit(1)

    target_url = "https://target.com"
    await simulate_session(target_url)
    show_report()

    success("Session complete.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, asyncio.CancelledError):
        print()
        warning("Interrupted by user.")
        sys.exit(0)
