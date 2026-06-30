from __future__ import annotations

import json
import os
from typing import Any

import httpx


class LLMClient:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        self._client = httpx.AsyncClient(timeout=120)

    @staticmethod
    def _get_api_key(env_var: str) -> str:
        return os.environ.get(env_var, "")

    async def _call_deepseek(self, messages: list[dict], temperature: float = 0.3, max_tokens: int = 8192) -> dict:
        cfg = self.config["primary"]
        api_key = self._get_api_key(cfg["api_key_env"])
        if not api_key:
            raise ValueError(f"Missing {cfg['api_key_env']} environment variable")
        resp = await self._client.post(
            f"{cfg['base_url']}/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": cfg["model"],
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            },
        )
        resp.raise_for_status()
        return resp.json()

    async def _call_openai(self, messages: list[dict], temperature: float = 0.3, max_tokens: int = 8192) -> dict:
        api_key = self._get_api_key("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("Missing OPENAI_API_KEY environment variable")
        resp = await self._client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": "gpt-4o",
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            },
        )
        resp.raise_for_status()
        return resp.json()

    async def _call_anthropic(self, messages: list[dict], temperature: float = 0.3, max_tokens: int = 8192) -> dict:
        api_key = self._get_api_key("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("Missing ANTHROPIC_API_KEY environment variable")
        system = ""
        filtered = []
        for m in messages:
            if m["role"] == "system":
                system += m["content"] + "\n"
            else:
                filtered.append(m)
        resp = await self._client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-20250514",
                "system": system.strip(),
                "messages": filtered,
                "max_tokens": max_tokens,
                "temperature": temperature,
            },
        )
        resp.raise_for_status()
        return resp.json()

    async def chat(self, messages: list[dict], temperature: float | None = None, max_tokens: int | None = None) -> str:
        if not self.is_available():
            return "{}"
        cfg = self.config["primary"]
        temp = temperature if temperature is not None else cfg.get("temperature", 0.3)
        mt = max_tokens if max_tokens is not None else cfg.get("max_tokens", 8192)
        provider = cfg["provider"]
        errors = []
        for attempt in range(2):
            try:
                if provider == "deepseek":
                    data = await self._call_deepseek(messages, temp, mt)
                    return data["choices"][0]["message"]["content"]
                elif provider == "openai":
                    data = await self._call_openai(messages, temp, mt)
                    return data["choices"][0]["message"]["content"]
                elif provider == "anthropic":
                    data = await self._call_anthropic(messages, temp, mt)
                    return data["content"][0]["text"]
            except Exception as e:
                errors.append(f"{provider}: {e}")
                if attempt == 0:
                    # Try fallback providers
                    for fallback in self.config.get("fallback", []):
                        try:
                            provider = fallback["provider"]
                            if provider == "openai":
                                data = await self._call_openai(messages, temp, mt)
                                return data["choices"][0]["message"]["content"]
                            elif provider == "anthropic":
                                data = await self._call_anthropic(messages, temp, mt)
                                return data["content"][0]["text"]
                        except Exception as e2:
                            errors.append(f"{fallback['provider']}: {e2}")
                            continue
        raise RuntimeError(f"All LLM providers failed: {'; '.join(errors)}")

    async def chat_json(self, messages: list[dict], temperature: float | None = None) -> dict:
        if not self.is_available():
            return {}
        result = await self.chat(messages, temperature=temperature or 0.1, max_tokens=4096)
        cleaned = result.strip()
        if cleaned.startswith("```"):
            lines = cleaned.splitlines()
            cleaned = "\n".join(lines[1:-1]) if len(lines) > 2 else lines[-1]
        return json.loads(cleaned)

    def is_available(self) -> bool:
        cfg = self.config["primary"]
        if self._get_api_key(cfg["api_key_env"]):
            return True
        for fb in self.config.get("fallback", []):
            if self._get_api_key(fb["api_key_env"]):
                return True
        return False

    async def test_connection(self) -> str:
        cfg = self.config["primary"]
        api_key = self._get_api_key(cfg["api_key_env"])
        provider = cfg["provider"]

        if not api_key:
            for fb in self.config.get("fallback", []):
                api_key = self._get_api_key(fb["api_key_env"])
                if api_key:
                    provider = fb["provider"]
                    break

        if not api_key:
            return "No API key found"

        try:
            if provider == "deepseek":
                data = await self._call_deepseek(
                    [{"role": "user", "content": "hello"}],
                    temperature=0.1, max_tokens=1,
                )
                return "ok"
            elif provider == "openai":
                data = await self._call_openai(
                    [{"role": "user", "content": "hello"}],
                    temperature=0.1, max_tokens=1,
                )
                return "ok"
            elif provider == "anthropic":
                data = await self._call_anthropic(
                    [{"role": "user", "content": "hello"}],
                    temperature=0.1, max_tokens=1,
                )
                return "ok"
        except Exception as e:
            return str(e)

        return "Unknown provider"

    async def close(self):
        await self._client.aclose()
