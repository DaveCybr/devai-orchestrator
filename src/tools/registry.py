from __future__ import annotations

import asyncio
import os
import re
import subprocess
import sys
import tempfile
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass


class ToolError(Exception):
    pass


class BaseTool:
    name: str = ""
    description: str = ""

    async def execute(self, **kwargs) -> str:
        raise NotImplementedError


class ToolRegistry:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        self._tools: dict[str, BaseTool] = {}
        self._register_builtins()

    def _register_builtins(self) -> None:
        self.register(HTTPFetchTool())
        self.register(ExecutePythonTool(self.config))
        self.register(DirEnumTool())
        self.register(DNSResolveTool())

    def register(self, tool: BaseTool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> BaseTool | None:
        return self._tools.get(name)

    def list_tools(self) -> list[str]:
        return list(self._tools.keys())

    async def execute(self, name: str, **kwargs) -> str:
        tool = self.get(name)
        if not tool:
            return f"[!] Tool '{name}' not found"
        try:
            return await tool.execute(**kwargs)
        except ToolError as e:
            return f"[!] Tool error: {e}"
        except Exception as e:
            return f"[!] Unexpected error: {e}"


class HTTPFetchTool(BaseTool):
    name = "http_fetch"
    description = "Fetch a URL and return response content"

    async def execute(self, url: str, method: str = "GET", headers: dict | None = None, data: str | None = None) -> str:
        import httpx
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                resp = await client.request(method, url, headers=headers, content=data)
                return f"Status: {resp.status_code}\n\n{resp.text[:10000]}"
        except Exception as e:
            return f"[!] HTTP error: {e}"


class ExecutePythonTool(BaseTool):
    name = "execute_python"
    description = "Execute Python code in a sandboxed environment"

    BLOCKED_PATTERNS = [
        r"os\.system",
        r"subprocess\.Popen",
        r"shutil\.rmtree",
        r"__import__",
    ]

    def __init__(self, config: dict[str, Any]):
        super().__init__()
        tool_cfg = config.get("tools", {}).get("local_exec", {})
        if tool_cfg.get("blocked_patterns"):
            self.BLOCKED_PATTERNS = tool_cfg["blocked_patterns"]
        self.max_lines = tool_cfg.get("max_lines", 200)
        self.allowed_imports = tool_cfg.get("allowed_imports", [])

    async def execute(self, code: str, purpose: str = "") -> str:
        if not code.strip():
            return "[!] Empty code"

        if code.count("\n") + 1 > self.max_lines:
            return f"[!] Code exceeds {self.max_lines} lines"

        for pattern in self.BLOCKED_PATTERNS:
            if re.search(pattern, code):
                return f"[!] Blocked pattern: {pattern}"

        tmp_path = ""
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
                f.write("import sys, json, re, base64, hashlib, itertools, collections\n")
                f.write(code)
                tmp_path = f.name

            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    [sys.executable, tmp_path],
                    capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=30,
                    cwd=tempfile.gettempdir(),
                ),
            )

            try:
                os.unlink(tmp_path)
            except OSError:
                pass

            output = ""
            if result.stdout:
                output += result.stdout
            if result.stderr:
                stderr = [l for l in result.stderr.splitlines() if "ImportError" not in l and "No module" not in l]
                if stderr:
                    output += "\n[stderr]\n" + "\n".join(stderr)
            return output or "[+] Executed with no output"

        except subprocess.TimeoutExpired:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            return "[!] Execution timed out"
        except Exception as e:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            return f"[!] Execution error: {e}"


class DirEnumTool(BaseTool):
    name = "dir_enum"
    description = "Enumerate directories/files on a web server"

    COMMON_PATHS = [
        "/admin", "/login", "/wp-admin", "/administrator",
        "/.env", "/.git/config", "/config", "/backup",
        "/api", "/v1", "/v2", "/graphql",
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/storage", "/uploads", "/files", "/download",
    ]

    async def execute(self, target: str, extra_paths: list[str] | None = None) -> str:
        import httpx, asyncio
        paths = self.COMMON_PATHS + (extra_paths or [])
        results = []
        connector = httpx.AsyncClient(timeout=5, follow_redirects=False)
        async with connector:
            tasks = []
            for path in paths:
                url = target.rstrip("/") + path
                tasks.append(self._check_path(connector, url))
            for coro in asyncio.as_completed(tasks):
                try:
                    r = await coro
                    if r:
                        results.append(r)
                except Exception:
                    pass
        return "\n".join(results) if results else "[!] No interesting paths found"

    async def _check_path(self, client, url: str) -> str | None:
        import httpx
        try:
            resp = await client.get(url)
            if resp.status_code in (200, 301, 302, 401, 403):
                return f"{url} -> {resp.status_code} ({len(resp.content)} bytes)"
        except Exception:
            pass
        return None


class DNSResolveTool(BaseTool):
    name = "dns_resolve"
    description = "Resolve a hostname to IP address"

    async def execute(self, hostname: str) -> str:
        import socket
        try:
            ips = set()
            for info in socket.getaddrinfo(hostname, None):
                ips.add(info[4][0])
            return f"{hostname} -> {', '.join(ips)}"
        except Exception as e:
            return f"[!] Resolution failed: {e}"
