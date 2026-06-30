from __future__ import annotations

import json
import os
import subprocess
import tempfile
from typing import Any


class SandboxError(Exception):
    pass


class SandboxManager:
    def __init__(self, config: dict[str, Any]):
        self.config = config.get("sandbox", {})
        self._enabled = self.config.get("enabled", False)
        self._container_name: str | None = None

    async def execute_python(self, code: str, timeout: int = 60) -> str:
        if not self._enabled:
            return "[!] Sandbox disabled, skipping"

        docker_cfg = self.config.get("docker", {})
        image = docker_cfg.get("image", "python:3.11-slim")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
            f.write(code)
            script_path = f.name

        try:
            host_script = script_path
            container_script = f"/tmp/{os.path.basename(script_path)}"

            cap_drop = docker_cfg.get("cap_drop", ["ALL"])
            cap_add = docker_cfg.get("cap_add", [])
            mem_limit = docker_cfg.get("memory_limit", "512m")
            cpu_limit = docker_cfg.get("cpu_limit", 1.0)
            read_only = docker_cfg.get("read_only_rootfs", True)
            user = docker_cfg.get("user", "nobody")

            cmd = ["docker", "run", "--rm"]
            cmd.extend(["--network", "none"])
            cmd.extend(["-m", mem_limit])
            cmd.extend(["--cpus", str(cpu_limit)])
            cmd.extend(["--read-only" if read_only else ""])
            if user:
                cmd.extend(["-u", user])
            for cap in cap_drop:
                cmd.extend(["--cap-drop", cap])
            for cap in cap_add:
                cmd.extend(["--cap-add", cap])
            if docker_cfg.get("tmpfs"):
                for t in docker_cfg["tmpfs"]:
                    cmd.extend(["--tmpfs", t])
            cmd.extend(["-v", f"{host_script}:{container_script}:ro"])
            cmd.append(image)
            cmd.extend(["python", container_script])

            cmd = [c for c in cmd if c]

            result = subprocess.run(
                cmd, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=timeout,
            )

            output = ""
            if result.stdout:
                output += result.stdout
            if result.returncode != 0 and result.stderr:
                output += f"\n[exit code: {result.returncode}]\n" + result.stderr[:2000]
            return output or "[+] Executed with no output"

        except subprocess.TimeoutExpired:
            return f"[!] Execution timed out ({timeout}s)"
        except FileNotFoundError:
            return "[!] Docker not found. Install Docker or disable sandbox."
        except Exception as e:
            return f"[!] Sandbox error: {e}"
        finally:
            try:
                os.unlink(script_path)
            except OSError:
                pass

    async def run_tool(self, tool: str, args: list[str], timeout: int = 120) -> str:
        if not self._enabled:
            return "[!] Sandbox disabled, skipping"

        docker_cfg = self.config.get("docker", {})
        bind_path = self.config.get("tool_bind_path", "/usr/bin")

        cmd = ["docker", "run", "--rm", "--network", "none"]
        cmd.extend(["-v", f"{bind_path}:/tools:ro"])
        cmd.extend([docker_cfg.get("image", "python:3.11-slim")])
        cmd.extend([tool] + args)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=timeout,
            )
            output = result.stdout or result.stderr
            return output[:20000] if output else "[+] Tool ran with no output"
        except subprocess.TimeoutExpired:
            return f"[!] Tool timed out ({timeout}s)"
        except Exception as e:
            return f"[!] Tool error: {e}"
