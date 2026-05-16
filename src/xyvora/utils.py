"""Shared utilities: subprocess execution, progress display, timeouts."""

import os
import shlex
import subprocess
import time

# Default configs
DIRBUSTER_MEDIUM = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
KERBRUTE_USERLIST = "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"
FFUF_VHOST_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
GOBUSTER_TIMEOUT = 600   # 10 minutes
DEFAULT_TIMEOUT = 300    # 5 minutes


class Result:
    """Result of running an external tool."""

    def __init__(self, tool: str, port: int = 0):
        self.tool = tool
        self.port = port
        self.stdout = ""
        self.stderr = ""
        self.success = False
        self.elapsed = 0.0

    @property
    def has_output(self) -> bool:
        return bool(self.stdout.strip())

    @property
    def label(self) -> str:
        return f"{self.tool}:{self.port}" if self.port else self.tool


def run_cmd(cmd: list[str], timeout: int = DEFAULT_TIMEOUT, env: dict[str, str] | None = None) -> Result:
    """Run an external command with timeout. Returns Result."""
    result = Result(cmd[0])

    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)

    start = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=merged_env,
        )
        result.stdout = proc.stdout
        result.stderr = proc.stderr
        result.success = proc.returncode == 0
    except subprocess.TimeoutExpired:
        result.stderr = f"Timeout after {timeout}s"
    except FileNotFoundError:
        result.stderr = f"Tool not found: {cmd[0]}"
    result.elapsed = time.monotonic() - start
    return result


def cmd_to_str(cmd: list[str]) -> str:
    """Format a command list into a shell-quoted string."""
    return " ".join(shlex.quote(c) for c in cmd)


def save_result(result: Result, out_dir: str) -> str | None:
    """Save result output to file. Returns path or None if empty."""
    if not result.has_output:
        return None
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"{result.label.replace(':', '_')}.txt")
    with open(path, "w", encoding="utf-8", errors="replace") as f:
        f.write(result.stdout)
    return path
