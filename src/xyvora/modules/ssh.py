"""SSH enumeration: ssh-audit."""

import os

from ..utils import DEFAULT_TIMEOUT, Result, run_cmd, save_result


def run_ssh(target: str, ports: list[int], dry_run: bool, out_dir: str, progress_callback=None) -> list[Result]:
    """Run ssh-audit on each SSH port."""
    results = []
    ssh_dir = os.path.join(out_dir, "ssh")

    for port in ports:
        if dry_run:
            print(f"[DRY-RUN] ssh-audit {target}:{port}")
            continue

        result = _run_ssh_audit(target, port)
        if progress_callback:
            progress_callback(f"ssh-audit:{port}", result)
        results.append(result)
        save_result(result, ssh_dir)

    return results


def _run_ssh_audit(target: str, port: int) -> Result:
    cmd = ["ssh-audit", f"{target}:{port}"]
    result = run_cmd(cmd, timeout=DEFAULT_TIMEOUT)
    result.tool = "ssh-audit"
    result.port = port
    return result
