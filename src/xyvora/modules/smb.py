"""SMB enumeration: enum4linux, smbclient."""

import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..utils import DEFAULT_TIMEOUT, Result, run_cmd, save_result


def run_smb(target: str, ports: list[int], username: str | None, password: str | None, dry_run: bool, out_dir: str, progress_callback=None) -> list[Result]:
    """Run SMB enumeration tools."""
    results = []
    smb_dir = os.path.join(out_dir, "smb")

    if dry_run:
        print("[DRY-RUN] enum4linux -a " + target)
        print(f"[DRY-RUN] smbclient -L \\\\{target}\\")
        return results

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {}
        futures[executor.submit(_run_enum4linux, target)] = "enum4linux"
        futures[executor.submit(_run_smbclient_list, target, username, password)] = "smbclient"

        for future in as_completed(futures):
            label = futures[future]
            result = future.result()
            if progress_callback:
                progress_callback(label, result)
            results.append(result)
            save_result(result, smb_dir)

    return results


def _run_enum4linux(target: str) -> Result:
    cmd = ["enum4linux", "-a", target]
    result = run_cmd(cmd, timeout=DEFAULT_TIMEOUT)
    result.tool = "enum4linux"
    return result


def _run_smbclient_list(target: str, username: str | None, password: str | None) -> Result:
    cmd = ["smbclient", "-L", f"\\\\{target}\\", "-N"]
    if username:
        cmd = ["smbclient", "-L", f"\\\\{target}\\", "-U", f"{username}%{password or ''}"]
    result = run_cmd(cmd, timeout=DEFAULT_TIMEOUT)
    result.tool = "smbclient"
    return result
