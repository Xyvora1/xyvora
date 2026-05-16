"""HTTP/HTTPS enumeration: gobuster, nikto, whatweb."""

import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..utils import (
    DEFAULT_TIMEOUT,
    DIRBUSTER_MEDIUM,
    GOBUSTER_TIMEOUT,
    Result,
    run_cmd,
    save_result,
)


def run_http(target: str, ports: list[int], dry_run: bool, out_dir: str, progress_callback=None) -> list[Result]:
    """Run HTTP enumeration on all detected web ports concurrently."""
    results = []
    tasks = []
    for port in ports:
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{target}:{port}"
        tasks.append((port, url))

    web_dir = os.path.join(out_dir, "web")

    if dry_run:
        for _port, url in tasks:
            print(f"[DRY-RUN] gobuster dir -u {url} -w {DIRBUSTER_MEDIUM}")
            print(f"[DRY-RUN] nikto -h {url}")
            print(f"[DRY-RUN] whatweb {url}")
        return results

    with ThreadPoolExecutor(max_workers=min(len(tasks) * 3, 10)) as executor:
        futures = {}
        for port, url in tasks:
            futures[executor.submit(_run_gobuster, url, port)] = f"gobuster:{port}"
            futures[executor.submit(_run_nikto, url, port)] = f"nikto:{port}"
            futures[executor.submit(_run_whatweb, url, port)] = f"whatweb:{port}"

        for future in as_completed(futures):
            label = futures[future]
            result = future.result()
            if progress_callback:
                progress_callback(label, result)
            results.append(result)
            # Only save if has output
            saved = save_result(result, web_dir)
            if saved and progress_callback:
                progress_callback(label, result, saved)

    return results


def _run_gobuster(url: str, port: int) -> Result:
    cmd = ["gobuster", "dir", "-u", url, "-w", DIRBUSTER_MEDIUM, "-q"]
    result = run_cmd(cmd, timeout=GOBUSTER_TIMEOUT)
    result.tool = "gobuster"
    result.port = port
    return result


def _run_nikto(url: str, port: int) -> Result:
    cmd = ["nikto", "-h", url, "-Tuning", "123456789"]
    result = run_cmd(cmd, timeout=DEFAULT_TIMEOUT)
    result.tool = "nikto"
    result.port = port
    return result


def _run_whatweb(url: str, port: int) -> Result:
    cmd = ["whatweb", url]
    result = run_cmd(cmd, timeout=DEFAULT_TIMEOUT)
    result.tool = "whatweb"
    result.port = port
    return result
