"""FTP enumeration: anonymous login detection."""

import os

from ..utils import Result, save_result


def run_ftp(target: str, ports: list[int], dry_run: bool, out_dir: str, progress_callback=None) -> list[Result]:
    """Try anonymous FTP login on each FTP port."""
    results = []
    ftp_dir = os.path.join(out_dir, "ftp")

    for port in ports:
        if dry_run:
            print(f"[DRY-RUN] ftp -n {target} {port} (anonymous login test)")
            continue

        result = _try_anonymous(target, port)
        if progress_callback:
            progress_callback(f"ftp:{port}", result)
        results.append(result)
        save_result(result, ftp_dir)

    return results


def _try_anonymous(target: str, port: int) -> Result:
    """Test anonymous FTP using Python ftplib (no external tool needed)."""
    try:
        from ftplib import FTP
    except ImportError:
        return _try_anonymous_telnet(target, port)

    result = Result("ftp", port)
    try:
        ftp = FTP()
        ftp.connect(target, port, timeout=10)
        ftp.login("anonymous", "anonymous")
        listing = []
        ftp.retrlines("LIST", listing.append)
        ftp.quit()
        result.stdout = "\n".join(listing)
        result.success = True
    except Exception as e:
        result.stderr = str(e)
    return result


def _try_anonymous_telnet(target: str, port: int) -> Result:
    """Fallback: use ftp command if ftplib unavailable."""
    import subprocess
    result = Result("ftp", port)
    try:
        proc = subprocess.run(
            f'echo -e "user anonymous anonymous\\nls\\nquit" | ftp -n {target} {port}',
            shell=True, capture_output=True, text=True, timeout=15
        )
        result.stdout = proc.stdout
        result.stderr = proc.stderr
        result.success = "230" in proc.stdout or "Login successful" in proc.stdout.lower()
    except Exception as e:
        result.stderr = str(e)
    return result
