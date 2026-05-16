"""Main orchestration: coordinates scan → classify → enumerate → report flow."""

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .modules.ad import run_ad
from .modules.ftp import run_ftp
from .modules.http import run_http
from .modules.smb import run_smb
from .modules.ssh import run_ssh
from .reporter import generate
from .scanner import _hosts_path, deep_scan, get_hosts_entries, identify_services, probe_http_redirects, save_hosts_entries, scan_ports
from .utils import Result


def run(
    target: str,
    username: str | None = None,
    password: str | None = None,
    domain: str | None = None,
    dry_run: bool = False,
) -> int:
    """Main entry point. Returns exit code."""
    start_time = time.monotonic()
    out_dir = os.path.join("results", target)
    os.makedirs(out_dir, exist_ok=True)

    # ---- Phase 1: rustscan ----
    print(f"\n[*] rustscan scanning {target} (0-65535)...")
    ports, rustscan_path = scan_ports(target, dry_run, out_dir)

    if not dry_run and not ports:
        print("[!] No open ports found.")
        return 1

    print(f"[+] Found {len(ports)} open ports: {', '.join(map(str, ports))}")

    # ---- Phase 2: nmap deep scan ----
    print("\n[*] nmap deep scan...")
    services, nmap_xml = deep_scan(target, ports, dry_run, out_dir)

    if not dry_run and not services:
        print("[!] No services identified.")
        return 2

    # Identify service types
    classified = identify_services(services)
    http_ports = classified.get("http", [])
    smb_ports = classified.get("smb", [])
    ftp_ports = classified.get("ftp", [])
    ssh_ports = classified.get("ssh", [])
    ad_detected = bool(classified.get("ad")) or bool(services.get(88)) or bool(services.get(389))

    if services.get(443):
        http_ports = list(set(http_ports + [443]))

    service_labels = []
    if http_ports:
        service_labels.append(f"HTTP({','.join(map(str, http_ports))})")
    if ssh_ports:
        service_labels.append(f"SSH({','.join(map(str, ssh_ports))})")
    if smb_ports:
        service_labels.append(f"SMB({','.join(map(str, smb_ports))})")
    if ftp_ports:
        service_labels.append(f"FTP({','.join(map(str, ftp_ports))})")
    if ad_detected:
        service_labels.append("AD")

    print(f"[+] Identified: {'  '.join(service_labels)}")

    # ---- Phase 2.5: Domain discovery + hosts entries ----
    http_hostnames: set[str] = set()
    if not dry_run and http_ports:
        redirect_domains = probe_http_redirects(target, http_ports)
        if redirect_domains:
            for domain_name, hostname_set in redirect_domains.items():
                http_hostnames.update(hostname_set)
                if not domain:
                    domain = domain_name
                    print(f"[+] Auto-detected domain: {domain}")
                    if hostname_set:
                        print(f"    hostnames: {', '.join(sorted(hostname_set))}")

    # Collect hosts entries from nmap + HTTP redirects
    hosts_entries = get_hosts_entries(target, services, http_hostnames if http_hostnames else None)
    if hosts_entries:
        print(f"\n[!] Found {len(hosts_entries)} hostname(s) that may need hosts file entries:")
        hosts_path = _hosts_path()
        for hostname, reason in hosts_entries:
            print(f"    {target}\t{hostname}\t# {reason}")
        print(f"    → saved to results/{target}/scan/hosts_entries.txt")
        print(f"    → add to {hosts_path} with: sudo nano {hosts_path}")
        save_hosts_entries(target, hosts_entries, os.path.join(out_dir, "scan"))

    if dry_run:
        print("")

    # ---- Phase 3: Concurrent enumeration ----
    task_count = 0
    if http_ports:
        task_count += len(http_ports) * 4  # gobuster, nikto, whatweb, ffuf-vhost
    if smb_ports:
        task_count += 2  # enum4linux, smbclient
    if ftp_ports:
        task_count += len(ftp_ports)
    if ssh_ports:
        task_count += len(ssh_ports)
    if ad_detected:
        task_count += 5  # anonymous modules
        if username and password:
            task_count += 3  # authenticated modules

    print(f"\n[*] Starting enumeration ({task_count} tasks)...\n")

    all_results: dict[str, list[Result]] = {}
    progress_info: dict[str, str] = {}  # label → status

    def progress_callback(label: str, result: Result | None = None, saved: str | None = None, message: str | None = None):
        """Update progress display."""
        if message:
            print(f"  [!] {label}: {message}")
            return
        if result:
            status = "done" if result.success else "failed"
            elapsed_str = f"{result.elapsed:.0f}s"
            bar = "=" * _bar_width(result.elapsed, result.tool)
            print(f"  {label:<20} [{bar:20}] {status:<7} ({elapsed_str})")

    # Launch modules concurrently
    with ThreadPoolExecutor(max_workers=4) as executor:
        module_futures = {}
        labels = {}
        if http_ports:
            f = executor.submit(run_http, target, http_ports, dry_run, out_dir, domain, progress_callback)
            module_futures[f] = "web"
        if smb_ports:
            f = executor.submit(run_smb, target, smb_ports, username, password, dry_run, out_dir, progress_callback)
            module_futures[f] = "smb"
        if ftp_ports:
            f = executor.submit(run_ftp, target, ftp_ports, dry_run, out_dir, progress_callback)
            module_futures[f] = "ftp"
        if ssh_ports:
            f = executor.submit(run_ssh, target, ssh_ports, dry_run, out_dir, progress_callback)
            module_futures[f] = "ssh"
        if ad_detected:
            f = executor.submit(run_ad, target, services, username, password, domain, dry_run, out_dir, progress_callback)
            module_futures[f] = "ad"

        for future in as_completed(module_futures):
            category = module_futures[future]
            try:
                results = future.result()
                all_results[category] = results
            except Exception as e:
                print(f"  [!] {category} module error: {e}")
                all_results[category] = []

    # ---- Phase 4: Generate report ----
    elapsed = time.monotonic() - start_time
    report_path = generate(target, out_dir, services, all_results, elapsed)

    print(f"\n[+] Done. Report: {report_path}")
    return 0


def _bar_width(elapsed: float, tool: str) -> int:
    """Calculate progress bar width based on elapsed vs timeout."""
    if tool == "gobuster":
        max_t = 600
    else:
        max_t = 300
    return min(max(int(elapsed / max_t * 20), 1), 20)
