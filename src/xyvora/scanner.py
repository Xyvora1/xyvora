"""Port scanning: rustscan + nmap."""

import http.client
import os
import socket
import ssl
import urllib.parse
import xml.etree.ElementTree as ET

from .utils import (
    DEFAULT_TIMEOUT,
    Result,
    cmd_to_str,
    run_cmd,
)


def scan_ports(target: str, dry_run: bool, out_dir: str) -> tuple[list[int], str | None]:
    """Run rustscan on all ports, return open ports. Returns (ports, rustscan_path)."""
    cmd = ["rustscan", "-a", target, "--range", "0-65535", "-b", "2000", "--", "-sC", "-sV"]
    if dry_run:
        return [], f"DRY-RUN: {cmd_to_str(cmd)}"

    result = run_cmd(cmd, timeout=DEFAULT_TIMEOUT)
    if not result.success:
        return [], None

    # Parse open ports from rustscan output
    ports = []
    for line in result.stdout.splitlines():
        # rustscan format: "Open 10.10.10.1:22"
        if "Open" in line and ":" in line:
            try:
                port = int(line.split(":")[-1].strip())
                ports.append(port)
            except ValueError:
                pass

    # Save rustscan output
    save_result(result, os.path.join(out_dir, "scan", "rustscan.txt"))
    return sorted(ports), os.path.join(out_dir, "scan", "rustscan.txt")


def deep_scan(target: str, ports: list[int], dry_run: bool, out_dir: str) -> tuple[dict[int, dict], str | None]:
    """Run nmap -sC -sV on discovered ports. Returns ({port: service_info}, xml_path)."""
    if not ports:
        return {}, None

    port_list = ",".join(str(p) for p in ports)
    cmd = ["nmap", "-sC", "-sV", "-p", port_list, "-oA", "nmap_output", target]

    if dry_run:
        return {}, f"DRY-RUN: {cmd_to_str(cmd)}"

    result = run_cmd(cmd, timeout=DEFAULT_TIMEOUT * 2)
    if not result.success:
        return {}, None

    # Move nmap output files to correct location
    os.makedirs(os.path.join(out_dir, "scan"), exist_ok=True)
    for ext in ["xml", "nmap", "gnmap"]:
        src = f"nmap_output.{ext}"
        if os.path.exists(src):
            dst = os.path.join(out_dir, "scan", f"nmap.{ext}")
            os.replace(src, dst)

    # Parse nmap XML
    services = parse_nmap_xml(os.path.join(out_dir, "scan", "nmap.xml"))
    return services, os.path.join(out_dir, "scan", "nmap.xml")


def parse_nmap_xml(xml_path: str) -> dict[int, dict]:
    """Parse nmap XML output into service dict {port: {name, product, hostname}}."""
    services = {}
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for host in root.iter("host"):
            hostname_elem = host.find("hostnames/hostname")
            hostname = hostname_elem.get("name", "") if hostname_elem is not None else ""
            for port_elem in host.iter("port"):
                port = int(port_elem.get("portid", 0))
                svc = port_elem.find("service")
                if svc is not None:
                    services[port] = {
                        "name": svc.get("name", ""),
                        "product": svc.get("product", ""),
                        "version": svc.get("version", ""),
                        "hostname": hostname,
                    }
    except (ET.ParseError, FileNotFoundError):
        pass
    return services


def save_result(result: Result, path: str) -> str | None:
    """Save result to a specific file path. Returns path or None if empty."""
    if not result.has_output:
        return None
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", errors="replace") as f:
        f.write(result.stdout)
    return path


def probe_http_redirect(target: str, port: int, scheme: str = "http") -> str | None:
    """Quick HTTP probe to check for redirect Location header. Returns hostname if found."""
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(target, port, timeout=10, context=ctx)
        else:
            conn = http.client.HTTPConnection(target, port, timeout=10)
        conn.request("GET", "/")
        resp = conn.getresponse()
        # Read body to allow next request, but we only care about headers
        try:
            resp.read(8192)
        except Exception:
            pass
        conn.close()
        if resp.status in (301, 302, 307, 308):
            location = resp.getheader("Location", "")
            if location:
                parsed = urllib.parse.urlparse(location)
                if parsed.hostname and parsed.hostname != target:
                    return parsed.hostname
    except Exception:
        pass
    return None


def probe_http_redirects(target: str, http_ports: list[int]) -> dict[str, set[str]]:
    """Probe all HTTP ports for redirect domains.

    Returns {domain: {source_hostnames}} mapping.
    """
    found: dict[str, set[str]] = {}
    for port in http_ports:
        for scheme in ["http", "https"]:
            hostname = probe_http_redirect(target, port, scheme)
            if hostname:
                # Extract root domain from hostname
                parts = hostname.split(".")
                if len(parts) >= 2:
                    domain = ".".join(parts[-2:])  # e.g. helix.htb
                else:
                    domain = hostname
                found.setdefault(domain, set()).add(hostname)
                break  # Got result on first scheme attempt
    return found


def get_hosts_entries(
    target: str,
    services: dict[int, dict],
    extra_hostnames: set[str] | None = None,
) -> list[tuple[str, str]]:
    """Collect hostnames from nmap that may need /etc/hosts entries.

    Returns list of (hostname, reason) tuples.
    """
    hostnames: set[str] = set()
    for info in services.values():
        hn = info.get("hostname", "").strip()
        if hn and hn != target and hn != "localhost":
            hostnames.add(hn)
    if extra_hostnames:
        hostnames.update(extra_hostnames)

    if not hostnames:
        return []

    entries: list[tuple[str, str]] = []
    for hn in sorted(hostnames):
        try:
            resolved = socket.getaddrinfo(hn, None)
            ips = {addr[4][0] for addr in resolved}
            if target not in ips:
                entries.append((hn, f"resolves to {', '.join(sorted(ips))}, not {target}"))
            # If target is in ips, hostname already resolves correctly — skip
        except socket.gaierror:
            entries.append((hn, "no DNS record"))

    return entries


def save_hosts_entries(target: str, entries: list[tuple[str, str]], out_dir: str) -> str | None:
    """Save suggested hosts entries to file. Returns path or None."""
    if not entries:
        return None
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "hosts_entries.txt")
    lines = [
        f"# Suggested /etc/hosts entries for {target}",
        f"# {_hosts_path()}",
        "",
    ]
    for hostname, reason in entries:
        lines.append(f"{target}\t{hostname}\t# {reason}")
    with open(path, "w", encoding="utf-8", errors="replace") as f:
        f.write("\n".join(lines) + "\n")
    return path


def _hosts_path() -> str:
    if os.name == "nt":
        return r"C:\Windows\System32\drivers\etc\hosts"
    return "/etc/hosts"


def identify_services(services: dict[int, dict]) -> dict[str, list[int]]:
    """Classify services by type. Returns {type: [ports]}."""
    classification: dict[str, list[int]] = {}
    for port, info in services.items():
        name = info.get("name", "").lower()
        if name in ("http", "https", "http-proxy", "ssl/http"):
            classification.setdefault("http", []).append(port)
        if name in ("smb", "microsoft-ds", "netbios-ssn"):
            classification.setdefault("smb", []).append(port)
        if name == "ftp":
            classification.setdefault("ftp", []).append(port)
        if name == "ssh":
            classification.setdefault("ssh", []).append(port)
        if name in ("kerberos-sec", "ldap", "ldaps", "ldapssl", "microsoft-ds", "netbios-ssn"):
            classification.setdefault("ad", []).append(port)
        # AD detection: if kerberos (88) or ldap (389/636) is present
        if port in (88, 389, 636) and "ad" not in classification:
            classification.setdefault("ad", []).append(port)
    return classification
