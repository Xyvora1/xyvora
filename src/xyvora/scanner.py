"""Port scanning: rustscan + nmap."""

import os
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
