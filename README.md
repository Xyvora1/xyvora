# xyvora

Automated penetration testing enumeration tool. Orchestrates common recon tools against a single target IP and generates a structured report.

## Quick Start

```bash
pip install -e .
python3 xyvora.py 10.10.10.1
```

## Requirements

External tools must be installed separately:
- rustscan, nmap
- gobuster, nikto, whatweb
- enum4linux, smbclient, rpcclient
- crackmapexec, ldapsearch, kerbrute
- ssh-audit
