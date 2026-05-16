# Local Development Guide

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
pre-commit install
```

## Running

```bash
python3 xyvora.py <target-ip>
python3 xyvora.py <target-ip> --dry-run          # Show commands only
python3 xyvora.py <target-ip> -u admin -p pass    # With credentials
python3 xyvora.py <target-ip> --domain htb.local  # Manual domain
```

## Running Tests

```bash
pytest src/tests/ -v                    # All tests
pytest src/tests/ --cov=src/xyvora      # With coverage
pytest src/tests/test_scanner.py -v     # Single test file
```

## Code Quality

```bash
black src/          # Format
isort src/          # Sort imports
ruff check src/     # Lint
```

## Project Structure

See [architecture.md](architecture.md) for module responsibilities and data flow.

## External Tool Dependencies

All external tools must be in `$PATH`:
- `rustscan`, `nmap` — port scanning
- `gobuster`, `nikto`, `whatweb` — web enumeration
- `enum4linux`, `smbclient`, `rpcclient` — SMB/Windows enumeration
- `ldapsearch` — LDAP queries
- `kerbrute` — Kerberos user enumeration
- `GetNPUsers`, `GetUserSPNs` — Impacket suite
- `crackmapexec` — SMB authentication testing
- `ssh-audit` — SSH configuration audit
