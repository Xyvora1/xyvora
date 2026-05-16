# AGENTS.md — xyvora

AI Agent behavioral constitution for this repository. Read before any code change.

---

## 1. Repository Overview

xyvora is an automated penetration testing enumeration CLI tool written in Python. It orchestrates external recon tools (rustscan, nmap, gobuster, nikto, whatweb, enum4linux, kerbrute, crackmapexec, etc.) against a single target IP and generates a structured markdown report.

## 2. Directory Structure

```
xyvora/
├── xyvora.py                  # CLI entry point (argparse)
├── pyproject.toml             # Package metadata, dependencies, tool configs
├── src/
│   ├── xyvora/
│   │   ├── __init__.py        # Version
│   │   ├── main.py            # Orchestrator: scan → classify → enumerate → report
│   │   ├── scanner.py         # rustscan + nmap integration
│   │   ├── utils.py           # Shared: subprocess runner, Result dataclass, paths
│   │   ├── reporter.py        # Markdown report generation
│   │   └── modules/
│   │       ├── http.py        # gobuster, nikto, whatweb
│   │       ├── smb.py         # enum4linux, smbclient
│   │       ├── ftp.py         # Anonymous FTP detection
│   │       ├── ssh.py         # ssh-audit
│   │       └── ad.py          # LDAP, kerbrute, AS-REP, Kerberoasting
│   └── tests/                 # pytest test suite
├── docs/                      # Architecture docs, ADRs
├── results/                   # Output directory (gitignored)
└── .github/workflows/ci.yml   # CI pipeline
```

## 3. Forbidden Behaviors

- Do NOT modify the `src/xyvora/utils.py` `Result` class interface — it is the data contract between all modules.
- Do NOT add new external tool dependencies without updating `pyproject.toml` and the README tool list.
- Do NOT create empty output files — always check `result.has_output` before saving.
- Do NOT add interactive prompts without explicit request — the tool is designed for automation.
- Do NOT implement: searchsploit, hydra, multi-target batching, interactive menus.

## 4. Coding Standards

- **Python 3.9+** compatible. No f-string `=` debugging syntax (3.8), no `match` statements (3.10).
- **Naming:** snake_case for functions/variables, PascalCase for classes.
- **Imports:** stdlib first, then third-party, then internal. Use `isort` profile `black`.
- **Line length:** 100 characters.
- **Testing:** Every module function that invokes external commands must have a unit test mocking the subprocess call. Use pytest with AAA pattern (Arrange/Act/Assert).
- **No bare except:** Always catch specific exceptions.
- **Use `subprocess.run`** not `os.system` or `shell=True` (except for the FTP fallback where it's documented).

## 5. Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):
```
feat(module): description
fix(module): description
chore: description
docs: description
test(module): description
```

## 6. How to Run Locally

```bash
pip install -e ".[dev]"
python3 xyvora.py <target-ip>
python3 xyvora.py <target-ip> --dry-run
python3 xyvora.py <target-ip> -u admin -p Pass123 --domain htb.local
```

## 7. How to Run Tests

```bash
pytest                           # All tests
pytest src/tests/ -v             # Verbose
pytest --cov=src/xyvora          # With coverage
```

## 8. When to Ask Human for Help

- If a required external tool (rustscan, nmap, etc.) is not installed on the system — do not attempt to install it.
- If nmap XML parsing fails on an unexpected schema — report the XML snippet, do not silently skip.
- If a subprocess returns an error code that is not documented in the tool's man page — report it.
- If the user's target IP format is invalid — reject with explanation, do not guess.
- **If you encounter ambiguity in requirements → STOP and output the question. Do not assume.**
