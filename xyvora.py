#!/usr/bin/env python3
"""xyvora - Automated penetration testing enumeration tool.

Usage:
    python3 xyvora.py 10.10.10.1
    python3 xyvora.py 10.10.10.1 -u administrator -p Password123
    python3 xyvora.py 10.10.10.1 --dry-run
    python3 xyvora.py 10.10.10.1 --domain htb.local
"""

import argparse
import sys
from src.xyvora.main import run


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="xyvora - Automated penetration testing enumeration tool"
    )
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("-u", "--username", default=None, help="Username for authenticated enumeration")
    parser.add_argument("-p", "--password", default=None, help="Password for authenticated enumeration")
    parser.add_argument("--domain", default=None, help="Domain name (e.g. htb.local)")
    parser.add_argument("--dry-run", action="store_true", help="Show commands without executing")
    return parser.parse_args()


def main():
    args = parse_args()
    sys.exit(run(args.target, args.username, args.password, args.domain, args.dry_run))


if __name__ == "__main__":
    main()
