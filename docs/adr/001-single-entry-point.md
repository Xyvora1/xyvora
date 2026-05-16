# ADR-001: Single-file entry point with internal package

**Status:** Accepted
**Date:** 2026-05-16

## Context

The tool needs to be invoked as `python3 xyvora.py <target>`. Two approaches were considered:
1. Single monolithic Python file
2. Root entry point + internal package under `src/`

## Decision

Option 2: `xyvora.py` at root delegates to `src/xyvora/` package.

## Rationale

- The requirements show `python3 xyvora.py` as the CLI — a root file satisfies this.
- A 500+ line single file is unmaintainable for this complexity (7+ service modules).
- Internal package keeps modules separated by concern while hiding from the user.

## Consequences

- Slight complexity of two-layer import structure.
- `src/` layout is standard Python packaging and compatible with editable installs (`pip install -e .`).
