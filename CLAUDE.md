# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install (uv manages the venv and Python 3.14)
uv venv && uv pip install -e ".[dev]"

# Run the tool
uv run python xyvora.py <target-ip>
uv run python xyvora.py <target-ip> --dry-run

# Tests
uv run pytest src/tests/ -v                          # All tests
uv run pytest src/tests/test_utils.py -v             # Single test file
uv run pytest src/tests/ --cov=src/xyvora             # With coverage

# Lint & format
uv run ruff check src/                                # Lint
uv run ruff check --fix src/                          # Auto-fix
uv run black src/                                     # Format
uv run isort src/                                     # Import sorting
```

## Architecture

Four-phase orchestration pipeline in `main.py`:
1. **rustscan** (0-65535) → open port list
2. **nmap -sC -sV** → XML parsed into `{port: {name, product, version, hostname}}`
3. **Concurrent modules** — one `ThreadPoolExecutor` thread per module category, each category internally spawns its own threads
4. **Report** — `reporter.py` aggregates only non-empty `Result` objects into `results/<ip>/report.md`

## Key Design Patterns

**`Result` is the universal data contract.** Every module function returns `list[Result]`. Each `Result` has `.tool`, `.port`, `.stdout`, `.stderr`, `.success`, `.elapsed`, `.has_output` (True iff stdout is non-empty), and `.label` (`"tool:port"` or `"tool"`).

**`save_result` auto-names and auto-skips.** Call `save_result(result, directory)` — it generates filename `{tool}_{port}.txt`, creates the directory, writes content. Returns `None` (not a path) when `result.has_output` is False. Never create empty output files.

**ThreadPoolExecutor + as_completed pattern.** The convention is `futures[executor.submit(fn, ...)] = "label"`, then iterate `for future in as_completed(futures): label = futures[future]`. The future is the dict KEY, the label is the VALUE. Module categories in `main.py` use one thread each; within each module (http.py, ad.py) another executor fans out individual tool invocations.

**Module runner signatures** — all `run_*` functions in `modules/` take `(target, ports, dry_run, out_dir, progress_callback)` and return `list[Result]`. The AD module is the exception: it takes `services` dict instead of `ports`, plus optional `username`/`password`/`domain`.

**AD domain extraction is sequential.** Before any AD enumeration, `extract_domain()` tries: LDAP anonymous bind → nmap hostname field → returns `None` (caller prints "use --domain"). All AD modules (including the dry-run codepath) depend on having a domain.

## Testing Conventions

Tests mock BOTH the subprocess runner AND `as_completed`. Mocking `as_completed` with `side_effect=lambda d: iter(d)` prevents hangs, since real `as_completed` blocks on mock futures. Use `patch("xyvora.modules.<module>.run_cmd")` (the fully-qualified import path within the module under test, not `xyvora.utils.run_cmd`).

Assertions target the structure of the generated command list (`mock_run.call_args[0][0]`), not shell strings.

## Constraints

- Python 3.9+ compatible — no `match` statements, no f-string `=` debugging
- External tools (rustscan, nmap, gobuster, etc.) must be in `$PATH` — never attempt to install them
- Wordlists are hardcoded in `utils.py`: `DIRBUSTER_MEDIUM`, `KERBRUTE_USERLIST`
- Timeout is 10min for gobuster, 5min for everything else
- `results/` is gitignored — all output goes there
- Do NOT implement: searchsploit, hydra, multi-target, interactive menus
