# Maintenance Guide

## Weekly Scans (Stage 21 — Code Cleanup)

Scan criteria configured for xyvora:

| Dimension | Threshold | Notes |
|-----------|-----------|-------|
| Dead code | Any unreferenced function/variable | Run `vulture src/` |
| Duplicate code | >80% similarity | Check subprocess call patterns |
| Outdated dependencies | >2 major versions behind | Check `pip list --outdated` |
| Stale TODOs | >30 days | Grep `TODO` in src/ |
| Empty tests | Test files with no assertions | Check test files have pass/fail assertions |

### How to run
```bash
# Dead code scan
vulture src/xyvora/

# Dependency check
pip list --outdated

# TODO scan
grep -r "TODO" src/
```

---

## Documentation Gardener (Stage 22)

| Rule | Threshold |
|------|-----------|
| API path validity | Check referenced paths exist in code |
| Config keys | Verify config keys in pyproject.toml match code references |
| Stale docs | Last modified >90 days AND related code changed |
| Code examples | Verify examples are runnable |

Auto-creates GitHub Issues with `docs-stale` label when issues found.
