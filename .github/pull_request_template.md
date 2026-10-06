## What and why

<!-- What changes, and which problem does it solve? Link issues. -->

## Checklist

- [ ] Tests added/updated (regression test for bug fixes)
- [ ] `ruff`, `mypy`, `bandit` and `pytest` pass locally
- [ ] Failure paths surface as ERROR/UNRESOLVED/INCOMPLETE, never as "clean"
- [ ] Goldens regenerated and reviewed (`python -m tests.regen_golden`) if behaviour changed
- [ ] JS engine in `web/src/core/` updated for parity (if engine behaviour changed)
- [ ] Docs and `CHANGELOG.md` updated
