# Contributing to DepGuard

Thanks for helping. DepGuard is a security tool, so correctness and honest
behaviour matter more than features.

## Development setup

```bash
git clone https://github.com/AlejandroDukesini/Devs-Guard.git
cd Devs-Guard
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Checks (the same ones CI runs)

```bash
ruff check dep_guard tests && ruff format --check dep_guard tests
mypy
bandit -q -c pyproject.toml -r dep_guard
pytest --cov
```

Web demo (`web/`): `npm ci && npm run lint && npm test && npm run build`.

## Ground rules

1. **Never turn "unknown" into "safe".** Any new source, adapter or code path
   that can fail must surface the failure (ComponentStatus.ERROR / UNRESOLVED,
   a Problem, exit code 3), never an empty result.
2. **No code execution.** Adapters parse text; they never run package
   managers, build tools or scripts (`tests/test_security.py` enforces it).
3. **Every bug fix ships with a regression test.**
4. **Python and JavaScript engines stay in parity.** Behaviour changes update
   `fixtures/golden/` (`python -m tests.regen_golden`, review the diff) and the
   JS engine in `web/src/core/` in the same pull request.
5. **No real vulnerability data in tests.** Use the synthetic universe in
   `fixtures/osv-mock/` (`acme-*` packages, `CVE-2099-*`).

## Adding an ecosystem

1. Create `dep_guard/adapters/<name>.py` with a class exposing `id`,
   `matches(filename, parent_dir)` and `parse(content, ctx) -> ParseResult`.
2. Register it in `dep_guard/adapters/__init__.py`.
3. Add a fixture project under `fixtures/projects/`, entries in
   `fixtures/osv-mock/index.json` if needed, and a case in
   `tests/regen_golden.py`; regenerate goldens.
4. Document it in `docs/ecosystems.md` and `docs/limitations.md`.

Prefer CycloneDX input (`*.cdx.json`) over a native adapter when a mature SBOM
generator already exists for that ecosystem.

## Commits and pull requests

- Small, focused commits; conventional prefixes (`feat:`, `fix:`, `docs:`,
  `test:`, `ci:`, `refactor:`) are appreciated.
- Update `CHANGELOG.md` under *Unreleased* for user-visible changes.
