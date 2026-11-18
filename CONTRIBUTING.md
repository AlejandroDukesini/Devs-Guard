# Contributing to DepGuard

Thanks for helping. DepGuard is a security tool, so correctness and honest
behaviour matter more than features.

## Development setup

```bash
git clone https://github.com/AlejandroDukesini/Devs-Guard.git
cd Devs-Guard
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install --require-hashes -r requirements/ci.txt   # exactly what CI installs
pip install --no-deps --no-build-isolation -e .
```

After changing dependencies in `pyproject.toml`, regenerate the hashed lock
(command in `docs/devsecops.md`) and commit both files.

Local web app: `cd web && npm ci --ignore-scripts && npm run build:local`,
then `depguard serve`.

## Checks (the same ones CI runs)

```bash
ruff check dep_guard tests scripts && ruff format --check dep_guard tests scripts
mypy
bandit -q -c pyproject.toml -r dep_guard
pytest --cov
python scripts/check_text_safety.py
```

Web (`web/`): `npm ci --ignore-scripts && npm run lint && npm test && npm run build`.
E2E: `npx playwright test` (public demo) and
`DEPGUARD_BIN=depguard npx playwright test -c playwright.local.config.js` (local app).

Security stages (gitleaks, OSV-Scanner, SBOM schema validation, ZAP) run in
`.github/workflows/security.yml`; `docs/devsecops.md` describes each one.

## Ground rules

1. **Never turn "unknown" into "safe".** Any new source, adapter or code path
   that can fail must surface the failure (ComponentStatus.ERROR / UNRESOLVED,
   a Problem, exit code 3), never an empty result.
2. **No code execution.** Adapters parse text; they never run package
   managers, build tools or scripts (`tests/test_security.py` enforces it).
3. **Every bug fix ships with a regression test.**
4. **Python and JavaScript engines stay in parity** for shared behaviour
   (report, risk, policy, patch status and the original formats). Changes
   update `fixtures/golden/` (`python -m tests.regen_golden`, review the diff)
   and `web/src/core/` in the same pull request. Formats added after 1.0.0b2
   exist only in the Python engine.
5. **No real vulnerability data in tests.** Use the synthetic universe in
   `fixtures/osv-mock/` (`acme-*` packages, `CVE-2099-*`).
6. **The local app is a security boundary.** Every new endpoint goes through
   the middleware in `dep_guard/server/app.py` and ships with adversarial
   tests in `tests/test_server.py`.

## Adding an ecosystem

1. Create an adapter in `dep_guard/adapters/` with a class exposing `id`,
   `matches(filename, parent_dir)` and `parse(content, ctx) -> ParseResult`.
   Load untrusted YAML/XML/JSON/TOML through `adapters/safe_formats.py`.
2. Register it in `dep_guard/adapters/__init__.py` (and `SUPERSEDED_BY` if a
   lockfile replaces a manifest).
3. Add a hand-written fixture under `fixtures/ecosystems/<name>/` and its exact
   expected inventory in `tests/test_ecosystems.py` (direct/transitive,
   prod/dev, non-registry sources, malformed input).
4. Add the adapter id to `SUPPORTED_FILES` in `dep_guard/cli.py` (a test
   enforces it).
5. Document it in `docs/ecosystems.md` and `docs/limitations.md`.

Prefer CycloneDX input (`*.cdx.json`) over a native adapter when a mature SBOM
generator already exists for that ecosystem.

## Commits and pull requests

- Small, focused commits; conventional prefixes (`feat:`, `fix:`, `docs:`,
  `test:`, `ci:`, `refactor:`) are appreciated.
- Update `CHANGELOG.md` under *Unreleased* for user-visible changes.
