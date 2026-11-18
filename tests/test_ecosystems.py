"""Adapters for pnpm, yarn, Pipfile.lock, pyproject, Cargo, Go, Composer, NuGet, Maven, Gradle.

Each fixture under fixtures/ecosystems/ is hand-written from the format's
documentation and covers direct/transitive, prod/dev, non-registry sources
and unresolvable versions. The expected tables are exhaustive: an adapter
that reports an extra package or misses one fails here.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dep_guard.adapters import ParseContext, ParseError, adapter_for
from dep_guard.discovery import discover
from dep_guard.engine import ScanOptions, collect, scan
from dep_guard.policy import Verdict
from tests.osv_mock import FIXTURES

ECOSYSTEMS = FIXTURES / "ecosystems"
P, D, U = "prod", "dev", "unknown"
OK, UNRES = "clean", "unresolved"

# fixture -> {(name, version, direct, scope, status)}
EXPECTED: dict[str, set[tuple[str, str | None, bool | None, str, str]]] = {
    "pnpm-v9": {
        ("js-tokens", "4.0.0", False, P, OK),
        ("lodash-es", None, True, P, UNRES),
        ("loose-envify", "1.4.0", False, P, OK),
        ("react", "18.2.0", False, P, OK),
        ("react-dom", "18.2.0", True, P, OK),
        ("vitest", "1.0.0", True, D, OK),
    },
    "pnpm-v6": {
        ("@types/node", "20.1.0", True, D, OK),
        ("express", "4.17.1", True, P, OK),
        ("qs", "6.7.0", False, P, OK),
    },
    "pnpm-v5": {
        ("react", "17.0.2", False, P, OK),
        ("react-dom", "17.0.2", True, P, OK),
    },
    "yarn-v1": {
        ("@scope/helper", "2.1.0", False, D, OK),
        ("left-pad", None, True, P, UNRES),
        ("lodash", "4.17.15", True, P, OK),
        ("minimist", "1.2.0", True, D, OK),
    },
    "yarn-berry": {
        ("axios", "0.21.1", True, P, OK),
        ("follow-redirects", "1.13.0", False, P, OK),
        ("typescript", "5.0.4", True, D, OK),
    },
    "pipfile": {
        ("asgiref", "3.3.4", False, P, OK),
        ("django", "3.2.0", True, P, OK),
        ("mylib", None, False, P, UNRES),
        ("pytest", "7.0.0", True, D, OK),
    },
    "pyproject": {
        ("black", "22.1.0", True, D, OK),
        ("cryptography", "3.3.1", True, P, OK),
        ("flask", None, True, P, UNRES),
        ("local", None, True, P, UNRES),
        ("mylib", None, True, P, UNRES),
        ("pytest", "7.0.0", True, D, OK),
        ("pyyaml", None, True, P, UNRES),
        ("requests", "2.19.0", True, P, OK),
        ("urllib3", "1.26.4", True, P, OK),
    },
    "cargo": {
        ("cfg-if", "1.0.0", False, D, OK),
        ("mycrate", None, True, P, UNRES),
        ("smallvec", "1.6.0", True, P, OK),
        ("tempfile", "3.2.0", True, D, OK),
    },
    "go": {
        ("example.com/internal", None, True, U, UNRES),
        ("github.com/gin-gonic/gin", "v1.6.0", True, U, OK),
        ("github.com/new/lib", "v1.2.0", True, U, OK),
        ("golang.org/x/text", "v0.3.7", False, U, OK),
    },
    "composer": {
        ("acme/dev-tool", None, False, D, UNRES),
        ("phpunit/phpunit", "9.5.0", True, D, OK),
        ("psr/log", "1.1.4", False, P, OK),
        ("symfony/http-kernel", "v4.4.0", True, P, OK),
    },
    "nuget-lock": {
        ("Newtonsoft.Json", "12.0.1", True, U, OK),
        ("Serilog", "2.10.0", True, U, OK),
        ("System.Memory", "4.5.4", False, U, OK),
    },
    "nuget-project": {
        ("Central", None, True, U, UNRES),
        ("Central", "5.0.0", True, U, OK),
        ("ChildVersion", "3.1.0", True, U, OK),
        ("FromProps", None, True, U, UNRES),
        ("Newtonsoft.Json", "12.0.1", True, U, OK),
        ("Pinned.Exact", "1.2.3", True, U, OK),
        ("Ranged", None, True, U, UNRES),
    },
    "maven": {
        ("com.acme:sibling", "1.0.0", True, P, OK),
        ("com.fasterxml.jackson.core:jackson-databind", "2.9.8", True, P, OK),
        ("com.google.guava:guava", "29.0-jre", True, P, OK),
        ("junit:junit", "4.12", True, D, OK),
        ("org.apache.logging.log4j:log4j-core", "2.14.1", True, P, OK),
        ("org.example:ranged", None, True, P, UNRES),
        ("org.example:undefined-prop", None, True, P, UNRES),
        ("org.springframework.boot:spring-boot-starter-web", None, True, P, UNRES),
    },
    "gradle": {
        ("com.fasterxml.jackson.core:jackson-databind", "2.9.8", None, P, OK),
        ("junit:junit", "4.12", None, D, OK),
        ("org.apache.logging.log4j:log4j-core", "2.14.1", None, P, OK),
    },
}

ECOSYSTEM_OF = {
    "pnpm-v9": "npm",
    "pnpm-v6": "npm",
    "pnpm-v5": "npm",
    "yarn-v1": "npm",
    "yarn-berry": "npm",
    "pipfile": "PyPI",
    "pyproject": "PyPI",
    "cargo": "crates.io",
    "go": "Go",
    "composer": "Packagist",
    "nuget-lock": "NuGet",
    "nuget-project": "NuGet",
    "maven": "Maven",
    "gradle": "Maven",
}


@pytest.mark.parametrize("fixture", sorted(EXPECTED))
def test_adapter_output_is_exactly_the_expected_inventory(fixture: str) -> None:
    _, components, _ = collect(ECOSYSTEMS / fixture)
    got = {(c.name, c.version, c.direct, c.scope.value, c.status.value) for c in components}
    assert got == EXPECTED[fixture]
    assert {c.ecosystem for c in components} == {ECOSYSTEM_OF[fixture]}
    for c in components:
        assert c.locations and c.locations[0].file  # every package points to its file
        if c.status.value == UNRES:
            assert c.unresolved_reason  # never unresolved without saying why


def test_transitive_paths_explain_why_a_package_is_installed() -> None:
    _, components, _ = collect(ECOSYSTEMS / "pnpm-v9")
    by_name = {c.name: c for c in components}
    assert by_name["js-tokens"].paths[0] == ["react-dom", "loose-envify", "js-tokens"]
    _, cargo, _ = collect(ECOSYSTEMS / "cargo")
    assert {c.name: c.paths[0] for c in cargo}["cfg-if"] == ["tempfile", "cfg-if"]


def test_go_replace_scans_the_module_that_is_actually_built() -> None:
    _, components, _ = collect(ECOSYSTEMS / "go")
    names = {c.name for c in components}
    assert "github.com/new/lib" in names and "github.com/old/lib" not in names
    assert "golang.org/x/net" not in names  # `exclude` is not a dependency


@pytest.mark.parametrize(
    ("fixture", "superseded"),
    [
        ("nuget-lock", "App.csproj"),
        ("composer", "composer.json"),
        ("yarn-v1", "package.json"),
        ("cargo", "Cargo.toml"),
        ("pipfile", "Pipfile"),
    ],
)
def test_lockfile_supersedes_its_manifest(fixture: str, superseded: str) -> None:
    _, files, problems = discover(ECOSYSTEMS / fixture)
    assert superseded not in {f.rel_path for f in files}
    assert not any(p.code == "manifest_not_analysed" for p in problems)


def test_recognised_but_unsupported_files_make_the_scan_incomplete(tmp_path: Path) -> None:
    _, files, problems = discover(ECOSYSTEMS / "not-analysed")
    assert [f.rel_path for f in files] == ["requirements.txt"]
    assert sorted(p.file or "" for p in problems if p.code == "manifest_not_analysed") == [
        "Gemfile.lock",
        "rust-no-lock/Cargo.toml",
    ]
    report = scan(
        ECOSYSTEMS / "not-analysed",
        ScanOptions(offline=True, cache_dir=tmp_path, epss=False, kev=False),
    )
    assert report.policy.verdict is Verdict.INCOMPLETE
    assert "2 dependency files were recognised but not analysed" in (
        report.policy.incomplete_reasons
    )


def test_cargo_toml_inside_a_locked_workspace_is_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "Cargo.lock").write_text((ECOSYSTEMS / "cargo" / "Cargo.lock").read_text())
    member = tmp_path / "crates" / "member"
    member.mkdir(parents=True)
    (member / "Cargo.toml").write_text('[package]\nname = "member"\nversion = "0.1.0"\n')
    _, _, problems = discover(tmp_path)
    assert not any(p.code == "manifest_not_analysed" for p in problems)


# --------------------------------------------------------------- hostile input


def _parse(filename: str, content: str, parent: str = "") -> object:
    adapter = adapter_for(filename, parent)
    assert adapter is not None, filename
    return adapter.parse(content, ParseContext(filename))


def test_yaml_alias_bomb_is_refused_before_expansion() -> None:
    lines = ["lockfileVersion: '9.0'", 'a: &a ["x","x","x","x","x","x","x","x","x"]']
    for i in range(1, 12):
        prev = chr(ord("a") + i - 1)
        cur = chr(ord("a") + i)
        lines.append(f"{cur}: &{cur} [*{prev},*{prev},*{prev},*{prev},*{prev},*{prev}]")
    with pytest.raises(ParseError, match="aliases are not allowed"):
        _parse("pnpm-lock.yaml", "\n".join(lines) + "\n")


@pytest.mark.parametrize(
    "doctype",
    [
        '<!DOCTYPE p [<!ENTITY x SYSTEM "file:///etc/passwd">]>',  # XXE
        '<!DOCTYPE p [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]>',  # entity expansion
        "<!doctype p>",
    ],
)
@pytest.mark.parametrize("filename", ["pom.xml", "App.csproj", "Directory.Packages.props"])
def test_xml_with_dtd_is_refused(doctype: str, filename: str) -> None:
    with pytest.raises(ParseError, match="DOCTYPE or ENTITY"):
        _parse(filename, f'<?xml version="1.0"?>\n{doctype}\n<project></project>\n')


@pytest.mark.parametrize(
    ("filename", "content", "message"),
    [
        ("pnpm-lock.yaml", "lockfileVersion: '4.0'\n", "unsupported pnpm lockfileVersion"),
        ("pnpm-lock.yaml", "- just\n- a list\n", "not a mapping"),
        ("pnpm-lock.yaml", "key: [unclosed\n", "invalid YAML"),
        ("yarn.lock", 'lodash@^4:\n  version "4"\nbroken line\n', "unexpected content"),
        ("go.mod", "require github.com/x/y v1.0.0\n", "no `module` directive"),
        ("Cargo.lock", "version = 3\n", "not a Cargo.lock"),
        ("composer.lock", "[]", "not an object"),
        ("packages.lock.json", '{"version": 1}', "not a NuGet"),
        ("pom.xml", "<project><dependencies>", "invalid XML"),
        ("Pipfile.lock", "{not json", "invalid JSON"),
        ("pyproject.toml", "[project\n", "invalid TOML"),
    ],
)
def test_malformed_files_raise_parse_error(filename: str, content: str, message: str) -> None:
    with pytest.raises(ParseError, match=message):
        _parse(filename, content)


def test_gradle_garbage_lines_are_reported_not_guessed() -> None:
    result = _parse("gradle.lockfile", "not-a-coordinate\ng:a:1.0=runtimeClasspath\n")
    assert [c.name for c in result.components] == ["g:a"]  # type: ignore[attr-defined]
    assert [p.code for p in result.problems] == ["invalid_line"]  # type: ignore[attr-defined]


def test_maven_property_cycles_terminate() -> None:
    pom = (
        "<project><properties><a>${b}</a><b>${a}</b></properties><dependencies>"
        "<dependency><groupId>g</groupId><artifactId>x</artifactId><version>${a}</version>"
        "</dependency></dependencies></project>"
    )
    result = _parse("pom.xml", pom)
    (comp,) = result.components  # type: ignore[attr-defined]
    assert comp.version is None and "unresolved property" in comp.unresolved_reason


def test_hostile_names_are_sanitised() -> None:
    evil = "evil" + chr(0x1B) + "[31m" + chr(0x202E) + "pkg"
    lock = json.dumps({"default": {evil: {"version": "==1.0"}}, "develop": {}})
    result = _parse("Pipfile.lock", lock)
    (comp,) = result.components  # type: ignore[attr-defined]
    assert chr(0x1B) not in comp.name and chr(0x202E) not in comp.name


def test_every_adapter_is_documented_in_the_formats_command() -> None:
    from dep_guard.adapters import ADAPTERS
    from dep_guard.cli import SUPPORTED_FILES

    assert {a.id for a in ADAPTERS} == set(SUPPORTED_FILES)
