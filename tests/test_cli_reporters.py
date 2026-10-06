from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from rich.console import Console

from dep_guard.cli import main
from dep_guard.engine import ScanOptions, scan
from dep_guard.reporters import cyclonedx, sarif, table
from tests.conftest import PROJECTS
from tests.osv_mock import MockState


@pytest.fixture(autouse=True)
def _no_color(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")


class TestExitCodes:
    def test_policy_failure_is_1(self, osv: MockState, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["scan", str(PROJECTS / "npm-app")]) == 1
        out = capsys.readouterr().out
        assert "Política: FAIL" in out
        assert "acme-qs" in out

    def test_untrusted_markup_is_printed_literally(self, osv: MockState, opts: ScanOptions) -> None:
        buf = io.StringIO()
        table.render(scan(PROJECTS / "npm-app", opts), Console(file=buf, width=250, no_color=True))
        text = buf.getvalue()
        assert "[bold]parses[/bold]" in text  # rich markup from the advisory is not interpreted
        assert "\x1b" not in text  # ANSI escape from the advisory was stripped

    def test_pass_is_0(self, osv: MockState, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("unknown-pkg==1.0\n")
        assert main(["scan", str(tmp_path), "-q"]) == 0

    def test_fail_on_none_downgrades_to_pass(self, osv: MockState) -> None:
        assert main(["scan", str(PROJECTS / "py-uv"), "--fail-on", "none", "-q"]) == 0

    def test_incomplete_is_3(self, osv: MockState) -> None:
        osv.fail["batch"] = 503
        assert main(["scan", str(PROJECTS / "py-uv"), "-q"]) == 3

    def test_tool_errors_are_2(self, osv: MockState, tmp_path: Path) -> None:
        assert main(["scan", str(tmp_path / "missing")]) == 2
        bad = tmp_path / "notes.md"
        bad.write_text("hello")
        assert main(["scan", str(bad)]) == 2
        cfg = tmp_path / "depguard.toml"
        cfg.write_text("[policy]\nfail_on_kevv = true\n")
        assert main(["scan", str(tmp_path)]) == 2
        assert main(["scan", str(tmp_path), "-c", str(tmp_path / "nope.toml")]) == 2

    def test_argparse_errors_are_2(self) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["scan", "--format", "pdf"])
        assert exc.value.code == 2

    def test_legacy_invocation(self, osv: MockState) -> None:
        # 0.x: `python -m dep_guard.cli requirements.txt`
        assert main([str(PROJECTS / "py-requirements" / "requirements.txt"), "-q"]) == 1


class TestOutputs:
    def test_json_to_file(self, osv: MockState, tmp_path: Path) -> None:
        out = tmp_path / "out" / "report.json"
        code = main(["scan", str(PROJECTS / "npm-app"), "-f", "json", "-o", str(out)])
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["schema"] == "depguard.report/v1"
        assert data["exit_code"] == code == 1

    def test_json_stdout_is_pure_json(
        self, osv: MockState, capfdbinary: pytest.CaptureFixture[bytes]
    ) -> None:
        main(["scan", str(PROJECTS / "npm-app"), "-f", "json"])
        captured = capfdbinary.readouterr()
        json.loads(captured.out.decode("utf-8"))  # progress/verdict went to stderr

    def test_sarif_structure(self, osv: MockState, opts: ScanOptions) -> None:
        doc = sarif.to_dict(scan(PROJECTS / "npm-app", opts))
        run = doc["runs"][0]
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        assert doc["version"] == "2.1.0"
        assert {r["ruleId"] for r in run["results"]} <= rule_ids
        for rule in run["tool"]["driver"]["rules"]:
            float(rule["properties"]["security-severity"])
        loc = run["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "package-lock.json"
        assert loc["region"]["startLine"] > 1
        fps = [r["partialFingerprints"]["depguard/v1"] for r in run["results"]]
        assert len(fps) == len(set(fps))

    def test_sarif_marks_ignored_as_suppressed(self, osv: MockState, opts: ScanOptions) -> None:
        opts.config_path = PROJECTS.parent / "configs" / "npm-app-policy.toml"
        run = sarif.to_dict(scan(PROJECTS / "npm-app", opts))["runs"][0]
        suppressed = [r for r in run["results"] if "suppressions" in r]
        assert len(suppressed) == 1
        assert suppressed[0]["suppressions"][0]["status"] == "accepted"

    def test_cyclonedx_roundtrip(self, osv: MockState, opts: ScanOptions, tmp_path: Path) -> None:
        report = scan(PROJECTS / "npm-app", opts)
        bom = cyclonedx.to_dict(report.components, "demo-shop", report.findings)
        assert bom["specVersion"] == "1.6"
        refs = {c["bom-ref"] for c in bom["components"]}
        for dep in bom["dependencies"]:
            assert dep["ref"] in refs | {"depguard:root"}
            assert set(dep["dependsOn"]) <= refs
        assert {v["id"] for v in bom["vulnerabilities"]} >= {"CVE-2099-1001"}
        # Feed our own SBOM back in: same vulnerable packages are found.
        sbom = tmp_path / "bom.cdx.json"
        sbom.write_text(json.dumps(bom))
        again = scan(sbom, opts)
        assert {(f.id, f.component.name, f.component.version) for f in again.findings} == {
            (f.id, f.component.name, f.component.version) for f in report.findings
        }

    def test_sbom_command_needs_no_network(self, tmp_path: Path) -> None:
        out = tmp_path / "bom.json"
        assert main(["sbom", str(PROJECTS / "py-uv"), "-o", str(out)]) == 0
        bom = json.loads(out.read_text(encoding="utf-8"))
        assert "vulnerabilities" not in bom
        assert any(c["name"] == "acme-markup" for c in bom["components"])

    def test_formats_command(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["formats"]) == 0
        assert "package-lock.json" in capsys.readouterr().out
