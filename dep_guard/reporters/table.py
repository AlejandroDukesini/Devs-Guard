"""Human-readable terminal report.

All text that originates outside DepGuard (package names, advisory
summaries, file names) is wrapped in rich.text.Text, never interpolated
into markup, so `[bold]`-style sequences in an advisory cannot restyle or
hide output. Control characters were already stripped at ingestion.
Colour is used only for severity/priority and the verdict.
"""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from dep_guard.engine import ScanReport
from dep_guard.models import ComponentStatus, Finding, FindingStatus, Priority, Severity
from dep_guard.policy import Verdict
from dep_guard.reporters.json_report import remediation, summary

_PRIORITY_STYLE = {
    Priority.P0: "bold red",
    Priority.P1: "red",
    Priority.P2: "yellow",
    Priority.P3: "dim",
}
_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "default",
    Severity.UNKNOWN: "magenta",
}
_VERDICT_STYLE = {
    Verdict.PASS: "bold green",
    Verdict.FAIL: "bold red",
    Verdict.INCOMPLETE: "bold yellow",
}
_VERDICT_TEXT = {
    Verdict.PASS: "PASS",
    Verdict.FAIL: "FAIL",
    Verdict.INCOMPLETE: "INCOMPLETE — no se pudo determinar el estado de todas las dependencias",
}
MAX_ROWS = 200


def _origin(f: Finding) -> Text:
    c = f.component
    if c.direct is True:
        kind = "directa"
    elif c.direct is False:
        kind = "transitiva"
    else:
        kind = "?"
    scope = {"prod": "prod", "dev": "dev", "unknown": "¿prod?"}[c.scope.value]
    text = Text(f"{kind} · {scope}")
    if c.direct is False and c.paths and len(c.paths[0]) > 1:
        text.append("\n" + " > ".join(c.paths[0][:-1]), style="dim")
    return text


def render(report: ScanReport, console: Console, quiet: bool = False) -> None:
    s = summary(report)
    verdict = report.policy.verdict
    if quiet:
        line = Text(f"DepGuard: {verdict.value}", style=_VERDICT_STYLE[verdict])
        line.append(
            f" · {s['findings']} hallazgos activos "
            f"(P0 {s['by_priority']['P0']}, P1 {s['by_priority']['P1']})",
            style="default",
        )
        console.print(line)
        return

    console.print(Text(f"DepGuard {report.tool_version}", style="bold"))
    names = ", ".join(m.path for m in report.manifests[:5]) + (
        " …" if len(report.manifests) > 5 else ""
    )
    console.print(_check(True, f"{len(report.manifests)} archivo(s) analizados: {names or '—'}"))
    extra = []
    if s["unresolved"]:
        extra.append(f"{s['unresolved']} sin versión exacta")
    if s["private"]:
        extra.append(f"{s['private']} privadas (no consultadas)")
    console.print(
        _check(
            True,
            f"{s['components']} dependencias ({s['direct']} directas)"
            + (" · " + " · ".join(extra) if extra else ""),
        )
    )
    for name, status in report.sources.items():
        ok = status in ("ok", "offline-cache", "disabled", "not needed")
        console.print(_check(ok, f"{name.upper()}: {status}"))

    active = report.active_findings
    if active:
        console.print()
        table = Table(box=box.SIMPLE_HEAD, pad_edge=False, expand=True)
        table.add_column("Prio", no_wrap=True, width=4)
        table.add_column("Paquete", ratio=2, overflow="fold")
        table.add_column("Vulnerabilidad", ratio=4, overflow="ellipsis")
        table.add_column("Severidad", no_wrap=True)
        table.add_column("Corrige en", no_wrap=True)
        table.add_column("Origen", ratio=2, overflow="fold")
        for f in active[:MAX_ROWS]:
            sev = Text(f.severity.value, style=_SEVERITY_STYLE[f.severity])
            if f.cvss_score is not None:
                sev.append(f" {f.cvss_score}", style="dim")
            vuln = Text(f.id, no_wrap=True, overflow="ellipsis")
            if f.kev:
                vuln.append(" KEV", style="bold red")
            vuln.append("\n")
            vuln.append(f.summary, style="dim")
            table.add_row(
                Text(f.priority.value, style=_PRIORITY_STYLE[f.priority]),
                Text(f"{f.component.name}\n{f.component.version}"),
                vuln,
                sev,
                Text(
                    f.fixed_versions[0] if f.fixed_versions else "sin fix",
                    style="" if f.fixed_versions else "dim",
                ),
                _origin(f),
            )
        console.print(table)
        if len(active) > MAX_ROWS:
            console.print(
                Text(f"… y {len(active) - MAX_ROWS} más (usa --format json)", style="dim")
            )

        urgent = [f for f in active if f.priority in (Priority.P0, Priority.P1)]
        if urgent:
            console.print(Text("Por qué importan (P0/P1)", style="bold"))
            for f in urgent[:10]:
                line = Text(f"  {f.priority.value} {f.id} ", style=_PRIORITY_STYLE[f.priority])
                line.append(
                    f"{f.component.name}@{f.component.version} — {f.summary}\n      ",
                    style="default",
                )
                line.append(" · ".join(r.text for r in f.reasons), style="dim")
                console.print(line)

        plan = [r for r in remediation(report.findings) if r["upgrade_to"]]
        if plan:
            console.print(Text("\nRemediación sugerida", style="bold"))
            for r in plan[:15]:
                how = (
                    ""
                    if r["direct"]
                    else f" (llega vía {' > '.join(r['via'][:-1])})"
                    if r["via"]
                    else ""
                )
                console.print(
                    Text(
                        f"  • {r['package']} {r['current']} → {r['upgrade_to']}  "
                        f"corrige {r['fixes']} de {r['of']}{how}"
                    )
                )

    ignored = [f for f in report.findings if f.status is FindingStatus.IGNORED]
    if ignored:
        console.print(Text(f"\nExcepciones aplicadas ({len(ignored)})", style="bold"))
        for f in ignored[:20]:
            console.print(
                Text(
                    f"  {f.id} {f.component.name}: {f.ignore_reason} (caduca {f.ignore_expires})",
                    style="dim",
                )
            )

    unresolved = [c for c in report.components if c.status is ComponentStatus.UNRESOLVED]
    errors = [c for c in report.components if c.status is ComponentStatus.ERROR]
    if unresolved:
        console.print(
            Text(
                f"\nNo analizadas por falta de versión exacta ({len(unresolved)})",
                style="bold yellow",
            )
        )
        for c in unresolved[:10]:
            console.print(Text(f"  {c.name}: {c.unresolved_reason}", style="dim"))
        if len(unresolved) > 10:
            console.print(Text(f"  … y {len(unresolved) - 10} más", style="dim"))
    if errors:
        console.print(
            Text(f"\nEstado desconocido ({len(errors)}): la consulta falló", style="bold yellow")
        )
        for c in errors[:10]:
            console.print(Text(f"  {c.name}@{c.version}: {c.error}", style="dim"))
    shown = {"unused_ignore"}
    for p in report.problems:
        if p.code in shown:
            continue
        console.print(Text(f"! {p.file + ': ' if p.file else ''}{p.message}", style="yellow"))
    for msg in report.policy.unused_ignores:
        console.print(Text(f"! {msg}", style="yellow"))

    console.print()
    bp = s["by_priority"]
    counts = Text("Resultado  ")
    for prio in Priority:
        counts.append(
            f"{prio.value} {bp[prio.value]}  ",
            style=_PRIORITY_STYLE[prio] if bp[prio.value] else "dim",
        )
    if s["ignored"]:
        counts.append(f"(ignorados {s['ignored']})", style="dim")
    console.print(counts)
    console.print(Text(f"Política: {_VERDICT_TEXT[verdict]}", style=_VERDICT_STYLE[verdict]))
    for v in report.policy.violations[:20]:
        console.print(Text(f"  ✗ {v}", style="red"))
    for why in report.policy.incomplete_reasons:
        console.print(Text(f"  ? {why}", style="yellow"))
    if not active and verdict is Verdict.PASS:
        console.print(
            Text(
                "No se encontraron vulnerabilidades conocidas en las dependencias analizadas.",
                style="green",
            )
        )


def _check(ok: bool, message: str) -> Text:
    t = Text("✓ " if ok else "✗ ", style="green" if ok else "yellow")
    t.append(message)
    return t
