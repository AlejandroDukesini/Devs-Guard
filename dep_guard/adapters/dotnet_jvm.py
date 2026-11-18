"""NuGet (.NET) and Maven/Gradle (JVM) manifests.

NuGet
  packages.lock.json (enabled with RestorePackagesWithLockFile) records the
  resolved version of every package per target framework, marking each one
  Direct / Transitive / Project. It is the source of truth when present.
  Without it, project files (*.csproj, *.fsproj, *.vbproj) and
  Directory.Packages.props give direct references only. NuGet resolves a
  bare version ("1.2.3") to the *lowest applicable* version, i.e. exactly
  1.2.3 when it exists; interval notation is only exact for "[1.2.3]".

Maven
  pom.xml lists direct dependencies. Versions written literally or through
  properties defined in the same POM are resolved; anything inherited from a
  parent POM or imported BOM, and every transitive dependency, needs Maven
  itself (remote POM resolution), which this scanner never runs. Those cases
  are reported, not guessed; generate a CycloneDX SBOM for full coverage.

Gradle
  Build scripts are programs (Groovy/Kotlin) and are never evaluated. With
  dependency locking enabled, gradle.lockfile records every resolved module
  (direct and transitive) with the configurations that use it.
"""

from __future__ import annotations

import re

# Type annotations only; parsing happens in safe_formats.parse_xml.
from xml.etree.ElementTree import Element  # nosec B405

from dep_guard.adapters.base import (
    ParseContext,
    ParseError,
    ParseResult,
    make_component,
    walk_graph,
)
from dep_guard.adapters.safe_formats import (
    child_text,
    children,
    first,
    load_json_object,
    local_name,
    parse_xml,
)
from dep_guard.models import Problem, Scope
from dep_guard.textutil import clean, find_line

# ------------------------------------------------------------------- NuGet

_NUGET_EXACT_RANGE = re.compile(r"^\[\s*([^,\]\s]+)\s*\]$")
_NUGET_PLAIN = re.compile(r"^\d+(\.\d+){0,3}(-[0-9A-Za-z.-]+)?$")


def _nuget_version(raw: str | None) -> tuple[str | None, str | None]:
    if raw is None:
        return None, "version managed centrally (Directory.Packages.props) or not set"
    text = raw.strip()
    if "$(" in text:
        return None, f"MSBuild property ({clean(text, 60)})"
    exact = _NUGET_EXACT_RANGE.match(text)
    if exact:
        return exact.group(1), None
    if _NUGET_PLAIN.match(text):
        return text, None
    return None, f"version range ({clean(text, 60)}); enable packages.lock.json"


class NugetLockAdapter:
    id = "nuget-lock"

    def matches(self, filename: str, parent_dir: str) -> bool:
        return filename == "packages.lock.json"

    def parse(self, content: str, ctx: ParseContext) -> ParseResult:
        data = load_json_object(content)
        frameworks = data.get("dependencies")
        if not isinstance(frameworks, dict):
            raise ParseError("no `dependencies` map: not a NuGet packages.lock.json")
        nodes: dict[str, tuple[str, str]] = {}  # lower name -> (name, version)
        edges: dict[str, list[str]] = {}
        roots: list[str] = []
        projects: set[str] = set()
        for packages in frameworks.values():
            if not isinstance(packages, dict):
                continue
            for name, entry in packages.items():
                if not isinstance(entry, dict):
                    continue
                key = str(name).lower()
                kind = entry.get("type")
                if kind == "Project":
                    projects.add(key)
                    continue
                resolved = entry.get("resolved")
                if isinstance(resolved, str):
                    nodes.setdefault(key, (str(name), resolved))
                deps = entry.get("dependencies")
                if isinstance(deps, dict):
                    edges.setdefault(key, []).extend(str(d).lower() for d in deps)
                if kind == "Direct":
                    roots.append(key)
        graph = walk_graph(edges, roots, [], lambda n: nodes[n][0] if n in nodes else n)
        result = ParseResult()
        for key, (name, version) in nodes.items():
            if key in projects:
                continue
            info = graph.get(key)
            result.components.append(
                make_component(
                    "NuGet",
                    name,
                    version,
                    ctx,
                    find_line(content, f'"{name}"'),
                    info,
                    direct=info.direct if info else False,
                    # The lockfile does not record development-only references.
                    scope=Scope.UNKNOWN,
                )
            )
        return result


def _msbuild_refs(root: Element, element: str) -> list[tuple[str, str | None]]:
    refs: list[tuple[str, str | None]] = []
    for node in root.iter():
        if local_name(node.tag) != element:
            continue
        name = node.get("Include") or node.get("Update")
        if not name:
            continue
        version = node.get("Version") or child_text(node, "Version")
        refs.append((name, version))
    return refs


class MsbuildProjectAdapter:
    """*.csproj / *.fsproj / *.vbproj (PackageReference) and Directory.Packages.props."""

    id = "nuget-project"
    _SUFFIXES = (".csproj", ".fsproj", ".vbproj")

    def matches(self, filename: str, parent_dir: str) -> bool:
        return filename.endswith(self._SUFFIXES) or filename == "Directory.Packages.props"

    def parse(self, content: str, ctx: ParseContext) -> ParseResult:
        root = parse_xml(content)
        central = ctx.rel_path.endswith("Directory.Packages.props")
        refs = _msbuild_refs(root, "PackageVersion" if central else "PackageReference")
        result = ParseResult()
        for name, raw_version in refs:
            version, reason = _nuget_version(raw_version)
            result.components.append(
                make_component(
                    "NuGet",
                    name,
                    version,
                    ctx,
                    find_line(content, f'"{name}"'),
                    direct=True,
                    unresolved_reason=reason,
                )
            )
        if result.components:
            result.problems.append(
                Problem(
                    "no_lockfile",
                    "project file without packages.lock.json: only direct references are "
                    "visible; enable RestorePackagesWithLockFile for transitive coverage",
                    ctx.rel_path,
                )
            )
        return result


# ------------------------------------------------------------------- Maven

_PROPERTY = re.compile(r"\$\{([^}]+)\}")
_MAVEN_RANGE = re.compile(r"^[\[(].*[\])]$")


class PomAdapter:
    id = "maven-pom"

    def matches(self, filename: str, parent_dir: str) -> bool:
        return filename == "pom.xml"

    def parse(self, content: str, ctx: ParseContext) -> ParseResult:
        project = parse_xml(content)
        props: dict[str, str] = {}
        for prop in children(first(project, "properties"), "*"):
            if prop.text and prop.text.strip():
                props[local_name(prop.tag)] = prop.text.strip()
        parent = first(project, "parent")
        project_version = child_text(project, "version") or child_text(parent, "version")
        if project_version:
            props.setdefault("project.version", project_version)
            props.setdefault("pom.version", project_version)
        if parent is not None and child_text(parent, "version"):
            props.setdefault("project.parent.version", child_text(parent, "version") or "")
        group = child_text(project, "groupId") or child_text(parent, "groupId")
        if group:
            props.setdefault("project.groupId", group)

        def interpolate(text: str | None) -> str | None:
            if text is None:
                return None
            for _ in range(5):  # nested properties, bounded
                new = _PROPERTY.sub(lambda m: props.get(m.group(1), m.group(0)), text)
                if new == text:
                    break
                text = new
            return text

        managed: dict[str, str | None] = {}
        dm = first(project, "dependencyManagement")
        for dep in children(first(dm, "dependencies"), "dependency"):
            g, a = child_text(dep, "groupId"), child_text(dep, "artifactId")
            if g and a:
                managed[f"{interpolate(g)}:{interpolate(a)}"] = interpolate(
                    child_text(dep, "version")
                )

        result = ParseResult()
        for dep in children(first(project, "dependencies"), "dependency"):
            g = interpolate(child_text(dep, "groupId"))
            a = interpolate(child_text(dep, "artifactId"))
            if not g or not a:
                continue
            name = f"{g}:{a}"
            version = interpolate(child_text(dep, "version")) or managed.get(name)
            reason: str | None = None
            if version is None:
                reason = "version inherited from a parent POM or BOM (needs Maven to resolve)"
            elif "${" in version:
                reason = f"unresolved property ({clean(version, 60)})"
            elif _MAVEN_RANGE.match(version):
                reason = f"version range ({clean(version, 60)})"
            scope_text = (child_text(dep, "scope") or "compile").lower()
            scope = Scope.DEV if scope_text == "test" else Scope.PROD
            if scope_text == "system":
                reason = reason or "system-scoped local JAR"
            result.components.append(
                make_component(
                    "Maven",
                    name,
                    version,
                    ctx,
                    find_line(content, f"<artifactId>{child_text(dep, 'artifactId')}<"),
                    direct=True,
                    scope=scope,
                    unresolved_reason=reason,
                )
            )
        if result.components:
            result.problems.append(
                Problem(
                    "direct_only",
                    "pom.xml lists direct dependencies only; transitive ones need Maven "
                    "(scan a CycloneDX SBOM from cyclonedx-maven-plugin for full coverage)",
                    ctx.rel_path,
                )
            )
        return result


# ------------------------------------------------------------------ Gradle

_GRADLE_LINE = re.compile(r"^([^:\s#=]+):([^:\s=]+):([^:\s=]+)(?:=(.*))?$")


class GradleLockfileAdapter:
    id = "gradle-lockfile"

    def matches(self, filename: str, parent_dir: str) -> bool:
        if filename in ("gradle.lockfile", "buildscript-gradle.lockfile"):
            return True
        return parent_dir == "dependency-locks" and filename.endswith(".lockfile")

    def parse(self, content: str, ctx: ParseContext) -> ParseResult:
        buildscript = ctx.rel_path.rsplit("/", 1)[-1].startswith("buildscript")
        result = ParseResult()
        seen: set[tuple[str, str]] = set()
        for lineno, raw in enumerate(content.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("empty="):
                continue
            m = _GRADLE_LINE.match(line)
            if m is None:
                result.problems.append(
                    Problem(
                        "invalid_line", f"line {lineno}: not group:artifact:version", ctx.rel_path
                    )
                )
                continue
            group, artifact, version, confs = m.groups()
            configurations = [c.strip() for c in (confs or "").split(",") if c.strip()]
            test_only = bool(configurations) and all(c.startswith("test") for c in configurations)
            scope = Scope.DEV if buildscript or test_only else Scope.PROD
            name = f"{group}:{artifact}"
            if (name, version) in seen:
                continue
            seen.add((name, version))
            result.components.append(
                make_component("Maven", name, version, ctx, lineno, scope=scope)
            )
        return result
