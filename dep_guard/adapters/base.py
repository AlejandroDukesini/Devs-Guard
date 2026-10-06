"""Adapter contract: one adapter per manifest/lockfile format.

An adapter turns file *content* into Components. It never touches the
network, never executes anything and never reads files other than the
siblings explicitly offered through ParseContext.read_sibling.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Protocol

from dep_guard.models import Component, Location, Problem, Scope


class ParseError(Exception):
    """The file is malformed: its dependencies cannot be determined."""


@dataclass(slots=True)
class ParseContext:
    rel_path: str
    read_sibling: Callable[[str], str | None] = lambda _name: None


@dataclass(slots=True)
class ParseResult:
    components: list[Component] = field(default_factory=list)
    problems: list[Problem] = field(default_factory=list)


class Adapter(Protocol):
    id: str

    def matches(self, filename: str, parent_dir: str) -> bool: ...

    def parse(self, content: str, ctx: ParseContext) -> ParseResult: ...


@dataclass(slots=True)
class GraphInfo:
    direct: bool
    scope: Scope
    path: list[str]


def walk_graph(
    edges: dict[str, list[str]],
    prod_roots: Iterable[str],
    dev_roots: Iterable[str],
    label: Callable[[str], str],
) -> dict[str, GraphInfo]:
    """BFS over a dependency graph.

    Production roots are walked first so a package reachable from both a
    production and a development dependency is classified as production
    (the conservative choice). Each node gets the shortest path from a
    direct dependency, which is what a developer needs to see to understand
    why a transitive package is installed.
    """
    prod_roots, dev_roots = list(prod_roots), list(dev_roots)
    direct = set(prod_roots) | set(dev_roots)
    info: dict[str, GraphInfo] = {}
    for roots, scope in ((prod_roots, Scope.PROD), (dev_roots, Scope.DEV)):
        queue: deque[str] = deque()
        for root in roots:
            if root not in info:
                info[root] = GraphInfo(True, scope, [label(root)])
                queue.append(root)
        while queue:
            node = queue.popleft()
            for child in edges.get(node, []):
                if child in info:
                    continue
                info[child] = GraphInfo(child in direct, scope, [*info[node].path, label(child)])
                queue.append(child)
    return info


def location(ctx: ParseContext, line: int | None) -> list[Location]:
    return [Location(ctx.rel_path, line)]
