"""Hardened loaders for the data formats adapters read from untrusted repositories.

- JSON/TOML come from the standard library and build only plain data.
- YAML (pnpm-lock.yaml, Yarn Berry yarn.lock): `SafeLoader` only builds plain
  data, but it still expands aliases, so a few hundred bytes of nested
  aliases ("billion laughs") can exhaust memory. No lockfile format we read
  uses anchors or aliases, so any alias is rejected before construction.
- XML (pom.xml, *.csproj, Directory.Packages.props, maven-metadata.xml):
  ElementTree never fetches external entities, and documents with a
  DOCTYPE are rejected outright, which removes internal entity expansion
  (XXE, billion laughs) entirely. None of these formats needs a DTD.
"""

from __future__ import annotations

import json
import re
import tomllib

# Safe here: documents with a DTD are refused before parsing (see _NO_DTD).
import xml.etree.ElementTree as ET  # nosec B405
from typing import Any

import yaml

from dep_guard.adapters.base import ParseError
from dep_guard.textutil import clean

_Loader: type[yaml.SafeLoader] = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
_NO_DTD = re.compile(r"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)


def load_json_object(content: str) -> dict[str, Any]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid JSON at line {exc.lineno}") from None
    if not isinstance(data, dict):
        raise ParseError("top-level JSON value is not an object")
    return data


def load_toml(content: str) -> dict[str, Any]:
    try:
        return tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        raise ParseError(f"invalid TOML: {clean(str(exc), 120)}") from None


def load_yaml_mapping(content: str) -> dict[str, Any]:
    try:
        for event in yaml.parse(content, Loader=_Loader):
            if isinstance(event, yaml.AliasEvent):
                raise ParseError("YAML aliases are not allowed in lockfiles")
        # _Loader is (C)SafeLoader: plain data only, aliases rejected above.
        data = yaml.load(content, Loader=_Loader)  # noqa: S506  # nosec B506
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" at line {mark.line + 1}" if mark is not None else ""
        raise ParseError(f"invalid YAML{where}") from None
    if not isinstance(data, dict):
        raise ParseError("top-level YAML value is not a mapping")
    return data


def parse_xml(content: str) -> ET.Element:
    if _NO_DTD.search(content):
        raise ParseError("XML with a DOCTYPE or ENTITY declaration is refused")
    try:
        # No DTD can reach this point (checked above), so no entity expansion.
        return ET.fromstring(content)  # noqa: S314  # nosec B314
    except ET.ParseError as exc:
        raise ParseError(f"invalid XML: {clean(str(exc), 120)}") from None


def local_name(tag: object) -> str:
    """Element name without its XML namespace ("{ns}dependency" -> "dependency")."""
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def child_text(elem: ET.Element | None, name: str) -> str | None:
    if elem is None:
        return None
    for child in elem:
        if local_name(child.tag) == name:
            text = (child.text or "").strip()
            return text or None
    return None


def children(elem: ET.Element | None, name: str) -> list[ET.Element]:
    if elem is None:
        return []
    return [c for c in elem if name == "*" or local_name(c.tag) == name]


def first(elem: ET.Element | None, name: str) -> ET.Element | None:
    found = children(elem, name)
    return found[0] if found else None
