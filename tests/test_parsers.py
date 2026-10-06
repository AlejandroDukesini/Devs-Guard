"""Legacy 0.x API (dep_guard.parsers) keeps working, minus the version-guessing bug."""

from __future__ import annotations

import pytest

from dep_guard.parsers import parse_package_json, parse_requirements_txt

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


def test_parse_requirements_txt_returns_only_exact_pins() -> None:
    content = """
    # Comentario de prueba
    requests==2.28.1
    flask>=2.0.0
    urllib3!=1.25.0
    """
    # Before 1.0 this returned flask 2.0.0 and urllib3 1.25.0 (the *excluded*
    # version), i.e. versions that are not installed. They are now unresolved.
    assert parse_requirements_txt(content) == [
        {"name": "requests", "version": "2.28.1", "ecosystem": "PyPI"}
    ]


def test_parse_package_json_returns_only_exact_versions() -> None:
    content = """
    {
      "name": "sample-project",
      "dependencies": {"express": "^4.18.2", "lodash": "~4.17.21"},
      "devDependencies": {"jest": "29.5.0"}
    }
    """
    assert parse_package_json(content) == [
        {"name": "jest", "version": "29.5.0", "ecosystem": "npm"}
    ]


def test_legacy_api_warns() -> None:
    with pytest.warns(DeprecationWarning):
        parse_requirements_txt("a==1")
