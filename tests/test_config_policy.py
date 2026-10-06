from __future__ import annotations

import datetime as dt
from typing import Any

import pytest

from dep_guard.config import ConfigError, parse
from dep_guard.models import Priority, Severity
from tests.conftest import TODAY


def _cfg(data: dict[str, Any]):  # type: ignore[no-untyped-def]
    return parse(data, TODAY)


def test_defaults_are_secure() -> None:
    cfg = _cfg({})
    assert cfg.fail_on_priority is Priority.P1
    assert cfg.fail_on_kev and cfg.fail_on_incomplete and cfg.fail_on_expired_ignore


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"policy": {"fail_on_kevv": True}}, "unknown key"),
        ({"polcy": {}}, "unknown section"),
        ({"policy": {"fail_on_kev": "yes"}}, "wrong type"),
        ({"sources": {"retries": True}}, "wrong type"),
        ({"policy": {"fail_on_priority": "P9"}}, "must be one of"),
        ({"risk": {"epss_threshold": 2}}, "between 0 and 1"),
        ({"sources": {"timeout": 0}}, "between 1 and 300"),
        ({"policy": {"fail_on_severity": "unknown"}}, "cannot be UNKNOWN"),
        (
            {"ignore": [{"id": "CVE-1", "reason": "short", "expires": dt.date(2099, 2, 1)}]},
            "reason",
        ),
        ({"ignore": [{"id": "CVE-1", "reason": "long enough reason"}]}, "expires"),
        ({"ignore": [{"reason": "long enough reason", "expires": dt.date(2099, 2, 1)}]}, "id"),
        (
            {
                "ignore": [
                    {"id": "CVE-1", "reason": "long enough reason", "expires": dt.date(2150, 1, 1)}
                ]
            },
            "permanent ignores are not allowed",
        ),
        (
            {
                "ignore": [
                    {"id": "CVE-1", "reason": "long enough reason", "expires": "2099-02-01", "x": 1}
                ]
            },
            "unknown key",
        ),
    ],
)
def test_invalid_config_is_rejected(data: dict[str, Any], message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        _cfg(data)


def test_valid_config() -> None:
    cfg = _cfg(
        {
            "policy": {"fail_on_priority": "none", "fail_on_severity": "critical"},
            "ignore": [
                {
                    "package": "acme-qs",
                    "reason": "documented reason",
                    "expires": "2099-03-01",
                    "owner": "me",
                }
            ],
        }
    )
    assert cfg.fail_on_priority is None
    assert cfg.fail_on_severity is Severity.CRITICAL
    assert cfg.ignores[0].expires == dt.date(2099, 3, 1)
