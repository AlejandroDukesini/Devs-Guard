"""Configuration file (depguard.toml) with strict validation.

Unknown keys are errors, not silently ignored: a typo like `fail_on_kevv`
must not quietly weaken a security gate.
"""

from __future__ import annotations

import datetime as dt
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dep_guard.models import Priority, Severity
from dep_guard.risk import DEFAULT_EPSS_THRESHOLD

CONFIG_NAMES = ("depguard.toml", ".depguard.toml")
MAX_CONFIG_BYTES = 1024 * 1024


class ConfigError(Exception):
    pass


@dataclass(slots=True)
class IgnoreRule:
    reason: str
    expires: dt.date
    id: str | None = None
    package: str | None = None
    owner: str | None = None
    index: int = 0  # position in the file, for messages

    def describe(self) -> str:
        target = " ".join(p for p in (self.id, self.package and f"package={self.package}") if p)
        return f"ignore #{self.index + 1} ({target})"


@dataclass(slots=True)
class Config:
    exclude: list[str] = field(default_factory=list)
    epss: bool = True
    kev: bool = True
    timeout: float = 20.0
    retries: int = 3
    cache: bool = True
    private_packages: list[str] = field(default_factory=list)
    epss_threshold: float = DEFAULT_EPSS_THRESHOLD
    fail_on_priority: Priority | None = Priority.P1
    fail_on_severity: Severity | None = None
    fail_on_kev: bool = True
    fail_on_incomplete: bool = True
    fail_on_unresolved: bool = False
    fail_on_expired_ignore: bool = True
    include_dev: bool = True
    max_ignore_days: int = 365
    ignores: list[IgnoreRule] = field(default_factory=list)
    source: str | None = None  # path of the loaded file


_SCHEMA: dict[str, dict[str, type | tuple[type, ...]]] = {
    "scan": {"exclude": list},
    "sources": {
        "epss": bool,
        "kev": bool,
        "timeout": (int, float),
        "retries": int,
        "cache": bool,
        "private_packages": list,
    },
    "risk": {"epss_threshold": (int, float)},
    "policy": {
        "fail_on_priority": str,
        "fail_on_severity": str,
        "fail_on_kev": bool,
        "fail_on_incomplete": bool,
        "fail_on_unresolved": bool,
        "fail_on_expired_ignore": bool,
        "include_dev": bool,
        "max_ignore_days": int,
    },
}
_IGNORE_KEYS = {"id", "package", "reason", "expires", "owner"}


def find_config(scan_root: Path) -> Path | None:
    for name in CONFIG_NAMES:
        candidate = scan_root / name
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    return None


def load(path: Path | None, today: dt.date | None = None) -> Config:
    if path is None:
        return Config()
    try:
        if path.stat().st_size > MAX_CONFIG_BYTES:
            raise ConfigError(f"{path.name}: config file too large")
        data = tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc.strerror}") from None
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path.name}: invalid TOML: {exc}") from None
    cfg = parse(data, today)
    cfg.source = str(path)
    return cfg


def parse(data: dict[str, Any], today: dt.date | None = None) -> Config:
    today = today or dt.date.today()
    cfg = Config()
    for section, value in data.items():
        if section == "ignore":
            continue
        if section not in _SCHEMA:
            raise ConfigError(f"unknown section [{section}]")
        if not isinstance(value, dict):
            raise ConfigError(f"[{section}] must be a table")
        for key, item in value.items():
            expected = _SCHEMA[section].get(key)
            if expected is None:
                raise ConfigError(f"unknown key {section}.{key}")
            if not isinstance(item, expected) or (expected is not bool and isinstance(item, bool)):
                raise ConfigError(f"{section}.{key} has the wrong type")
            _apply(cfg, section, key, item)
    _validate_ranges(cfg)
    cfg.ignores = _parse_ignores(data.get("ignore", []), cfg.max_ignore_days, today)
    return cfg


def _apply(cfg: Config, section: str, key: str, item: Any) -> None:
    if section == "scan":
        cfg.exclude = _strings(item, "scan.exclude")
    elif section == "sources":
        if key == "private_packages":
            cfg.private_packages = _strings(item, "sources.private_packages")
        else:
            setattr(cfg, key, float(item) if key == "timeout" else item)
    elif section == "risk":
        cfg.epss_threshold = float(item)
    elif key == "fail_on_priority":
        cfg.fail_on_priority = (
            None if item.lower() == "none" else _enum(Priority, item.upper(), key)
        )
    elif key == "fail_on_severity":
        cfg.fail_on_severity = (
            None if item.lower() == "none" else _enum(Severity, item.upper(), key)
        )
    else:
        setattr(cfg, key, item)


def _validate_ranges(cfg: Config) -> None:
    if not 0.0 <= cfg.epss_threshold <= 1.0:
        raise ConfigError("risk.epss_threshold must be between 0 and 1")
    if not 1.0 <= cfg.timeout <= 300.0:
        raise ConfigError("sources.timeout must be between 1 and 300 seconds")
    if not 0 <= cfg.retries <= 10:
        raise ConfigError("sources.retries must be between 0 and 10")
    if not 1 <= cfg.max_ignore_days <= 3650:
        raise ConfigError("policy.max_ignore_days must be between 1 and 3650")
    if cfg.fail_on_severity is Severity.UNKNOWN:
        raise ConfigError("policy.fail_on_severity cannot be UNKNOWN")


def _parse_ignores(raw: Any, max_days: int, today: dt.date) -> list[IgnoreRule]:
    if not isinstance(raw, list):
        raise ConfigError("[[ignore]] entries must be an array of tables")
    rules: list[IgnoreRule] = []
    for i, entry in enumerate(raw):
        where = f"ignore #{i + 1}"
        if not isinstance(entry, dict):
            raise ConfigError(f"{where} must be a table")
        unknown = set(entry) - _IGNORE_KEYS
        if unknown:
            raise ConfigError(f"{where}: unknown key(s) {', '.join(sorted(unknown))}")
        vid, package = entry.get("id"), entry.get("package")
        if not (isinstance(vid, str) and vid) and not (isinstance(package, str) and package):
            raise ConfigError(f"{where}: needs `id` and/or `package`")
        reason = entry.get("reason")
        if not isinstance(reason, str) or len(reason.strip()) < 10:
            raise ConfigError(f"{where}: `reason` is required (at least 10 characters)")
        expires = _date(entry.get("expires"), where)
        if expires > today + dt.timedelta(days=max_days):
            raise ConfigError(
                f"{where}: expires {expires} is more than {max_days} days ahead "
                "(policy.max_ignore_days); permanent ignores are not allowed"
            )
        owner = entry.get("owner")
        if owner is not None and not isinstance(owner, str):
            raise ConfigError(f"{where}: `owner` must be a string")
        rules.append(
            IgnoreRule(
                reason=reason.strip(),
                expires=expires,
                id=vid if isinstance(vid, str) and vid else None,
                package=package if isinstance(package, str) and package else None,
                owner=owner,
                index=i,
            )
        )
    return rules


def _date(value: Any, where: str) -> dt.date:
    if isinstance(value, dt.datetime):
        return value.date()
    if isinstance(value, dt.date):
        return value
    if isinstance(value, str):
        try:
            return dt.date.fromisoformat(value)
        except ValueError:
            pass
    raise ConfigError(f"{where}: `expires` is required as a date (YYYY-MM-DD)")


def _strings(value: list[Any], key: str) -> list[str]:
    if not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{key} must be a list of strings")
    return list(value)


def _enum(enum: Any, value: str, key: str) -> Any:
    try:
        return enum(value)
    except ValueError:
        allowed = ", ".join(e.value for e in enum)
        raise ConfigError(f"policy.{key} must be one of: {allowed}, none") from None
