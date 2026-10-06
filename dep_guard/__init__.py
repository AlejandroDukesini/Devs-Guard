"""DepGuard: dependency vulnerability scanner with explainable prioritisation.

Library usage::

    from dep_guard import scan
    report = scan("path/to/project")
    print(report.policy.verdict, report.exit_code)
"""

__version__ = "1.0.0b1"


def scan(target, options=None):  # type: ignore[no-untyped-def]
    """Scan a directory or file. See dep_guard.engine.scan."""
    from dep_guard.engine import scan as _scan  # noqa: PLC0415 - keeps `import dep_guard` cheap

    return _scan(target, options)


__all__ = ["__version__", "scan"]
