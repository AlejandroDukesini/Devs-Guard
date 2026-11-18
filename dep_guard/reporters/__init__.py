"""Output formats. Each has one purpose:

- table:     humans in a terminal
- json:      automation and integrations (stable schema depguard.report/v1)
- sarif:     GitHub code scanning / security dashboards
- cyclonedx: SBOM + VEX exchange with other supply-chain tools
- spdx:      SBOM for tools and processes that require SPDX 2.3
"""

FORMATS = ("table", "json", "sarif", "cyclonedx", "spdx")
