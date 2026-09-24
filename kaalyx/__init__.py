"""Kaalyx — automated bug-bounty reconnaissance & vulnerability-discovery pipeline.

Kaalyx orchestrates 40+ external CLI recon/vuln tools for a single target domain,
persisting findings to both SQLite and raw files, and surfacing them through a local
web dashboard and Telegram alerts. It is an *orchestrator* — external tools are always
invoked as subprocesses, never reimplemented.
"""

__version__ = "1.2.0"
