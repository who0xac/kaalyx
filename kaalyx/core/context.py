"""ScanContext — the shared state object threaded through every stage.

Rather than give each stage a grab-bag of positional arguments, the orchestrator builds
one :class:`ScanContext` and passes it to every stage. It bundles the immutable scan
inputs (target, config, secrets, options) with the shared services stages need (the
subprocess runner, the repository, the raw-file writer, the rate limiter, and the
Telegram notifier), plus a small mutable ``shared`` dict for passing derived data
*between* stages (e.g. the list of live hosts the web stage needs from the hosts stage).

Keeping this in one place means a stage never constructs its own runner or opens its own
DB connection — it uses what the orchestrator wired up, so concurrency limits and
persistence stay consistent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..config import Config, Secrets
    from ..data.repository import Repository
    from ..data.writers import ResultWriter
    from ..notify.telegram import TelegramNotifier
    from .ratelimit import AdaptiveRateLimiter
    from .runner import SubprocessRunner
    from .target import Target


@dataclass
class ScanOptions:
    """The opt-in flags that shape a run (mirrors ``config.scan`` + CLI overrides)."""

    full_nmap: bool = False
    brutespray: bool = False
    ipv6: bool = False
    sqlmap: bool = False

    def as_dict(self) -> dict[str, bool]:
        return {
            "full_nmap": self.full_nmap,
            "brutespray": self.brutespray,
            "ipv6": self.ipv6,
            "sqlmap": self.sqlmap,
        }


@dataclass
class ScanContext:
    """Everything a stage needs to do its work.

    Attributes:
        scan_id: The current scan's database id.
        target: The parsed, classified :class:`~kaalyx.core.target.Target`.
        options: Opt-in flags for this run.
        config: Loaded settings.
        secrets: API keys / tokens (missing ones disable their source gracefully).
        runner: Shared async subprocess runner (enforces the global concurrency limit).
        repo: Persistence gateway (SQLite).
        writer: Raw ``.txt`` file writer (``results/<domain>/<stage>/``).
        rate_limiter: Adaptive rate limiter shared by request-heavy stages.
        notifier: Telegram notifier (a no-op stub when Telegram is disabled/unconfigured).
        interactsh: OOB payload domain from the background interactsh listener, if running.
        shared: Free-form dict for passing derived data between stages.
    """

    scan_id: int
    target: "Target"
    options: ScanOptions
    config: "Config"
    secrets: "Secrets"
    runner: "SubprocessRunner"
    repo: "Repository"
    writer: "ResultWriter"
    rate_limiter: "AdaptiveRateLimiter"
    notifier: "TelegramNotifier"
    interactsh: str | None = None
    shared: dict[str, Any] = field(default_factory=dict)

    # -- convenience accessors ---------------------------------------------------------

    @property
    def domain(self) -> str:
        return self.target.domain

    def stage_dir(self, stage: str) -> Path:
        """The raw-output directory for *stage* (via the writer)."""
        return self.writer.stage_dir(stage)

    def get_shared(self, key: str, default: Any = None) -> Any:
        return self.shared.get(key, default)

    def set_shared(self, key: str, value: Any) -> None:
        self.shared[key] = value
