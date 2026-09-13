"""Stage base class and result type.

A *stage* is one part of the pipeline (OSINT, Subdomains, Hosts, Web, Vulns). Each stage
subclasses :class:`Stage`, implements :meth:`run`, and returns a :class:`StageResult`
summarising what it produced. The orchestrator handles the surrounding lifecycle —
checkpoint skipping, ``stage_runs`` bookkeeping, exception isolation, timing — so stages
focus purely on *doing the work* and persisting via the context's repo/writer.

The cardinal rule: a stage should catch and log its own per-tool
failures and keep going. If a stage raises, the orchestrator records it as failed and
moves on to the next stage rather than aborting the scan.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from .context import ScanContext
from .logging import get_logger


@dataclass
class StageResult:
    """Summary of a stage's execution, returned to the orchestrator.

    ``counts`` is a small dict of item-type -> number produced (e.g.
    ``{"subdomains": 412}``) used for the log line, the Telegram progress update, and the
    dashboard. ``ok`` reflects whether the stage completed without an unrecoverable error;
    individual tool failures inside a successful stage do not make it ``False``.
    """

    stage: str
    ok: bool = True
    counts: dict[str, int] = field(default_factory=dict)
    detail: str = ""
    duration_s: float = 0.0
    skipped: bool = False

    def summary_line(self) -> str:
        if self.skipped:
            return f"{self.stage}: skipped ({self.detail})"
        parts = ", ".join(f"{k}={v}" for k, v in self.counts.items()) or "no items"
        status = "ok" if self.ok else "failed"
        return f"{self.stage}: {status} — {parts} ({self.duration_s:.1f}s)"


class Stage(ABC):
    """Abstract base for a pipeline stage.

    Subclasses set :attr:`name` (the stable stage key used for checkpoints, DB rows, and
    the ``results/<domain>/<name>/`` directory) and implement :meth:`run`.
    """

    #: Stable stage key — must match the value used in checkpoints and the DB.
    name: str = "stage"

    def __init__(self, ctx: ScanContext) -> None:
        self.ctx = ctx
        self.log = get_logger(f"stages.{self.name}")

    @abstractmethod
    async def run(self) -> StageResult:
        """Execute the stage. Implementations persist their own output via ``self.ctx``.

        Should not need to touch timing or ``stage_runs`` — the orchestrator wraps this.
        """

    # -- helpers available to all stages ----------------------------------------------

    def result(self, **kwargs) -> StageResult:
        """Build a :class:`StageResult` for this stage (fills in ``stage=self.name``)."""
        return StageResult(stage=self.name, **kwargs)

    async def timed_run(self) -> StageResult:
        """Run the stage, timing it and turning an unexpected exception into a failed
        result rather than propagating (the orchestrator also guards, belt-and-braces)."""
        start = time.monotonic()
        try:
            result = await self.run()
        except Exception as exc:  # pragma: no cover - defensive; orchestrator also guards
            self.log.exception("Stage '%s' raised: %s", self.name, exc)
            result = self.result(ok=False, detail=f"{type(exc).__name__}: {exc}")
        result.duration_s = time.monotonic() - start
        return result
