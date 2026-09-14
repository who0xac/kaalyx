"""The orchestrator — top-level scan driver.

Responsibilities:

* Build the :class:`ScanContext` (wire up runner, repo, writer, rate limiter, notifier).
* Decide the stage sequence based on target type (an apex runs every stage; a bare
  subdomain skips subdomain enumeration).
* Create or resume a scan via the checkpoint store, so a crashed run continues from the
  last completed stage instead of restarting from zero.
* Run each stage inside a guard that records ``stage_runs`` state, isolates exceptions
  (one failed stage never aborts the scan), times execution, and checkpoints on success.
* Emit start / progress / final Telegram notifications and print a rich summary.

Stages are supplied as *factories* (``stage_class`` list) so the orchestrator stays
decoupled from concrete stage implementations — new stages are registered in one list.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Callable

from rich.table import Table

from ..config import Config, Secrets, resolve_paths
from ..data.db import connect
from ..data.repository import Repository
from ..data.writers import ResultWriter
from ..notify.telegram import TelegramNotifier
from .checkpoint import Checkpoint, CheckpointStore
from .context import ScanContext, ScanOptions
from .logging import attach_file_handler, get_console, get_logger
from .ratelimit import AdaptiveRateLimiter
from .runner import SubprocessRunner
from .stage import Stage, StageResult
from .target import Target, TargetType

logger = get_logger("orchestrator")

# A stage factory takes the context and returns a Stage instance.
StageFactory = Callable[[ScanContext], Stage]


@dataclass
class ScanReport:
    """Aggregate outcome of a whole scan, returned by :meth:`Orchestrator.run`."""

    scan_id: int
    domain: str
    status: str
    stage_results: list[StageResult]
    counts: dict[str, int]


class Orchestrator:
    """Drives a single scan from start to finish."""

    def __init__(
        self,
        target: Target,
        options: ScanOptions,
        config: Config,
        secrets: Secrets,
        stage_factories: list[StageFactory],
    ) -> None:
        self.target = target
        self.options = options
        self.config = config
        self.secrets = secrets
        self.stage_factories = stage_factories
        self.console = get_console()

        # Shared services. Paths resolve to <output_root>/<domain>/ by default so a scan
        # is self-contained (raw .txt + per-domain kaalyx.db + checkpoint) — see
        # config.resolve_paths. Per-domain DB persistence is what lets a re-scan diff
        # against history for continuous monitoring.
        results_dir, database_path, checkpoint_dir = resolve_paths(config, target.slug)
        self._db = connect(database_path)
        self.repo = Repository(self._db)
        self.writer = ResultWriter(results_dir, target.slug)
        self.checkpoints = CheckpointStore(checkpoint_dir)
        self.notifier = TelegramNotifier.create(config, secrets)

        sem = asyncio.Semaphore(config.concurrency.max_parallel_tools)
        self.runner = SubprocessRunner(
            sem, default_timeout=config.concurrency.default_tool_timeout
        )
        self.rate_limiter = AdaptiveRateLimiter(
            chunk_size=config.rate_limit.chunk_size,
            backoff_factor=config.rate_limit.backoff_factor,
            max_delay_seconds=config.rate_limit.max_delay_seconds,
            max_retries=config.rate_limit.max_retries,
        )

    # -- stage sequencing --------------------------------------------------------------

    def _planned_stages(self) -> list[StageFactory]:
        """Filter the stage list for this target.

        A bare subdomain skips the subdomain-enumeration stage (whose ``name`` is
        ``"subdomains"``); everything else runs. We peek at the stage name by
        instantiating against a throwaway probe is overkill — instead each stage class
        exposes its ``name`` as a class attribute, so we read it off the factory's
        ``__stage_name__`` marker when present, falling back to running the stage.
        """
        if self.target.target_type is TargetType.APEX:
            return self.stage_factories
        planned: list[StageFactory] = []
        for factory in self.stage_factories:
            name = getattr(factory, "__stage_name__", None)
            if name == "subdomains":
                logger.info("Target is a subdomain — skipping subdomain enumeration.")
                continue
            planned.append(factory)
        return planned

    # -- resume ------------------------------------------------------------------------

    def _load_or_create_checkpoint(self, resume: bool) -> Checkpoint:
        existing = self.checkpoints.load(self.target.slug) if resume else None
        if existing is not None:
            logger.info(
                "Resuming scan #%d for %s (completed: %s)",
                existing.scan_id,
                self.target.domain,
                ", ".join(existing.completed_stages) or "none",
            )
            return existing

        scan_id = self.repo.create_scan(
            self.target.domain,
            self.target.registrable,
            self.target.target_type.value,
            self.options.as_dict(),
        )
        cp = Checkpoint(
            domain=self.target.domain,
            slug=self.target.slug,
            scan_id=scan_id,
            options=self.options.as_dict(),
        )
        self.checkpoints.save(cp)
        return cp

    # -- main entry --------------------------------------------------------------------

    async def run(self, *, resume: bool = False) -> ScanReport:
        """Execute the planned stages and return a :class:`ScanReport`."""
        attach_file_handler(self.writer.log_path())
        checkpoint = self._load_or_create_checkpoint(resume)
        scan_id = checkpoint.scan_id

        ctx = ScanContext(
            scan_id=scan_id,
            target=self.target,
            options=self.options,
            config=self.config,
            secrets=self.secrets,
            runner=self.runner,
            repo=self.repo,
            writer=self.writer,
            rate_limiter=self.rate_limiter,
            notifier=self.notifier,
        )

        logger.info(
            "[kaalyx.stage]Scan #%d[/] starting for %s (%s)",
            scan_id,
            self.target.domain,
            self.target.target_type.value,
        )
        await self.notifier.scan_started(
            self.target.domain, self.target.target_type.value, self.options.as_dict()
        )

        stage_results: list[StageResult] = []
        overall_status = "completed"

        try:
            for factory in self._planned_stages():
                stage = factory(ctx)
                if checkpoint.is_complete(stage.name):
                    logger.info(
                        "[kaalyx.stage]%s[/] already complete — skipping (resume).",
                        stage.name,
                    )
                    self.repo.finish_stage(scan_id, stage.name, "skipped", "resumed")
                    stage_results.append(
                        StageResult(stage.name, ok=True, skipped=True, detail="resumed")
                    )
                    continue

                result = await self._run_stage(scan_id, stage)
                stage_results.append(result)

                if result.ok and not result.skipped:
                    checkpoint.mark_complete(stage.name)
                    self.checkpoints.save(checkpoint)

                # Live progress ping after each stage.
                if result.counts:
                    await self.notifier.progress(
                        self.target.domain, f"{stage.name} complete", result.counts
                    )
        except asyncio.CancelledError:
            overall_status = "aborted"
            logger.warning("Scan cancelled — state checkpointed for resume.")
            raise
        except Exception as exc:  # pragma: no cover - defensive
            overall_status = "failed"
            logger.exception("Scan aborted by unexpected error: %s", exc)
        finally:
            counts = self.repo.scan_counts(scan_id)
            if overall_status != "aborted":
                if any(not r.ok and not r.skipped for r in stage_results):
                    overall_status = (
                        "completed" if overall_status == "completed" else overall_status
                    )
                self.repo.finish_scan(scan_id, overall_status)
                if overall_status == "completed":
                    # Whole pipeline done: clear the resume checkpoint.
                    self.checkpoints.clear(self.target.slug)
                await self.notifier.scan_finished(
                    self.target.domain, overall_status, counts
                )

        self._print_summary(scan_id, stage_results, counts)
        return ScanReport(
            scan_id=scan_id,
            domain=self.target.domain,
            status=overall_status,
            stage_results=stage_results,
            counts=counts,
        )

    async def _run_stage(self, scan_id: int, stage: Stage) -> StageResult:
        """Run a single stage under full lifecycle bookkeeping + exception isolation."""
        logger.info("[kaalyx.stage]%s[/] running…", stage.name)
        self.repo.start_stage(scan_id, stage.name)
        try:
            result = await stage.timed_run()
        except Exception as exc:  # pragma: no cover - timed_run already guards
            logger.exception("[kaalyx.stage]%s[/] crashed: %s", stage.name, exc)
            result = StageResult(stage.name, ok=False, detail=f"{type(exc).__name__}: {exc}")

        status = "completed" if result.ok else "failed"
        if result.skipped:
            status = "skipped"
        self.repo.finish_stage(scan_id, stage.name, status, result.detail)
        logger.info("[kaalyx.stage]%s[/] %s", stage.name, result.summary_line())
        return result

    def _print_summary(
        self, scan_id: int, results: list[StageResult], counts: dict[str, int]
    ) -> None:
        table = Table(title=f"Kaalyx scan #{scan_id} — {self.target.domain}")
        table.add_column("Stage", style="cyan")
        table.add_column("Status")
        table.add_column("Items")
        table.add_column("Time", justify="right")
        for r in results:
            status = (
                "[yellow]skipped[/]"
                if r.skipped
                else ("[green]ok[/]" if r.ok else "[red]failed[/]")
            )
            items = ", ".join(f"{k}={v}" for k, v in r.counts.items()) or "-"
            table.add_row(r.stage, status, items, f"{r.duration_s:.1f}s")
        self.console.print(table)

        totals = Table(title="Totals", show_header=False)
        for key in ("subdomains", "hosts", "web_urls", "findings", "osint"):
            totals.add_row(key, str(counts.get(key, 0)))
        for sev in ("critical", "high", "medium", "low", "info"):
            n = counts.get(f"sev_{sev}", 0)
            if n:
                totals.add_row(f"findings.{sev}", str(n))
        self.console.print(totals)

    def close(self) -> None:
        try:
            self._db.close()
        except Exception:  # pragma: no cover
            pass
