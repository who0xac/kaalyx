"""Shared machinery for running many independent "sources" concurrently within a stage.

Several stages (OSINT especially) are really a *fan-out* of independent data sources:
WHOIS, DNS, SPF/DMARC, github-subdomains, trufflehog, cloud_enum, … Each is independent,
each may fail, and — per the cardinal rule — one failing source
must never take down the others or the scan.

This module provides:

* :class:`SourceResult` — the normalised bundle a source returns (subdomains, hosts,
  URLs, OSINT records, findings) plus its own ok/error state and timing.
* :func:`run_sources` — runs a list of named async source callables concurrently, isolates
  every exception into a failed :class:`SourceResult`, and returns them all so the stage
  can persist results and log which sources failed.

A "source" is any ``async def f(ctx) -> SourceResult`` (or a partial/closure over ctx).
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from ..core.logging import get_logger
from ..data.models import Email, Employee, Finding, Host, OsintRecord, Subdomain, WebURL

logger = get_logger("sources")

SourceFn = Callable[[], Awaitable["SourceResult"]]

# Progress hook: called with (event, name, result_or_None).
#   event="start"  -> a source began (result is None)
#   event="finish" -> a source finished (result is the SourceResult)
# Lets a UI layer render live per-source spinners without coupling sources to rich.
ProgressHook = Callable[[str, str, "SourceResult | None"], None]


@dataclass
class SourceResult:
    """What a single source produced.

    A source appends to the relevant lists; the stage then persists them in bulk. Keeping
    every record type on one result object lets a source contribute to several tables
    (e.g. a DNS source yields both OSINT records and, indirectly, host hints).
    """

    name: str
    ok: bool = True
    error: str | None = None
    duration_s: float = 0.0
    subdomains: list[Subdomain] = field(default_factory=list)
    hosts: list[Host] = field(default_factory=list)
    urls: list[WebURL] = field(default_factory=list)
    osint: list[OsintRecord] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    emails: list[Email] = field(default_factory=list)
    employees: list[Employee] = field(default_factory=list)
    skipped: bool = False  # True when the source chose not to run (missing tool/key)
    note: str = ""  # short human summary for logs, e.g. "skipped: no GITHUB_TOKEN"

    @property
    def total(self) -> int:
        return (
            len(self.subdomains)
            + len(self.hosts)
            + len(self.urls)
            + len(self.osint)
            + len(self.findings)
            + len(self.emails)
            + len(self.employees)
        )


async def _guarded(
    name: str, fn: SourceFn, progress: ProgressHook | None = None
) -> SourceResult:
    """Run one source, converting any exception into a failed SourceResult."""
    start = time.monotonic()
    if progress is not None:
        try:
            progress("start", name, None)
        except Exception:  # pragma: no cover - a UI hook must never break a source
            pass
    try:
        result = await fn()
        result.name = name  # ensure the name is set even if the source forgot
        result.duration_s = time.monotonic() - start
        if result.ok:
            extra = f" — {result.note}" if result.note else ""
            logger.info("source %s: %d item(s) in %.1fs%s",
                        name, result.total, result.duration_s, extra)
        else:
            logger.warning("source %s: failed — %s", name, result.error or result.note)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - deliberate: isolate every source failure
        duration = time.monotonic() - start
        logger.warning("source %s raised %s: %s", name, type(exc).__name__, exc)
        result = SourceResult(
            name=name, ok=False, error=f"{type(exc).__name__}: {exc}", duration_s=duration
        )
    if progress is not None:
        try:
            progress("finish", name, result)
        except Exception:  # pragma: no cover
            pass
    return result


async def run_sources(
    sources: dict[str, SourceFn], progress: ProgressHook | None = None
) -> list[SourceResult]:
    """Run named sources concurrently and return all results (failures isolated).

    Args:
        sources: mapping of source name -> zero-arg async callable returning SourceResult.
        progress: optional hook invoked as each source starts/finishes, for live UI.
    """
    if not sources:
        return []
    names = list(sources.keys())
    tasks = [asyncio.create_task(_guarded(name, sources[name], progress)) for name in names]
    return await asyncio.gather(*tasks)
