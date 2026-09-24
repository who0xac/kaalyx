"""Part 2 — Subdomains stage.

Two phases, same architecture and standards as OSINT (Part 1):

* STAGE 1 · PASSIVE DISCOVERY — nine independent sources run CONCURRENTLY (subfinder, findomain,
  assetfinder, subdominator, sublist3r, crt.sh, jsmon, github_subdomains, amass). Each is isolated:
  a missing tool/key or a failure is logged and skipped, never taking down the others.
* STAGE 2 · ACTIVE ENUMERATION — four steps run SEQUENTIALLY on the merged passive results:
  alterx (permutations) → puredns bruteforce (alterx guesses + wordlist) → puredns resolve
  (massdns + wildcard validation against trusted resolvers) → dnsx (final structuring/enrichment).

Every source/step writes dual output (raw + readable text) and its subdomains are persisted to
SQLite with per-source attribution; the final merged/deduped list is written to subdomains.txt.
Enumeration only — no takeover detection in this stage.
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

from ..core.stage import Stage, StageResult
from ..data.models import Subdomain
from ..monitor.flags import flag_all
from ..parsers import osint_parsers as P
from ..ui import subdomains_ui
from ..ui.subdomains_ui import _Breakdown
from . import subdomains_inproc as SI
from .github_org import ensure_github_org
from .sources import SourceResult, run_sources

# Human-readable board labels, keyed by source/step name.
PASSIVE_LABELS: dict[str, str] = {
    "subfinder": "SUBFINDER",
    "findomain": "FINDOMAIN",
    "assetfinder": "ASSETFINDER",
    "subdominator": "SUBDOMINATOR",
    "sublist3r": "SUBLIST3R",
    "crtsh": "CRT_SH",
    "jsmon": "JSMON",
    "github_subdomains": "GITHUB_SUBDOMAINS",
    "amass": "AMASS",
}
ACTIVE_LABELS: dict[str, str] = {
    "alterx": "ALTERX",
    "puredns_bruteforce": "PUREDNS_BRUTEFORCE[wordlist]",
    "puredns_resolve": "PUREDNS_RESOLVE",
    "dnsx": "DNSX",
}

# Local, install-time asset locations (never fetched at scan time).
_WORDLISTS = {
    "seclists-110k": Path.home() / ".config" / "kaalyx" / "wordlists" / "seclists-110k.txt",
    "jhaddix-all": Path.home() / ".config" / "kaalyx" / "wordlists" / "jhaddix-all.txt",
}
_RESOLVERS = Path.home() / ".config" / "kaalyx" / "resolvers" / "resolvers.txt"

#: How long after a first Ctrl+C a second press still counts as "abort the whole scan" (seconds).
_DOUBLE_INTERRUPT_WINDOW = 2.0


class _InterruptController:
    """Two-stage Ctrl+C handling for the Subdomains stage.

    * FIRST Ctrl+C  → "skip the current source(s)": set :attr:`skip_requested` and cancel the
      in-flight source task(s). Already-finished sources keep their results; a cancelled source
      keeps whatever partial output it wrote to disk (e.g. amass ``-o``), and the scan moves on.
    * SECOND Ctrl+C within :data:`_DOUBLE_INTERRUPT_WINDOW` → "abort the whole scan": re-raise
      KeyboardInterrupt so the stage propagates it (the orchestrator leaves the stage
      un-checkpointed, so ``kaalyx resume`` re-runs it).

    Installed for the scan's duration via :meth:`install` / :meth:`restore`. A no-op on platforms
    without a usable SIGINT signal handler in the current thread (falls back to normal behaviour)."""

    def __init__(self, console) -> None:
        self._console = console
        self._prev = None
        self._installed = False
        self._last_press = 0.0
        self.skip_requested = False
        #: The asyncio tasks currently in-flight; the handler cancels these on the first press.
        self._active_tasks: set = set()

    def track(self, task) -> None:
        self._active_tasks.add(task)

    def untrack(self, task) -> None:
        self._active_tasks.discard(task)

    def clear_skip(self) -> None:
        """Reset the per-step skip flag before the next source/step so a stale press doesn't skip it."""
        self.skip_requested = False

    def _handle(self, signum, frame) -> None:
        now = time.monotonic()
        if self.skip_requested and (now - self._last_press) <= _DOUBLE_INTERRUPT_WINDOW:
            # Second press in the window → abort the whole scan.
            self.restore()
            raise KeyboardInterrupt
        # First press → request skip of the current source(s) and cancel their tasks.
        self.skip_requested = True
        self._last_press = now
        try:
            self._console.print(
                "\n[yellow]Ctrl+C — skipping the current source"
                " (press again within 2s to abort the whole scan).[/]")
        except Exception:
            pass
        for t in list(self._active_tasks):
            if not t.done():
                t.cancel()

    def install(self) -> None:
        import signal
        try:
            self._prev = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGINT, self._handle)
            self._installed = True
        except (ValueError, OSError, RuntimeError):
            # Not the main thread / unsupported → leave default behaviour (a plain Ctrl+C aborts).
            self._installed = False

    def restore(self) -> None:
        if not self._installed:
            return
        import signal
        try:
            signal.signal(signal.SIGINT, self._prev if self._prev is not None else signal.SIG_DFL)
        except (ValueError, OSError, RuntimeError):
            pass
        self._installed = False


class SubdomainsStage(Stage):
    name = "subdomains"

    async def run(self) -> StageResult:
        ctx = self.ctx
        cfg = ctx.config.subdomains
        ctx.writer.reset_stage_dir(self.name)

        registrable = ctx.target.registrable

        # Passive source registry — only enabled ones run. Same toggle pattern as OSINT.
        passive_candidates = {
            "subfinder": (cfg.subfinder, self._src_subfinder),
            "findomain": (cfg.findomain, self._src_findomain),
            "assetfinder": (cfg.assetfinder, self._src_assetfinder),
            "subdominator": (cfg.subdominator, self._src_subdominator),
            "sublist3r": (cfg.sublist3r, self._src_sublist3r),
            "crtsh": (cfg.crtsh, self._src_crtsh),
            "jsmon": (cfg.jsmon, self._src_jsmon),
            "github_subdomains": (cfg.github_subdomains, self._src_github_subdomains),
            "amass": (cfg.amass, self._src_amass),
        }
        passive = {n: fn for n, (en, fn) in passive_candidates.items() if en}

        # Board: full banner only when standalone (banner prints once per invocation — a prior
        # stage sets ctx.shared["banner_printed"]).
        n_active = sum(1 for en in (cfg.alterx, cfg.puredns, cfg.puredns, cfg.dnsx) if en)
        progress = subdomains_ui.SubdomainsProgress(registrable, len(passive), n_active)
        for n in passive:
            progress.register(n, PASSIVE_LABELS[n],
                              unit="found", slow=(n == "amass"), live_tick=(n == "amass"))
        show_banner = not ctx.get_shared("banner_printed")
        progress.print_header(show_banner)
        ctx.set_shared("banner_printed", True)
        self._progress = progress

        # GitHub-org pre-step (shared, cross-stage, at-most-once) — only when github_subdomains is
        # actually part of this run, so a --subdomains-only run still resolves the org itself.
        if "github_subdomains" in passive and ctx.secrets.has_github:
            await ensure_github_org(ctx)

        from ..core.logging import set_console_logging

        def _hook(event: str, name: str, result) -> None:
            progress.hook(event, name, result)
            if event == "finish" and result is not None:
                self._flush_source(result)

        interrupt_exc: BaseException | None = None
        passive_results: list[SourceResult] = []
        # Two-stage Ctrl+C: 1st press skips the current source(s) & continues; 2nd (within 2s)
        # aborts the whole scan (its handler raises KeyboardInterrupt, caught below → resumable).
        interrupt = _InterruptController(subdomains_ui.get_console())

        try:
            set_console_logging(False)
            interrupt.install()
            # ---- STAGE 1 · PASSIVE (concurrent) ----
            with progress.live_stage("STAGE 1 · PASSIVE DISCOVERY", list(passive.keys())):
                try:
                    passive_results = await self._run_passive_concurrent(passive, _hook, interrupt)
                except (KeyboardInterrupt, asyncio.CancelledError) as exc:
                    interrupt_exc = exc

            # Merge + dedup passive results (per-source attribution preserved on each Subdomain).
            passive_subs, passive_raw, passive_dupes = self._merge([r for r in passive_results])
            progress.print_static(progress.stage_block(
                "STAGE 1 · PASSIVE DISCOVERY", [], breakdown=_Breakdown(
                    "PASSIVE RESULTS",
                    [("Raw results", passive_raw),
                     ("Duplicates removed", passive_dupes),
                     ("Unique subdomains", len(passive_subs))])))

            active_new_subs: list[Subdomain] = []
            active_bd = None
            if interrupt_exc is None and n_active:
                # Let the operator pick the puredns bruteforce wordlist (unless --wordlist was
                # given). Done here — after passive, before the STAGE 2 live block opens — so the
                # prompt isn't fighting a live-rendering region for the terminal.
                self._prompt_wordlist()
                progress.print_static(progress.stage_block(
                    "", [], lead_note="Active enumeration ahead — bruteforce takes time, sit tight."))
                # ---- STAGE 2 · ACTIVE (sequential) ----
                interrupt.clear_skip()
                active_new_subs, active_bd = await self._run_active(progress, passive_subs, interrupt)

            # ---- FINAL ----
            final_subs = self._dedup_merge(passive_subs, active_new_subs)
        except (KeyboardInterrupt, asyncio.CancelledError) as exc:
            # A second Ctrl+C during STAGE 2 (or an abort) lands here.
            interrupt_exc = exc
            passive_subs = locals().get("passive_subs", [])
            active_new_subs = locals().get("active_new_subs", [])
            final_subs = self._dedup_merge(passive_subs, active_new_subs)
        finally:
            interrupt.restore()
            set_console_logging(True)
            self._progress = None

        # Persist everything.
        self._persist(final_subs, passive_results)

        if interrupt_exc is not None:
            subdomains_ui.get_console().print(
                "\n[bold yellow]Interrupted[/] — passive stage incomplete; "
                "re-run on [cyan]kaalyx resume[/].")
            raise interrupt_exc

        progress.print_static(progress.final_block(len(passive_subs), len(active_new_subs)))
        folder = str(ctx.writer.stage_dir(self.name))
        progress.print_complete(folder)

        return self.result(ok=True, counts={"subdomains": len(final_subs)})

    # -- concurrent passive runner (Ctrl+C-skip aware) ---------------------------------

    async def _run_passive_concurrent(self, sources, hook, interrupt) -> list[SourceResult]:
        """Run the passive sources concurrently, tolerant of a per-source Ctrl+C "skip".

        Like :func:`run_sources` but each source runs as a task registered with the interrupt
        controller, and results are gathered with ``return_exceptions=True`` so cancelling ONE
        source (the first Ctrl+C — in practice the long amass) does NOT tear down the others:
        already-finished sources keep their results, the cancelled one keeps whatever partial
        output it harvested, and the scan proceeds to STAGE 2. A cancelled source that returns no
        result is recorded as a clean "skipped (Ctrl+C)" row. A second Ctrl+C is raised by the
        controller's handler as KeyboardInterrupt and propagates out of here to abort."""
        import time as _t

        async def _one(name: str, fn):
            start = _t.monotonic()
            try:
                hook("start", name, None)
            except Exception:
                pass
            try:
                result = await fn()
                result.name = name
                result.duration_s = _t.monotonic() - start
            except asyncio.CancelledError:
                # First Ctrl+C skip: this source didn't finish on its own. Record a clean skip
                # (amass already returns a partial result and won't reach here).
                result = SourceResult(name=name, ok=True, skipped=True,
                                      note="skipped: Ctrl+C (source cancelled)",
                                      duration_s=_t.monotonic() - start)
            except Exception as exc:  # isolate any source failure
                result = SourceResult(name=name, ok=False, error=f"{type(exc).__name__}: {exc}",
                                      duration_s=_t.monotonic() - start)
            try:
                hook("finish", name, result)
            except Exception:
                pass
            return result

        tasks = [asyncio.ensure_future(_one(n, fn)) for n, fn in sources.items()]
        for t in tasks:
            interrupt.track(t)
        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            for t in tasks:
                interrupt.untrack(t)
        # A second Ctrl+C (abort) surfaces as KeyboardInterrupt among the gathered exceptions.
        for r in results:
            if isinstance(r, KeyboardInterrupt):
                raise r
        return [r for r in results if isinstance(r, SourceResult)]

    # -- merge / dedup -----------------------------------------------------------------

    @staticmethod
    def _merge(results: list[SourceResult]) -> tuple[list[Subdomain], int, int]:
        """Merge subdomains from many results → (unique_list, raw_total, dupes_removed).

        Per-source attribution is preserved: when the same hostname is found by several sources,
        the sources are joined (``subfinder,crt.sh``) so the DB shows every tool that found it."""
        raw_total = 0
        by_host: dict[str, Subdomain] = {}
        for r in results:
            for s in r.subdomains:
                raw_total += 1
                host = s.hostname.strip().lower().rstrip(".")
                if not host:
                    continue
                if host in by_host:
                    existing = by_host[host]
                    srcs = {p for p in existing.source.split(",") if p}
                    srcs.add(s.source)
                    existing.source = ",".join(sorted(srcs))
                else:
                    by_host[host] = Subdomain(hostname=host, source=s.source)
        unique = sorted(by_host.values(), key=lambda s: s.hostname)
        dupes = max(0, raw_total - len(unique))
        return unique, raw_total, dupes

    @staticmethod
    def _dedup_merge(passive: list[Subdomain], active: list[Subdomain]) -> list[Subdomain]:
        """Union of passive + active subdomains, deduped by hostname (active adds only NEW ones)."""
        by_host: dict[str, Subdomain] = {s.hostname: s for s in passive}
        for s in active:
            if s.hostname not in by_host:
                by_host[s.hostname] = s
        return sorted(by_host.values(), key=lambda s: s.hostname)

    # -- STAGE 2 · active steps (sequential) -------------------------------------------

    async def _run_active(self, progress, passive_subs: list[Subdomain], interrupt):
        """Run the four active steps in sequence on the merged passive list, animating each row.

        Ctrl+C-aware: the 1st press cancels the CURRENT step (it's skipped, keeping any partial
        output, and the scan moves to the next step); a 2nd press within the window aborts. Each
        step runs as a task registered with the interrupt controller so the handler can cancel it.

        Returns ``(new_subdomains, breakdown)`` where new_subdomains are validated names not
        already in the passive set."""
        cfg = self.ctx.config.subdomains
        names = [n for n, en in (("alterx", cfg.alterx),
                                 ("puredns_bruteforce", cfg.puredns),
                                 ("puredns_resolve", cfg.puredns),
                                 ("dnsx", cfg.dnsx)) if en]
        for n in names:
            progress.register(n, ACTIVE_LABELS[n],
                              unit={"alterx": "candidates",
                                    "puredns_bruteforce": "candidates",
                                    "puredns_resolve": "resolved",
                                    "dnsx": "enriched"}[n])

        passive_names = sorted({s.hostname for s in passive_subs})
        candidates_generated = 0
        resolved: list[str] = []

        async def _step(name: str, coro, default):
            """Run one active step as a cancellable task. On the 1st Ctrl+C the task is cancelled
            → this step is marked skipped and *default* is returned so the sequence continues."""
            interrupt.clear_skip()
            progress.start(name)
            task = asyncio.ensure_future(coro)
            interrupt.track(task)
            try:
                return await task
            except asyncio.CancelledError:
                progress.set_done(name, 0, "skipped: Ctrl+C")
                return default
            finally:
                interrupt.untrack(task)

        with progress.live_stage("STAGE 2 · ACTIVE ENUMERATION", names):
            # 1) alterx — permutation candidates from the passive list.
            alterx_out: list[str] = []
            if "alterx" in names:
                alterx_out, r = await _step("alterx", self._step_alterx(passive_names), ([], None))
                if r is not None:
                    self._flush_source(r)
                    progress.set_done("alterx", len(alterx_out), r.note)

            # 2) puredns bruteforce — merge alterx guesses WITH the chosen wordlist into one pool.
            candidate_pool: list[str] = []
            if "puredns_bruteforce" in names:
                candidate_pool, r = await _step(
                    "puredns_bruteforce", self._step_puredns_bruteforce(alterx_out), ([], None))
                if r is not None:
                    self._flush_source(r)
                    candidates_generated = len(candidate_pool)
                    progress.set_done("puredns_bruteforce", candidates_generated, r.note)

            # 3) puredns resolve — resolve the ENTIRE merged pool with wildcard validation.
            if "puredns_resolve" in names:
                resolved, r = await _step(
                    "puredns_resolve", self._step_puredns_resolve(candidate_pool), ([], None))
                if r is not None:
                    self._flush_source(r)
                    progress.set_done("puredns_resolve", len(resolved), r.note)

            # 4) dnsx — structure/enrich the validated results.
            enriched = resolved
            if "dnsx" in names:
                enriched, r = await _step("dnsx", self._step_dnsx(resolved), (resolved, None))
                if r is not None:
                    self._flush_source(r)
                    progress.set_done("dnsx", len(enriched), r.note)

        # New = validated names not already known from the passive stage.
        passive_set = set(passive_names)
        new_hosts = [h for h in sorted(set(resolved)) if h not in passive_set]
        new_subs = [Subdomain(hostname=h, source="puredns/active") for h in new_hosts]
        dupes = max(0, len(set(resolved)) - len(new_hosts))
        bd = _Breakdown("ACTIVE RESULTS",
                        [("Candidates generated", candidates_generated),
                         ("Resolved", len(set(resolved))),
                         ("Duplicates removed", dupes),
                         ("New subdomains", len(new_subs))])
        progress.print_static(progress.stage_block("STAGE 2 · ACTIVE ENUMERATION", [], breakdown=bd))
        return new_subs, bd

    # -- persistence -------------------------------------------------------------------

    def _persist(self, final_subs: list[Subdomain], passive_results: list[SourceResult]) -> None:
        ctx = self.ctx
        flag_all(final_subs, ctx.config.flagging.interesting_keywords)
        if final_subs:
            ctx.repo.bulk_upsert_subdomains(ctx.scan_id, final_subs)
            ctx.writer.write_lines(self.name, "subdomains.txt", [s.hostname for s in final_subs])

    def _flush_source(self, r: SourceResult) -> None:
        """Dual output per source/step: raw → tool_output/<source>.raw.txt, readable → <source>.txt,
        structured subdomains → SQLite. Idempotent; never raises."""
        try:
            content = r.raw if r.raw else "\n".join(s.hostname for s in r.subdomains)
            header = r.note if (not content and r.note) else ""
            self.ctx.writer.raw_source_output(self.name, r.name, content, r.raw_ext, header)
        except Exception as exc:  # noqa: BLE001
            self.log.debug("raw flush failed for %s: %s", r.name, exc)
        try:
            lines = [f"# {r.name}", f"# {r.note}" if r.note else "",
                     f"# {len(r.subdomains)} subdomain(s)", ""]
            lines += [s.hostname for s in r.subdomains]
            self.ctx.writer.write_text(self.name, f"{r.name}.txt", "\n".join(x for x in lines if x is not None))
        except Exception as exc:  # noqa: BLE001
            self.log.debug("readable write failed for %s: %s", r.name, exc)
        try:
            if r.subdomains:
                flag_all(r.subdomains, self.ctx.config.flagging.interesting_keywords)
                self.ctx.repo.bulk_upsert_subdomains(self.ctx.scan_id, r.subdomains)
        except Exception as exc:  # noqa: BLE001
            self.log.debug("db persist failed for %s: %s", r.name, exc)

    # -- passive sources ---------------------------------------------------------------

    async def _src_subfinder(self) -> SourceResult:
        res = SourceResult(name="subfinder", raw_ext="txt")
        # subfinder reads its OWN ~/.config/subfinder/provider-config.yaml for API keys — Kaalyx
        # does not manage those. -silent = hostnames only; -all = every passive source.
        out = await self.ctx.runner.run(
            ["subfinder", "-d", self.ctx.target.registrable, "-silent", "-all"],
            timeout=600, label="subfinder")
        if not out.started:
            res.skipped, res.note = True, "skipped: subfinder not on PATH"
            return res
        res.raw = out.stdout
        res.subdomains = P.parse_subdomain_lines(out.stdout, "subfinder")
        res.note = f"{len(res.subdomains)} subdomain(s)"
        return res

    async def _src_findomain(self) -> SourceResult:
        res = SourceResult(name="findomain", raw_ext="txt")
        out = await self.ctx.runner.run(
            ["findomain", "-t", self.ctx.target.registrable, "-q"],
            timeout=600, label="findomain")
        if not out.started:
            res.skipped, res.note = True, "skipped: findomain not on PATH"
            return res
        res.raw = out.stdout
        res.subdomains = P.parse_subdomain_lines(out.stdout, "findomain")
        res.note = f"{len(res.subdomains)} subdomain(s)"
        return res

    async def _src_assetfinder(self) -> SourceResult:
        res = SourceResult(name="assetfinder", raw_ext="txt")
        out = await self.ctx.runner.run(
            ["assetfinder", "--subs-only", self.ctx.target.registrable],
            timeout=600, label="assetfinder")
        if not out.started:
            res.skipped, res.note = True, "skipped: assetfinder not on PATH"
            return res
        res.raw = out.stdout
        subs = P.parse_subdomain_lines(out.stdout, "assetfinder")
        res.subdomains = [s for s in subs if SI.in_scope(s.hostname, self.ctx.target.registrable)]
        res.note = f"{len(res.subdomains)} subdomain(s)"
        return res

    async def _src_subdominator(self) -> SourceResult:
        res = SourceResult(name="subdominator", raw_ext="txt")
        # subdominator reads its OWN provider config for extra API sources — Kaalyx does not manage
        # those keys. -d domain, -o - to stdout (silent host-per-line).
        out = await self.ctx.runner.run(
            ["subdominator", "-d", self.ctx.target.registrable],
            timeout=600, label="subdominator")
        if not out.started:
            res.skipped, res.note = True, "skipped: subdominator not on PATH"
            return res
        res.raw = out.stdout
        res.subdomains = P.parse_subdomain_lines(out.stdout, "subdominator")
        res.note = f"{len(res.subdomains)} subdomain(s)"
        return res

    async def _src_sublist3r(self) -> SourceResult:
        res = SourceResult(name="sublist3r", raw_ext="txt")
        stage_dir = self.ctx.writer.tool_output_dir(self.name)
        outfile = stage_dir / "_sublist3r.txt"
        out = await self.ctx.runner.run(
            ["sublist3r", "-d", self.ctx.target.registrable, "-o", str(outfile)],
            timeout=600, label="sublist3r")
        if not out.started:
            res.skipped, res.note = True, "skipped: sublist3r not on PATH"
            return res
        data = out.stdout
        try:
            data = outfile.read_text(encoding="utf-8") or out.stdout
        except OSError:
            pass
        res.raw = data
        subs = P.parse_subdomain_lines(data, "sublist3r")
        res.subdomains = [s for s in subs if SI.in_scope(s.hostname, self.ctx.target.registrable)]
        res.note = f"{len(res.subdomains)} subdomain(s)"
        return res

    async def _src_crtsh(self) -> SourceResult:
        res = SourceResult(name="crtsh", raw_ext="json")
        subs, raw = await SI.fetch_crtsh(self.ctx.target.registrable)
        res.subdomains, res.raw = subs, raw
        res.note = f"{len(subs)} subdomain(s) from CT logs"
        return res

    async def _src_jsmon(self) -> SourceResult:
        res = SourceResult(name="jsmon", raw_ext="json")
        subs, raw, skip = await SI.fetch_jsmon(
            self.ctx.target.registrable, self.ctx.secrets.jsmon_api_key)
        res.raw = raw
        if skip:
            res.skipped, res.note = True, skip
            return res
        res.subdomains = subs
        res.note = f"{len(subs)} subdomain(s)"
        return res

    async def _src_github_subdomains(self) -> SourceResult:
        res = SourceResult(name="github_subdomains", raw_ext="txt")
        if not self.ctx.secrets.has_github:
            res.skipped, res.note = True, "skipped: GITHUB_TOKEN not set"
            return res
        cmd = ["github-subdomains", "-d", self.ctx.target.registrable, "-e"]
        out = await self.ctx.runner.run(
            cmd, env={"GITHUB_TOKEN": self.ctx.secrets.next_github_token() or ""},
            timeout=300, label="github-subdomains")
        if not out.started:
            res.skipped, res.note = True, "skipped: github-subdomains not on PATH"
            return res
        res.raw = out.stdout
        subs = P.parse_subdomain_lines(out.stdout, "github-subdomains")
        res.subdomains = [s for s in subs if SI.in_scope(s.hostname, self.ctx.target.registrable)]
        res.note = f"{len(res.subdomains)} subdomain(s) from GitHub code"
        return res

    async def _src_amass(self) -> SourceResult:
        """amass passive, capped with the external `timeout` command (amass has no native timeout).

        On timeout the process is killed and whatever partial output amass produced is kept — a
        long amass run must never block the rest of the pipeline. Live-ticks its found count if
        the row supports it (amass streams results)."""
        res = SourceResult(name="amass", raw_ext="txt")
        stage_dir = self.ctx.writer.tool_output_dir(self.name)
        outfile = stage_dir / "_amass.txt"
        if not self.ctx.runner.tool_available("amass"):
            res.skipped, res.note = True, "skipped: amass not on PATH"
            return res
        # `timeout 2h amass enum -passive ...` — the 2h cap is enforced by the external `timeout`
        # binary. -norecursive keeps it passive-fast; -o writes results as it finds them, so a
        # kill-on-timeout still leaves partial output on disk.
        have_timeout = self.ctx.runner.tool_available("timeout")
        cmd = (["timeout", "2h"] if have_timeout else []) + [
            "amass", "enum", "-passive", "-d", self.ctx.target.registrable,
            "-norecursive", "-o", str(outfile)]
        def _harvest(extra_note: str = "") -> "SourceResult":
            # Read amass's -o file (written incrementally) — so a 2h-cap kill OR a Ctrl+C skip
            # still keeps whatever it found up to that point.
            data = ""
            try:
                data = outfile.read_text(encoding="utf-8")
            except OSError:
                data = ""
            res.raw = data
            subs = P.parse_subdomain_lines(data, "amass")
            res.subdomains = [s for s in subs if SI.in_scope(s.hostname, self.ctx.target.registrable)]
            res.note = f"{len(res.subdomains)} subdomain(s)" + (f" {extra_note}" if extra_note else "")
            return res

        # 124 = the exit code `timeout` uses when it kills the process; treat it as success so we
        # still harvest the partial -o file rather than discarding a long run's work.
        try:
            out = await self.ctx.runner.run(cmd, timeout=7500, label="amass",
                                            acceptable_codes=(0, 124))
        except asyncio.CancelledError:
            # Ctrl+C "skip" cancelled amass mid-run — keep the partial -o output and move on
            # (do NOT re-raise; the skip must not tear down the concurrent gather).
            return _harvest("(skipped via Ctrl+C — partial results kept)")
        if not out.started:
            res.skipped, res.note = True, "skipped: amass not on PATH"
            return res
        if not out.stdout.strip():
            _harvest()
        else:
            res.raw = out.stdout
            subs = P.parse_subdomain_lines(out.stdout, "amass")
            res.subdomains = [s for s in subs
                              if SI.in_scope(s.hostname, self.ctx.target.registrable)]
            res.note = f"{len(res.subdomains)} subdomain(s)"
        if out.returncode == 124:
            res.note += " (2h cap hit — partial results kept)"
        return res

    # -- active steps ------------------------------------------------------------------

    async def _step_alterx(self, passive_names: list[str]) -> tuple[list[str], SourceResult]:
        res = SourceResult(name="alterx", raw_ext="txt")
        if not passive_names:
            res.note = "no passive subdomains to permute"
            return [], res
        if not self.ctx.runner.tool_available("alterx"):
            res.skipped, res.note = True, "skipped: alterx not on PATH"
            return [], res
        out = await self.ctx.runner.run(
            ["alterx", "-silent"], stdin="\n".join(passive_names) + "\n",
            timeout=600, label="alterx")
        if not out.started:
            res.skipped, res.note = True, "skipped: alterx not runnable"
            return [], res
        cands = [ln.strip() for ln in out.stdout.splitlines() if ln.strip()]
        res.raw = out.stdout
        res.note = f"{len(cands)} permutation candidate(s)"
        return cands, res

    def _prompt_wordlist(self) -> None:
        """Interactively ask the operator to pick the puredns bruteforce wordlist, unless it was set
        explicitly with --wordlist. Prompts only on a real interactive TTY; a non-interactive/piped
        run (or an explicit choice) keeps the current value silently. The choice is written back to
        ``config.subdomains.wordlist`` so :meth:`_wordlist_path` and the board label reflect it."""
        cfg = self.ctx.config.subdomains
        if getattr(cfg, "wordlist_explicit", False):
            return
        try:
            if not sys.stdin.isatty():
                return
        except Exception:
            return
        console = subdomains_ui.get_console()
        current = cfg.wordlist if cfg.wordlist in _WORDLISTS else "seclists-110k"
        # Show each option with its on-disk presence so the operator knows if it was downloaded.
        console.print()
        console.print("[bold bright_cyan]    Choose the puredns bruteforce wordlist:[/]")
        opts = [("1", "seclists-110k", "SecLists subdomains-top1million-110000 (default)"),
                ("2", "jhaddix-all", "Jhaddix all.txt (deeper, slower)")]
        for key, name, desc in opts:
            present = "" if _WORDLISTS[name].exists() else "  [yellow](not downloaded)[/]"
            mark = " [green]←current[/]" if name == current else ""
            console.print(f"      [cyan]{key}[/]) {desc}{present}{mark}")
        default_key = "1" if current == "seclists-110k" else "2"
        try:
            raw = input(f"    Selection [1/2] (default {default_key}): ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("    [dim]No selection — keeping current wordlist.[/]")
            return
        choice = {"1": "seclists-110k", "2": "jhaddix-all"}.get(raw or default_key)
        if choice:
            cfg.wordlist = choice
            console.print(f"    [green]Using {choice}.[/]")

    def _wordlist_path(self) -> Path:
        """The chosen bruteforce wordlist: config-selected (seclists-110k default / jhaddix-all
        opt-in). Files are pre-downloaded at install time under ~/.config/kaalyx/wordlists/."""
        choice = getattr(self.ctx.config.subdomains, "wordlist", "seclists-110k")
        return _WORDLISTS.get(choice, _WORDLISTS["seclists-110k"])

    async def _step_puredns_bruteforce(self, alterx_cands: list[str]) -> tuple[list[str], SourceResult]:
        """Merge alterx guesses WITH the chosen wordlist into ONE candidate pool (not resolved
        here — resolution is the next step on the merged pool)."""
        res = SourceResult(name="puredns_bruteforce", raw_ext="txt")
        wordlist = self._wordlist_path()
        pool: set[str] = set(alterx_cands)
        if wordlist.exists():
            try:
                reg = self.ctx.target.registrable
                for line in wordlist.read_text(encoding="utf-8", errors="ignore").splitlines():
                    w = line.strip()
                    if w and not w.startswith("#"):
                        pool.add(f"{w}.{reg}")
            except OSError as exc:
                res.note = f"wordlist read error: {exc}"
        else:
            res.note = f"wordlist missing ({wordlist.name}); alterx guesses only"
        candidates = sorted(pool)
        res.raw = "\n".join(candidates)
        res.note = (res.note + "; " if res.note else "") + f"{len(candidates)} merged candidate(s)"
        return candidates, res

    async def _step_puredns_resolve(self, candidates: list[str]) -> tuple[list[str], SourceResult]:
        """Resolve the ENTIRE merged pool via puredns/massdns with wildcard + DNS-poisoning
        validation against the trusted resolver list."""
        res = SourceResult(name="puredns_resolve", raw_ext="txt")
        if not candidates:
            res.note = "no candidates to resolve"
            return [], res
        if not self.ctx.runner.tool_available("puredns"):
            res.skipped, res.note = True, "skipped: puredns not on PATH"
            return [], res
        stage_dir = self.ctx.writer.tool_output_dir(self.name)
        infile = stage_dir / "_puredns_candidates.txt"
        outfile = stage_dir / "_puredns_resolved.txt"
        try:
            infile.write_text("\n".join(candidates) + "\n", encoding="utf-8")
        except OSError:
            res.skipped, res.note = True, "skipped: could not write puredns input"
            return [], res
        cmd = ["puredns", "resolve", str(infile), "-w", str(outfile), "--quiet"]
        if _RESOLVERS.exists():
            cmd += ["-r", str(_RESOLVERS)]
        else:
            res.note = "resolvers.txt missing — using puredns defaults"
        out = await self.ctx.runner.run(cmd, timeout=1800, label="puredns")
        if not out.started:
            res.skipped, res.note = True, "skipped: puredns not runnable"
            return [], res
        data = out.stdout
        try:
            data = outfile.read_text(encoding="utf-8") or out.stdout
        except OSError:
            pass
        res.raw = data
        reg = self.ctx.target.registrable
        resolved = sorted({ln.strip().lower().rstrip(".") for ln in data.splitlines()
                           if ln.strip() and SI.in_scope(ln.strip(), reg)})
        res.subdomains = [Subdomain(hostname=h, source="puredns") for h in resolved]
        res.note = (res.note + "; " if res.note else "") + f"{len(resolved)} resolved"
        return resolved, res

    async def _step_dnsx(self, resolved: list[str]) -> tuple[list[str], SourceResult]:
        """Final structuring/enrichment pass (record types, resolved IPs) for later stages."""
        res = SourceResult(name="dnsx", raw_ext="json")
        if not resolved:
            res.note = "no resolved hosts to enrich"
            return [], res
        if not self.ctx.runner.tool_available("dnsx"):
            res.skipped, res.note = True, "skipped: dnsx not on PATH"
            return resolved, res
        out = await self.ctx.runner.run(
            ["dnsx", "-json", "-silent", "-a", "-aaaa", "-cname"],
            stdin="\n".join(resolved) + "\n", timeout=600, label="dnsx")
        if not out.started:
            res.skipped, res.note = True, "skipped: dnsx not runnable"
            return resolved, res
        res.raw = out.stdout
        records = P.parse_dnsx(out.stdout)
        # Keep the enriched host list; the DNS records feed the Hosts stage via osint-style rows.
        enriched = sorted({rec.value.split()[0] for rec in records if rec.value})
        enriched = [h for h in enriched if SI.in_scope(h, self.ctx.target.registrable)] or resolved
        res.subdomains = [Subdomain(hostname=h, source="dnsx") for h in enriched]
        res.note = f"{len(enriched)} enriched"
        return enriched, res
