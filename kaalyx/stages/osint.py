"""Part 1 — OSINT stage.

Runs a fan-out of independent OSINT sources concurrently,
persisting everything to both SQLite and raw files, and rendering a live rich UI. Each
source is isolated: a missing tool, a missing API key, a disabled toggle, or a source that
errors is logged and skipped — it never affects the other sources or the scan.

Design principles:

* fine-grained one-source-per-check structure, with typed findings/emails, keyless
  email harvesting (email-format/skymem), extended DNS security records, a keyless Azure
  tenant mapping method (ODC federationprovider), and an "``if not r: return``"
  graceful-skip discipline;
* theHarvester emails/employees/hosts extraction, email→breach chaining (harvested emails
  feed the breach lookup), and a categorised Google-dork taxonomy;
* a per-source enable/disable toggle for every sub-check, passing secrets via environment
  (not argv) so tokens don't leak into the process list, and tool-present checks with clear
  skip messages.

Sources:
    external tools (skip if not on PATH):  whois, dnsx, github-subdomains, trufflehog,
        cloud_enum, s3scanner, badsecrets, retire.js, theHarvester, misconfig-mapper.
    in-process keyless:  mail/DNS security posture, M365 tenant mapping, email harvesting,
        Google-dork generation.
    key-dependent (skip cleanly if no key):  breach lookup (h8mail), and the key-gated
        tools above (github-subdomains, trufflehog).

Credential/leak coverage (post-harvest chaining):
    * breach lookup (h8mail) — reports which breaches an email appears in, and, when the
      operator configures a local breach compilation / credential-returning API, the ACTUAL
      leaked passwords/hashes (one finding per recovered credential), not just counts.
    * leak search (LeakSearch) — keyless query of the ProxyNova/COMB credential dump for real
      user:password pairs, keyed on the domain and each harvested email.
    * CAA iodef contact emails are harvested from mail_dns and feed both.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx

from ..core.stage import Stage, StageResult
from ..data.models import Confidence, Email, Finding, OsintRecord, Severity, Subdomain
from ..monitor.flags import flag_all
from ..ui import osint_ui
from ..ui import osint_report
from . import osint_inproc
from . import shodan_inproc
from ..parsers import osint_parsers as P
from .sources import SourceResult, run_sources

# Human-readable labels for the live progress board, keyed by source name.
SOURCE_LABELS: dict[str, str] = {
    "whois": "WHOIS",
    "dns": "DNS records (dnsx)",
    "ip_info": "IP intel (geo/ASN)",
    "mail_dns": "Mail/DNS security",
    "m365": "M365 tenant map",
    "email_harvest": "Email harvest",
    "social": "Social profiles",
    "breach_lookup": "Breach lookup",
    "leak_search": "Leak search (creds)",
    "github_subdomains": "GitHub subdomains",
    "gitgraber": "gitGraber (secret regexes)",
    "trufflehog": "TruffleHog (org)",
    "cloud_enum": "Cloud enum",
    "s3scanner": "S3 scanner",
    "badsecrets": "badsecrets",
    "retirejs": "retire.js",
    "theharvester": "theHarvester",
    "third_party_misconfig": "3rd-party misconfig",
    "api_leaks": "API leaks (Postman/Swagger)",
    "exposed_git": "Exposed .git",
    "firebase": "Firebase RTDB exposure",
    "github_actions": "GitHub Actions audit",
    "google_dorks": "Google dorks",
    "shodan_org": "Shodan org/ASN",
    "shodan_favicon": "Shodan favicon pivot",
    "shodan_vulns": "Shodan CVE tags",
    "shodan_host": "Shodan host deep-lookup",
    "internetdb": "Shodan InternetDB (free)",
    "tls_cert": "TLS cert extraction",
    "gitlab": "GitLab discovery",
    "dockerhub": "Docker Hub repos",
    "mobile_apps": "Mobile app discovery",
    "affiliate_domains": "Affiliate domains",
    "dnstwist": "Typosquatting (dnstwist)",
    "workflow_logs": "CI log secret scan",
}


class OsintStage(Stage):
    name = "osint"

    async def run(self) -> StageResult:
        ctx = self.ctx
        osint_cfg = ctx.config.osint

        # Start from a clean stage folder so this scan's output is fully isolated — no stale
        # files from an earlier build and no artifacts from a different target can linger. The
        # orchestrator only reaches run() for a fresh/re-run stage (a resumed-complete stage is
        # skipped before here), so wiping our own <target>/osint/ dir is always safe.
        ctx.writer.reset_stage_dir(self.name)

        # Map each source name to (enabled?, coroutine). Disabled ones are dropped before
        # running; the toggle comes from config (a --no-<source> CLI flag overrides config
        # by mutating ctx.config.osint before the stage runs).
        # OSINT source registry. Only the sources listed here run under `--osint-only`.
        #
        # SCOPE REDUCTION: 15 sources were moved OUT of OSINT (they are being reassigned to later
        # stages). Their source methods (`self._src_*`) and parsers are DELIBERATELY LEFT INTACT —
        # they are simply not wired into this registry, so they don't run in OSINT, and are ready to
        # be assigned to their future stages later. The removed set is:
        #   github_subdomains, gitgraber, trufflehog, github_actions, workflow_logs,
        #   cloud_enum, s3scanner, firebase, exposed_git, badsecrets, retirejs,
        #   api_leaks (porch-pirate + swaggerspy), third_party_misconfig,
        #   shodan_vulns, shodan_host
        # ("grep_app" was never a distinct OSINT source, so there is nothing to remove for it;
        #  "porch-pirate" is one of the two tools inside api_leaks, removed with it.)
        # KEPT post-steps (added to the board separately, below): breach_lookup, leak_search.
        candidates = {
            "whois": (osint_cfg.whois, self._src_whois),
            "dns": (osint_cfg.dns, self._src_dnsx),
            "ip_info": (osint_cfg.ip_info, self._src_ip_info),
            "mail_dns": (osint_cfg.mail_dns, self._src_mail_dns),
            "m365": (osint_cfg.m365, self._src_m365),
            "email_harvest": (osint_cfg.email_harvest, self._src_email_harvest),
            "social": (osint_cfg.social, self._src_social),
            "theharvester": (osint_cfg.theharvester, self._src_theharvester),
            "google_dorks": (osint_cfg.google_dorks, self._src_google_dorks),
            "shodan_org": (osint_cfg.shodan_org, self._src_shodan_org),
            "shodan_favicon": (osint_cfg.shodan_favicon, self._src_shodan_favicon),
            "internetdb": (osint_cfg.internetdb, self._src_internetdb),
            "tls_cert": (osint_cfg.tls_cert, self._src_tls_cert),
            "gitlab": (osint_cfg.gitlab, self._src_gitlab),
            "dockerhub": (osint_cfg.dockerhub, self._src_dockerhub),
            "mobile_apps": (osint_cfg.mobile_apps, self._src_mobile_apps),
            "affiliate_domains": (osint_cfg.affiliate_domains, self._src_affiliate_domains),
            "dnstwist": (osint_cfg.dnstwist, self._src_dnstwist),
            # --- MOVED OUT OF OSINT (code kept; not wired so they don't run here) ---
            # "github_subdomains": (osint_cfg.github_subdomains, self._src_github_subdomains),
            # "gitgraber": (osint_cfg.gitgraber, self._src_gitgraber),
            # "trufflehog": (osint_cfg.trufflehog, self._src_trufflehog),
            # "github_actions": (osint_cfg.github_actions, self._src_github_actions),
            # "workflow_logs": (osint_cfg.workflow_logs, self._src_workflow_logs),
            # "cloud_enum": (osint_cfg.cloud_enum, self._src_cloud_enum),
            # "s3scanner": (osint_cfg.s3scanner, self._src_s3scanner),
            # "firebase": (osint_cfg.firebase, self._src_firebase),
            # "exposed_git": (osint_cfg.exposed_git, self._src_exposed_git),
            # "badsecrets": (osint_cfg.badsecrets, self._src_badsecrets),
            # "retirejs": (osint_cfg.retirejs, self._src_retirejs),
            # "api_leaks": (osint_cfg.api_leaks, self._src_api_leaks),
            # "third_party_misconfig": (osint_cfg.third_party_misconfig, self._src_misconfig),
            # "shodan_vulns": (osint_cfg.shodan_vulns, self._src_shodan_vulns),
            # "shodan_host": (osint_cfg.shodan_host, self._src_shodan_host),
        }
        sources = {name: fn for name, (enabled, fn) in candidates.items() if enabled}
        disabled = [name for name, (enabled, _) in candidates.items() if not enabled]

        osint_ui.print_banner(ctx.domain, len(sources))
        if disabled:
            self.log.info("OSINT sources disabled by config/flags: %s", ", ".join(disabled))

        # Identify the TARGET's GitHub org BEFORE the fan-out, ONLY when an org-consuming source is
        # actually part of THIS run. The org-scanning sources (trufflehog, gato/github_actions,
        # workflow_logs) have all been moved OUT of OSINT, so nothing in the remaining set consumes
        # the org — and this pre-step therefore does NOT run during OSINT anymore. Gating on the
        # live `sources` set (not the raw config toggles) is what makes that correct: even though
        # those toggles still default on, the sources aren't wired into `candidates`, so they're
        # absent from `sources` and the pre-step is skipped. It will run again automatically if/when
        # an org-consuming source is reassigned back into the OSINT registry.
        ORG_CONSUMERS = ("trufflehog", "github_actions", "workflow_logs")
        token_consumer = any(name in sources for name in ORG_CONSUMERS)
        if token_consumer and ctx.secrets.has_github:
            await self._discover_github_org()

        # Live progress board that updates in place. EVERYTHING — the concurrent fan-out AND
        # the post-steps (breach_lookup, leak_search) — runs inside this one board; the console
        # log handler is silenced for the whole span so no per-source lines print outside it
        # (the file log keeps capturing everything). Post-steps are shown as rows too, queued
        # up front, so the full pipeline is visible.
        from ..core.logging import set_console_logging

        labels = {name: SOURCE_LABELS.get(name, name) for name in sources}
        # Post-step rows (only when enabled) so they appear queued from the start.
        if ctx.config.osint.breach_lookup:
            labels["breach_lookup"] = SOURCE_LABELS.get("breach_lookup", "breach_lookup")
        if ctx.config.osint.leak_search:
            labels["leak_search"] = SOURCE_LABELS.get("leak_search", "leak_search")
        progress = osint_ui.OsintProgress(labels, target=ctx.domain)
        self._progress = progress
        # Flag the org-scanning sources on the live board (⚠) when no GitHub org was confidently
        # identified in the pre-step — so the data-integrity concern is visible on their rows from
        # the start, not only after they skip. Gated on the org-consumers actually being in THIS run
        # (they were moved out of OSINT, so this is currently a no-op); depends on the org result.
        if any(s in sources for s in ORG_CONSUMERS) and ctx.secrets.has_github \
                and not ctx.get_shared("github_org"):
            for s in ORG_CONSUMERS:
                if s in sources:
                    progress.mark_flagged(s)
        set_console_logging(False)

        # Wrap the UI hook so that as EACH source finishes we immediately flush its raw file to
        # disk — completed sources' data is then durable if a later source crashes, and can be
        # inspected while the rest still run (same per-unit-of-work durability as checkpoints).
        def _hook(event: str, name: str, result) -> None:
            progress.hook(event, name, result)
            if event == "finish" and result is not None:
                self._flush_source(result)

        # SEQUENTIAL CATEGORY EXECUTION. Instead of fanning out all sources at once, we run one
        # category at a time, in order (CLOUD & STORAGE last). Within a category the sources still
        # run CONCURRENTLY with each other (one run_sources call); the categories themselves run in
        # sequence. Each category gets its own small live block that animates while it runs and then
        # stays as static, natively-scrollable scrollback text — so the live region is never taller
        # than one category and always fits the terminal (no alt-screen, no red-dot truncation).
        # TRADEOFF: categories no longer overlap, so total time is the SUM of each category's slowest
        # source, not the single slowest source overall. The post-steps (breach_lookup, leak_search)
        # run at the END of the PEOPLE & EMAIL block, since they consume that category's harvested
        # emails; they show as two extra rows in that block.
        interrupt_exc: BaseException | None = None
        results: list[SourceResult] = []
        # Group by ALL board rows (labels) so the post-steps appear as rows in PEOPLE & EMAIL, but
        # only the fan-out sources (present in `sources`) are actually run by run_sources — the
        # post-steps are driven manually below.
        blocks = osint_ui.categories_in_run_order(list(labels.keys()))
        try:
            for title, names in blocks:
                cat_sources = {n: sources[n] for n in names if n in sources}
                with progress.category_live(title, names):
                    try:
                        cat_results = await run_sources(cat_sources, _hook)
                        results.extend(cat_results)
                        # Post-steps run inside the PEOPLE & EMAIL block, after its fan-out, so the
                        # harvested emails they consume already exist. Their rows update in place.
                        if title == "PEOPLE & EMAIL":
                            if ctx.config.osint.breach_lookup:
                                _hook("start", "breach_lookup", None)
                                await self._enrich_breaches(results)
                                _hook("finish", "breach_lookup",
                                      self._result_for("breach_lookup", results))
                            if ctx.config.osint.leak_search:
                                _hook("start", "leak_search", None)
                                await self._run_leak_search(results)
                                _hook("finish", "leak_search",
                                      self._result_for("leak_search", results))
                    except (KeyboardInterrupt, asyncio.CancelledError) as exc:
                        # Ctrl+C: show a clean interrupted frame, then RE-RAISE. Re-raising is what
                        # keeps the scan RESUMABLE: the orchestrator only marks a stage complete when
                        # it returns ok+not-skipped, so returning normally here would (wrongly) mark
                        # OSINT complete with partial data — and a resume would then SKIP it, showing
                        # "0 sources · 0 findings". By propagating the interrupt, OSINT stays NOT
                        # complete, so `kaalyx resume` re-runs the whole stage and recovers everything.
                        interrupt_exc = exc
                        progress.set_interrupted()
                        await asyncio.sleep(0.4)
                if interrupt_exc is not None:
                    break        # stop launching further categories on Ctrl+C
        finally:
            set_console_logging(True)
            self._progress = None

        if interrupt_exc is not None:
            # ONE clean line to normal scrollback (no raw INFO/WARNING dump), then re-raise so the
            # orchestrator leaves the stage un-checkpointed (resumable). OSINT is one atomic stage,
            # so resume re-runs it in full — that is how all pre-interrupt results are recovered.
            done = sum(1 for r in results if r.ok or r.skipped)
            osint_ui.get_console().print(
                f"\n[bold yellow]Interrupted[/] — {done}/{len(sources)} sources ran; OSINT is "
                "incomplete and will re-run on [cyan]kaalyx resume[/].")
            raise interrupt_exc

        return self._persist(results)

    @staticmethod
    def _result_for(name: str, results: list[SourceResult]) -> SourceResult:
        """Return the appended post-step SourceResult by name (for the board finish hook)."""
        for r in results:
            if r.name == name:
                return r
        return SourceResult(name=name, ok=True)

    # -- persistence + rendering -------------------------------------------------------

    def _persist(self, results: list[SourceResult]) -> StageResult:
        # Structured records + per-source raw/formatted files are ALREADY written per source as
        # each one finishes (the concurrent finish hook → _flush_source). This final pass writes
        # the AGGREGATE text artifacts (subdomains.txt, emails.txt, the cross-source report) and
        # re-affirms every source's DB rows/files as an idempotent safety net (upserts + dedup
        # merge make the repeat writes harmless), then renders the compact terminal output.
        ctx = self.ctx
        keywords = ctx.config.flagging.interesting_keywords

        all_subs = [s for r in results for s in r.subdomains]
        all_osint = [o for r in results for o in r.osint]
        all_findings = [f for r in results for f in r.findings]
        all_emails = [e for r in results for e in r.emails]
        all_employees = [e for r in results for e in r.employees]
        all_urls = [u for r in results for u in r.urls]

        flag_all(all_subs, keywords)

        if all_subs:
            ctx.repo.bulk_upsert_subdomains(ctx.scan_id, all_subs)
            ctx.writer.write_lines(self.name, "subdomains.txt", [s.hostname for s in all_subs])
        if all_urls:
            # API endpoints / URLs → the shared web_urls table + a file, so the Web stage
            # (Part 4) can pick them up rather than rediscovering them.
            ctx.repo.bulk_upsert_urls(ctx.scan_id, all_urls)
            ctx.writer.write_lines(self.name, "urls.txt", [u.url for u in all_urls])
        if all_osint:
            ctx.repo.bulk_insert_osint(ctx.scan_id, all_osint)
        if all_emails:
            ctx.repo.bulk_upsert_emails(ctx.scan_id, all_emails)
            ctx.writer.write_lines(self.name, "emails.txt", [e.address for e in all_emails])
        if all_employees:
            ctx.repo.bulk_upsert_employees(ctx.scan_id, all_employees)
            ctx.writer.write_lines(
                self.name, "employees.txt",
                [f"{e.name} ({e.source})" for e in all_employees], sort=False,
            )
        for finding in all_findings:
            ctx.repo.upsert_finding(ctx.scan_id, finding)

        # NOTE: no per-kind <kind>.txt files are written — they duplicated content already in each
        # source's readable osint/<source>.txt (and would collide with it, e.g. osint/whois.txt).
        # The cross-source rollups below (findings/subdomains/emails/…) do NOT match any source
        # name, so they never collide with a per-source file.
        if all_findings:
            ctx.writer.write_lines(
                self.name, "findings.txt",
                [f"[{f.severity.value}] {f.category}: {f.title} ({f.target})"
                 for f in all_findings],
                sort=False,
            )
        self._write_status_file(results)
        self._write_raw_source_files(results)
        self._write_report(results)

        # Compact terminal output only (roster + flagged callout + folder path).
        self._render_results(results)

        failed = [r.name for r in results if not r.ok]
        detail = "" if not failed else f"failed sources: {', '.join(failed)}"
        counts = {
            "subdomains": len(all_subs),
            "emails": len(all_emails),
            "employees": len(all_employees),
            "osint": len(all_osint),
            "findings": len(all_findings),
        }
        return self.result(ok=True, counts=counts, detail=detail)

    def _flagged(self, results: list[SourceResult]) -> tuple[list[str], set[str]]:
        """Compute the genuinely noteworthy items for the compact callout AND the set of source
        names that carry a flag (so the board can put a ⚠ right on those rows).

        Deliberately high-signal — only things an operator should look at first: a GitHub-org
        that could not be confidently identified (so the secret scanners skipped), any
        VERIFIED/live-authenticated secret, an exposed/downloadable .git, an exposed Firebase DB,
        and any critical/high finding. NOT a dump of every finding (that lives in the report)."""
        items: list[str] = []
        sources: set[str] = set()

        # Org-identification integrity: the guard against a silent wrong-org scan. Only relevant
        # when an org-scanning source actually RAN in this stage — those sources (trufflehog,
        # github_actions, workflow_logs) were moved out of OSINT, so this callout no longer fires
        # during OSINT. Keyed on the sources present in `results` (self-contained) rather than the
        # raw config toggles, so it re-activates automatically if one is reassigned back here.
        org_consumers = {"trufflehog", "github_actions", "workflow_logs"}
        ran_org_consumer = any(r.name in org_consumers for r in results)
        if ran_org_consumer and self.ctx.secrets.has_github:
            org = self.ctx.get_shared("github_org")
            reason = self.ctx.get_shared("github_org_reason") or ""
            if not org:
                items.append("GitHub org NOT confidently identified — org secret scanners "
                             "skipped (no wrong-org scan). " + reason)
                for r in results:
                    if r.name in org_consumers:
                        sources.add(r.name)

        for r in results:
            for f in r.findings:
                sev = (getattr(f.severity, "value", None) or str(f.severity)).lower()
                conf = (getattr(f.confidence, "value", None) or str(f.confidence)).lower()
                if conf == "confirmed":
                    items.append(f"VERIFIED secret ({r.name}): {f.title} · {f.target}".rstrip(" ·"))
                    sources.add(r.name)
                elif sev in ("critical", "high"):
                    items.append(f"{sev.upper()} ({r.name}): {f.title} · {f.target}".rstrip(" ·"))
                    sources.add(r.name)
        return items, sources

    def _flagged_items(self, results: list[SourceResult]) -> list[str]:
        """The flagged-item display strings (the report and callout use these)."""
        return self._flagged(results)[0]

    def _render_results(self, results: list[SourceResult]) -> None:
        """Terminal output after the scan: JUST the compact completion message. The category-
        grouped board is the LIVE renderable (screen=False), so its final frame already stays in
        normal scrollback when Live exits — there is NO separate static "SOURCE RESULTS" summary
        board (item #7: removed as redundant). NO finding detail / raw dumps here; the [flag] row
        icon is the only flag indicator and the full detail lives in the report file."""
        ctx = self.ctx
        console = osint_ui.get_console()

        flagged, _flagged_sources = self._flagged(results)

        # Compact completion message — folder path + one-line tally. No detail, no dumps, no
        # redundant per-source summary (the live grouped board already showed every source).
        duration = sum(r.duration_s for r in results)
        n_findings = sum(len(r.findings) for r in results)
        folder = str(ctx.writer.stage_dir(self.name))
        console.print()
        console.print(osint_ui.completion_message(
            ctx.domain, folder, duration, len(results), n_findings, len(flagged),
        ))

    def _write_report(self, results: list[SourceResult]) -> None:
        """Write the full, human-readable OSINT report — every source's output in a clean,
        field-labeled layout — to ``<domain>/osint/osint_report.txt``. This is the main artifact:
        the terminal stays compact, the full detail lives here. Never raises (a report-write
        failure must not take down the scan)."""
        try:
            duration = sum(r.duration_s for r in results)
            text = osint_report.build_osint_report(
                self.ctx.domain, results,
                org=self.ctx.get_shared("github_org"),
                org_reason=self.ctx.get_shared("github_org_reason"),
                duration_s=duration,
                flagged=self._flagged_items(results),
            )
            self.ctx.writer.write_text(self.name, "osint_report.txt", text)
        except Exception as exc:  # a report-write failure must never break the scan
            self.log.warning("Could not build OSINT report: %s", exc)

    def _write_status_file(self, results: list[SourceResult]) -> None:
        lines = []
        for r in sorted(results, key=lambda x: x.name):
            state = "ok" if r.ok else "FAILED"
            note = f" — {r.note}" if r.note else (f" — {r.error}" if r.error else "")
            lines.append(f"{r.name:22} {state:7} items={r.total}{note}")
        self.ctx.writer.write_lines(self.name, "_sources_status.txt", lines, sort=False)

    @staticmethod
    def _dump_source(r: SourceResult) -> str:
        """Text dump of a source's own records, used as the raw-file body when the source didn't
        set an explicit ``raw`` payload (so in-process sources still leave a readable artifact)."""
        parts: list[str] = []
        for o in r.osint:
            parts.append(f"{o.kind}\t{o.value}" + (f"\t{o.detail}" if o.detail else ""))
        for s in r.subdomains:
            parts.append(f"subdomain\t{s.hostname}")
        for e in r.emails:
            parts.append(f"email\t{e.address}" + (f"\t{e.source}" if e.source else ""))
        for e in r.employees:
            parts.append(f"employee\t{e.name}" + (f"\t{e.role}" if e.role else ""))
        for f in r.findings:
            parts.append(f"finding\t[{f.severity.value}] {f.category}: {f.title}\t{f.target}"
                         + (f"\t{f.evidence}" if f.evidence else ""))
        return "\n".join(parts)

    def _persist_source_records(self, r: SourceResult) -> None:
        """Write ONE source's structured records to SQLite immediately. Every record type goes to
        its own table with real columns (findings → title/severity/verified/location/file/line/
        value, osint → kind/value/detail/source, emails, employees, subdomains, urls) so the web
        dashboard (Part 6) can query/filter/search rather than parse text. Idempotent: the tables
        upsert by their UNIQUE keys and findings merge by dedup_key, so the final batch pass over
        all results simply re-affirms the same rows. Never raises."""
        ctx = self.ctx
        try:
            if r.subdomains:
                flag_all(r.subdomains, ctx.config.flagging.interesting_keywords)
                ctx.repo.bulk_upsert_subdomains(ctx.scan_id, r.subdomains)
            if r.urls:
                ctx.repo.bulk_upsert_urls(ctx.scan_id, r.urls)
            if r.osint:
                ctx.repo.bulk_insert_osint(ctx.scan_id, r.osint)
            if r.emails:
                ctx.repo.bulk_upsert_emails(ctx.scan_id, r.emails)
            if r.employees:
                ctx.repo.bulk_upsert_employees(ctx.scan_id, r.employees)
            for finding in r.findings:
                ctx.repo.upsert_finding(ctx.scan_id, finding)
        except Exception as exc:  # noqa: BLE001 — a DB write must never break the live scan
            self.log.debug("per-source DB persist failed for %s: %s", r.name, exc)

    def _flush_source(self, r: SourceResult) -> None:
        """Persist ONE source COMPLETELY the moment it finishes — its raw file, its readable file,
        AND its structured SQLite records — so a completed source's data is fully on disk and
        queryable while the OTHER sources are still running (this fires from the concurrent finish
        hook, per source, not in a batch at the end). EXACTLY TWO files per source, no duplication;
        the folder distinguishes readable from raw so the readable one needs no ".formatted" tag:
          * readable field-labeled text → ``osint/<source>.txt``
          * verbatim raw tool output    → ``osint/tool_output/<source>.raw.<ext>``
          * structured records          → SQLite tables (queryable columns)
        Idempotent and never raises (a write error must not take down the live scan)."""
        # 1) verbatim raw output → tool_output/<source>.raw.<ext> (raw data only).
        try:
            content = r.raw if r.raw else self._dump_source(r)
            header = r.note if (not content and r.note) else ""
            self.ctx.writer.raw_source_output(self.name, r.name, content, r.raw_ext, header)
        except Exception as exc:  # noqa: BLE001
            self.log.debug("per-source raw flush failed for %s: %s", r.name, exc)
        # 2) readable field-labeled section → osint/<source>.txt (alongside the report).
        try:
            text = osint_report.render_single_source(
                self.ctx.domain, r,
                org=self.ctx.get_shared("github_org"),
                org_reason=self.ctx.get_shared("github_org_reason"),
            )
            self.ctx.writer.write_text(self.name, f"{r.name}.txt", text)
        except Exception as exc:  # noqa: BLE001
            self.log.debug("per-source readable write failed for %s: %s", r.name, exc)
        # 3) structured records → SQLite (queryable columns) — immediately, per source.
        self._persist_source_records(r)

    def _write_raw_source_files(self, results: list[SourceResult]) -> None:
        """Final safety-net pass: re-flush every source (raw + formatted + DB) so every source has
        its artifacts even if a finish hook was missed, and post-steps whose result is finalized
        after the fan-out (breach_lookup, leak_search) are captured. Sources are already flushed
        individually as they finish (:meth:`_flush_source`); this is idempotent."""
        for r in results:
            self._flush_source(r)

    # -- breach enrichment (post-harvest chaining) -------------------------------------

    async def _enrich_breaches(self, results: list[SourceResult]) -> None:
        """Enrich harvested emails with breach data via h8mail (email→breach chaining).

        h8mail needs API keys/config to return meaningful data; without it we skip cleanly.
        The harvested emails are the input, so this only runs if we actually found emails
        and h8mail is on PATH.
        """
        def _skip(note: str) -> None:
            results.append(SourceResult(name="breach_lookup", ok=True, skipped=True,
                                        note=note, raw_ext="json"))

        emails = [e for r in results for e in r.emails]
        if not emails:
            _skip("skipped: no harvested emails to check")
            return
        if not self.ctx.runner.tool_available("h8mail"):
            self.log.info("breach lookup skipped — h8mail not on PATH (emails kept)")
            _skip("skipped: h8mail not on PATH")
            return

        # Feed emails via stdin file to avoid a huge argv. These are h8mail's own working files
        # (input list + JSON output), not readable artifacts — keep them under tool_output/.
        email_list = "\n".join(sorted({e.address for e in emails}))
        tool_dir = self.ctx.writer.tool_output_dir(self.name)
        infile = tool_dir / "_h8mail_targets.txt"
        outfile = tool_dir / "_h8mail_out.json"
        try:
            infile.write_text(email_list, encoding="utf-8")
        except OSError:
            _skip("skipped: could not write h8mail input file")
            return

        # Build the h8mail command. Beyond breach *counts*, h8mail can return actual cleartext
        # passwords/hashes when pointed at a local breach compilation or credential-returning
        # APIs — so we enable those whenever the operator has configured them (thoroughness
        # over speed). All are optional: absent config => h8mail still runs and returns counts.
        cmd = ["h8mail", "-t", str(infile), "--json", str(outfile), "-q", "quiet"]
        breach_cfg = self.ctx.secrets.h8mail_config      # -c INI with API keys (Snusbase/Dehashed/…)
        breach_comp = self.ctx.secrets.breach_comp_path  # -bc "Breach Compilation" torrent folder
        local_breach = self.ctx.secrets.local_breach_path  # -lb local cleartext dump file(s)
        if breach_cfg:
            cmd += ["-c", breach_cfg]
        if breach_comp:
            cmd += ["-bc", breach_comp]
        if local_breach:
            cmd += ["-lb", local_breach]

        out = await self.ctx.runner.run(cmd, timeout=1800, label="h8mail")
        if not out.started:
            self.log.info("breach lookup skipped — h8mail not runnable (emails kept)")
            _skip("skipped: h8mail not runnable")
            return
        # h8mail writes JSON to outfile; read it back.
        try:
            data = outfile.read_text(encoding="utf-8")
        except OSError:
            data = out.stdout
        breach_map = P.parse_h8mail(data)
        if not breach_map:
            self.log.info("breach lookup: no breach data (likely no API keys / local breach configured)")
            results.append(SourceResult(name="breach_lookup", ok=True,
                                        note="no breach data", raw=data, raw_ext="json"))
            return

        enriched: list[Email] = []
        findings: list[Finding] = []
        cred_total = 0
        for e in emails:
            res = breach_map.get(e.address.lower())
            if not res or res.count <= 0:
                continue
            # Note in the breach_detail how many actual credentials were recovered, so the
            # emails table reflects "not just a yes/no".
            detail = res.detail
            if res.credentials:
                detail = (detail + f" | {len(res.credentials)} credential(s) recovered").strip(" |")
            enriched.append(Email(address=e.address, source="h8mail",
                                  breached=True, breach_count=res.count, breach_detail=detail))
            # Summary finding: appears in N breaches.
            findings.append(Finding(
                title=f"Breached credential: {e.address}",
                category="credential-leak",
                severity=self._breach_severity(res.count),
                tool="h8mail",
                target=e.address,
                description=f"Appears in {res.count} known breach(es): {res.detail}",
                evidence=res.detail,
            ))
            # One finding PER recovered credential, carrying the actual leaked value.
            for cred in res.credentials:
                cred_total += 1
                is_pw = cred.kind == "password"
                findings.append(Finding(
                    title=(f"Leaked password for {cred.email}" if is_pw
                           else f"Leaked {cred.kind} for {cred.email}"),
                    category="credential-leak",
                    severity=Severity.HIGH if is_pw else Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    tool="h8mail",
                    target=cred.email,
                    description=(f"{cred.kind.capitalize()} recovered from {cred.source}."),
                    evidence=f"{cred.email}:{cred.value}",
                ))
        # Always append a breach_lookup result (with the raw h8mail JSON) so it gets a
        # dedicated raw file even when nothing was breached.
        results.append(SourceResult(
            name="breach_lookup", ok=True, emails=enriched, findings=findings,
            note=(f"{len(enriched)} breached, {cred_total} credential(s) recovered"
                  if enriched else "no breached emails"),
            raw=data, raw_ext="json",
        ))
        if enriched:
            self.log.warning("breach lookup: %d breached email(s), %d credential(s) recovered",
                             len(enriched), cred_total)

    @staticmethod
    def _breach_severity(count: int) -> Severity:
        return Severity.HIGH if count >= 3 else Severity.MEDIUM

    async def _run_leak_search(self, results: list[SourceResult]) -> None:
        """Query LeakSearch (a credential-dump source) for ACTUAL leaked passwords.

        LeakSearch searches the ProxyNova/COMB dump (keyless) and returns real user:password
        pairs — value h8mail can't give without a local breach compilation. We key it on the
        target DOMAIN (catches any ``user@domain`` in the dump) AND on each harvested email
        (catches employees whose leaked account uses a different address). Skips cleanly if
        the tool isn't installed. Each recovered credential becomes one finding.
        """
        if not self.ctx.runner.tool_available("LeakSearch") and \
                not self.ctx.runner.tool_available("leaksearch"):
            results.append(SourceResult(name="leak_search", ok=True, skipped=True,
                                        note="skipped: LeakSearch not on PATH", raw_ext="json"))
            return
        binary = "LeakSearch" if self.ctx.runner.tool_available("LeakSearch") else "leaksearch"

        # Query keys: the registrable domain first, then each unique harvested email.
        keys: list[str] = [self.ctx.target.registrable]
        seen_emails = {e.address.lower() for r in results for e in r.emails}
        keys += sorted(seen_emails)

        # Live N/total counter on the LEAKSEARCH board row (one increment per key queried).
        prog = getattr(self, "_progress", None)
        if prog is not None:
            prog.set_progress("leak_search", 0, len(keys))

        # LeakSearch's per-key JSON outputs are working files, not readable artifacts → tool_output/.
        tool_dir = self.ctx.writer.tool_output_dir(self.name)
        findings: list[Finding] = []
        combined_raw: list[str] = []
        for i, key in enumerate(keys):
            outfile = tool_dir / f"_leaksearch_{i}.json"
            # -d ProxyNova = keyless online dump; -n 100 raises the default 20-result cap
            # (thoroughness over speed); -o writes JSON we parse.
            out = await self.ctx.runner.run(
                [binary, "-k", key, "-d", "ProxyNova", "-n", "100", "-o", str(outfile)],
                timeout=600, label="LeakSearch",
            )
            if prog is not None:
                prog.set_progress("leak_search", i + 1, len(keys))
            if not out.started:
                results.append(SourceResult(name="leak_search", ok=True, skipped=True,
                                            note="skipped: LeakSearch not runnable",
                                            raw_ext="json"))
                return
            try:
                data = outfile.read_text(encoding="utf-8")
            except OSError:
                data = out.stdout
            combined_raw.append(f"# key={key}\n{data}")
            findings.extend(P.parse_leaksearch(data, target=self.ctx.target.registrable))

        raw_blob = "\n\n".join(combined_raw)
        # Dedup findings by (target, evidence) since domain + email queries can overlap.
        unique: dict[str, Finding] = {}
        for f in findings:
            unique.setdefault(f"{f.target}|{f.evidence}", f)
        deduped = list(unique.values())
        if deduped:
            results.append(SourceResult(
                name="leak_search", ok=True, findings=deduped,
                note=f"{len(deduped)} leaked credential(s)", raw=raw_blob, raw_ext="json",
            ))
            self.log.warning("leak search: %d leaked credential(s) found", len(deduped))
        else:
            results.append(SourceResult(
                name="leak_search", ok=True, note="no leaked credentials found",
                raw=raw_blob, raw_ext="json",
            ))

    # -- external-tool sources ---------------------------------------------------------

    async def _src_whois(self) -> SourceResult:
        res = SourceResult(name="whois")
        out = await self.ctx.runner.run(["whois", self.ctx.target.registrable],
                                        timeout=120, label="whois")
        if not out.started:
            res.skipped, res.note = True, "skipped: whois not on PATH"
            return res
        text = out.stdout.strip()
        if text:
            res.raw, res.raw_ext = text, "txt"
            res.osint = P.parse_whois(text)
        return res

    async def _src_dnsx(self) -> SourceResult:
        res = SourceResult(name="dnsx")
        cmd = ["dnsx", "-json", "-silent", "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-soa"]
        out = await self.ctx.runner.run(cmd, stdin=self.ctx.target.registrable + "\n",
                                        timeout=120, label="dnsx")
        if not out.started:
            res.skipped, res.note = True, "skipped: dnsx not on PATH"
            return res
        res.raw, res.raw_ext = out.stdout, "json"
        res.osint = P.parse_dnsx(out.stdout)
        return res

    async def _src_github_subdomains(self) -> SourceResult:
        res = SourceResult(name="github_subdomains", raw_ext="txt")
        if not self.ctx.secrets.has_github:
            res.skipped, res.note = True, "skipped: GITHUB_TOKEN not set"
            res.raw = "# skipped: GITHUB_TOKEN not set"
            return res
        # github-subdomains searches GitHub CODE for the domain string and extracts subdomains
        # (this is DIFFERENT from trufflehog: it's a global code search for the domain, not an
        # org scan). Token via env (never argv, so it isn't in the process list); the same
        # GITHUB_TOKEN the tool documents reading. `-e` = extended search (more code queries →
        # more thorough), consistent with the project's thoroughness-over-speed principle.
        cmd = ["github-subdomains", "-d", self.ctx.target.registrable, "-e"]
        out = await self.ctx.runner.run(
            cmd, env={"GITHUB_TOKEN": self.ctx.secrets.next_github_token() or ""},
            timeout=300, label="github-subdomains",
        )
        if not out.started:
            res.skipped, res.note = True, "skipped: github-subdomains not on PATH"
            res.raw = "# skipped: github-subdomains not on PATH"
            return res
        # Capture the tool's raw stdout so a 0-result run is inspectable on disk (why it found
        # nothing — an empty search vs. a rate-limit/error message from the tool).
        res.raw = out.stdout
        res.subdomains = P.parse_subdomain_lines(out.stdout, "github-subdomains")
        res.note = (f"{len(res.subdomains)} subdomain(s) from GitHub code search"
                    if res.subdomains else "no subdomains found in GitHub code")
        return res

    async def _src_gitgraber(self) -> SourceResult:
        """gitGraber — service-specific secret-pattern scan of public GitHub code (needs a
        GITHUB_TOKEN). Complementary to trufflehog (org repos) and github_subdomains (generic
        keyword search): gitGraber uses curated per-service regexes (AWS/Stripe/Twilio/
        Mailgun/PayPal/Heroku/…). It reads tokens from its own config.py, so we GENERATE that
        file at scan time from our rotated GITHUB_TOKEN (never argv, never committed)."""
        import shutil
        res = SourceResult(name="gitgraber", raw_ext="txt")
        if not self.ctx.secrets.has_github:
            res.skipped, res.note = True, "skipped: GITHUB_TOKEN not set"
            res.raw = "# skipped: GITHUB_TOKEN not set"
            return res
        # Locate the cloned gitGraber (install.sh clones to ~/src/gitGraber).
        gg_dir = Path.home() / "src" / "gitGraber"
        gg_py = gg_dir / "gitGraber.py"
        keywords = gg_dir / "wordlists" / "keywords.txt"
        venv_py = gg_dir / ".venv" / "bin" / "python"
        python_bin = str(venv_py) if venv_py.exists() else "python3"
        if not gg_py.exists():
            res.skipped, res.note = True, "skipped: gitGraber not installed (run: kaalyx tools --install)"
            res.raw = "# skipped: gitGraber not installed"
            return res
        # Generate config.py with our token(s). gitGraber does `from config import GITHUB_TOKENS`
        # plus optional Slack/Discord/Telegram vars — provide safe empty defaults so importing it
        # never errors and no notifier fires. Written fresh each run; never committed.
        tokens = self.ctx.secrets.github_tokens or []
        try:
            (gg_dir / "config.py").write_text(
                "GITHUB_TOKENS = " + repr(tokens) + "\n"
                "SLACK_WEBHOOKURL = ''\n"
                "DISCORD_WEBHOOKURL = ''\n"
                "TELEGRAM_CONFIG = {'token': '', 'chat_id': 0}\n",
                encoding="utf-8")
        except OSError as exc:
            res.skipped, res.note = True, f"skipped: could not write gitGraber config ({exc})"
            res.raw = f"# skipped: {exc}"
            return res
        # Run from gitGraber's own dir (it reads config.py / wordlists / writes rawGitUrls.txt
        # relative to cwd). Query the full registrable domain. No -s/-d/-tg → no notifiers.
        cmd = [python_bin, str(gg_py), "-k", str(keywords), "-q", self.ctx.target.registrable]
        out = await self.ctx.runner.run(cmd, cwd=str(gg_dir), timeout=900, label="gitGraber")
        if not out.started:
            res.skipped, res.note = True, "skipped: gitGraber not runnable"
            res.raw = "# skipped: gitGraber not runnable"
            return res
        res.raw = out.stdout
        res.findings = P.parse_gitgraber(out.stdout)
        res.note = (f"{len(res.findings)} possible secret(s)" if res.findings
                    else "no secrets matched in public code")
        return res

    async def _discover_github_org(self) -> None:
        """Identify the target's GitHub org(s) and stash the best one in ctx.shared.

        Delegates to the shared, cross-stage helper (:func:`stages.github_org.ensure_github_org`)
        so OSINT and the Subdomains stage discover the org identically and it runs at most once per
        pipeline. See that module for the data-integrity gate (HIGH-confidence only)."""
        from .github_org import ensure_github_org
        await ensure_github_org(self.ctx)

    async def _src_trufflehog(self) -> SourceResult:
        res = SourceResult(name="trufflehog")
        if not self.ctx.secrets.has_github:
            res.skipped, res.note = True, "skipped: GITHUB_TOKEN not set (org scan)"
            return res
        # Scan the TARGET's org (identified in the pre-step), never the token owner. No
        # confidently-identified org => skip cleanly rather than scan the wrong account.
        org = self.ctx.get_shared("github_org")
        if not org:
            res.skipped = True
            res.note = f"skipped: no GitHub org identified for {self.ctx.target.registrable}"
            return res
        cmd = ["trufflehog", "github", "--org", org, "--json"]
        out = await self.ctx.runner.run(
            cmd, env={"GITHUB_TOKEN": self.ctx.secrets.next_github_token() or ""},
            timeout=1800, label="trufflehog",
        )
        if not out.started:
            res.skipped, res.note = True, "skipped: trufflehog not on PATH"
            return res
        res.raw, res.raw_ext = out.stdout, "json"
        # Defense-in-depth: keep only secrets whose repo actually belongs to the target org,
        # so a trufflehog fallback-to-authenticated-user can never leak the operator's repos.
        res.findings = P.parse_trufflehog(out.stdout, restrict_owner=org)
        res.note = f"org={org}"
        return res

    def _cloud_keywords(self) -> list[str]:
        """Keyword variants for cloud-bucket enumeration.

        A single ``registrable.split('.')[0]`` (e.g. ``kycaid``) misses buckets that follow
        common org naming conventions. We feed several variants so enumeration is thorough:
        the bare base, the full registrable domain, and hyphen-collapsed forms. Thoroughness
        over speed — testing a few extra keywords is cheap next to missing an exposed bucket.
        """
        reg = self.ctx.target.registrable
        base = reg.split(".")[0]
        variants = [base, reg, reg.replace(".", "-")]
        if "-" in base:
            variants.append(base.replace("-", ""))
        # Preserve order, drop dupes/empties.
        seen: set[str] = set()
        return [k for k in variants if k and not (k in seen or seen.add(k))]

    async def _src_cloud_enum(self) -> SourceResult:
        res = SourceResult(name="cloud_enum")
        keywords = self._cloud_keywords()
        # Full enumeration (NOT --quickscan): --quickscan skips the brute-force name
        # mutations, testing far fewer candidate bucket/blob names. Kaalyx favours finding
        # more over finishing sooner, so we run the complete scan across every keyword.
        cmd = ["cloud_enum"]
        for kw in keywords:
            cmd += ["-k", kw]
        out = await self.ctx.runner.run(cmd, timeout=1800, label="cloud_enum")
        if not out.started:
            res.skipped, res.note = True, "skipped: cloud_enum not on PATH"
            return res
        res.raw, res.raw_ext = out.stdout, "txt"
        res.findings = P.parse_cloud_enum(out.stdout, target=self.ctx.target.registrable)
        res.note = f"keywords={','.join(keywords)}"
        return res

    async def _src_s3scanner(self) -> SourceResult:
        res = SourceResult(name="s3scanner")
        keywords = self._cloud_keywords()
        # s3scanner takes one -bucket per invocation; run it across every keyword variant so
        # a bucket named after any of the org's conventions is caught (completeness first).
        all_out: list[str] = []
        started = False
        for kw in keywords:
            out = await self.ctx.runner.run(["s3scanner", "-bucket", kw],
                                            timeout=300, label="s3scanner")
            if not out.started:
                break
            started = True
            all_out.append(out.stdout)
        if not started:
            res.skipped, res.note = True, "skipped: s3scanner not on PATH"
            return res
        combined = "\n".join(all_out)
        res.raw, res.raw_ext = combined, "txt"
        res.findings = P.parse_s3scanner(combined, target=self.ctx.target.registrable)
        res.note = f"keywords={','.join(keywords)}"
        return res

    async def _src_badsecrets(self) -> SourceResult:
        res = SourceResult(name="badsecrets")
        out = await self.ctx.runner.run(["badsecrets", "-u", f"https://{self.ctx.domain}"],
                                        timeout=180, label="badsecrets")
        if not out.started:
            res.skipped, res.note = True, "skipped: badsecrets not on PATH"
            return res
        res.raw, res.raw_ext = out.stdout, "json"
        res.findings = P.parse_badsecrets(out.stdout)
        return res

    async def _src_retirejs(self) -> SourceResult:
        res = SourceResult(name="retirejs")
        out = await self.ctx.runner.run(
            ["retire", "--outputformat", "json", "--jspath", f"https://{self.ctx.domain}"],
            timeout=300, label="retirejs", acceptable_codes=(0, 13),  # 13 = vulns found
        )
        if not out.started:
            res.skipped, res.note = True, "skipped: retire not on PATH"
            return res
        res.raw, res.raw_ext = out.stdout, "json"
        res.findings = P.parse_retirejs(out.stdout)
        return res

    async def _src_theharvester(self) -> SourceResult:
        res = SourceResult(name="theharvester")
        # theHarvester's own -f output files are working artifacts → tool_output/.
        tool_dir = self.ctx.writer.tool_output_dir(self.name)
        out_base = tool_dir / "_theharvester"
        cmd = ["theHarvester", "-d", self.ctx.target.registrable, "-b", "all",
               "-f", str(out_base)]
        out = await self.ctx.runner.run(cmd, timeout=900, label="theHarvester")
        if not out.started:
            res.skipped, res.note = True, "skipped: theHarvester not on PATH"
            return res
        # theHarvester writes <base>.json (and .xml). Read the JSON.
        data = ""
        for candidate in (out_base.with_suffix(".json"),
                          tool_dir / "_theharvester.json"):
            try:
                data = candidate.read_text(encoding="utf-8")
                break
            except OSError:
                continue
        if not data:
            data = out.stdout  # fallback
        res.raw, res.raw_ext = data, "json"   # dedicated raw/theharvester.json
        emails, employees, subs = P.parse_theharvester(data, self.ctx.target.registrable)
        res.emails, res.employees, res.subdomains = emails, employees, subs
        return res

    async def _src_misconfig(self) -> SourceResult:
        res = SourceResult(name="third_party_misconfig")
        # -output-json gives structured, reliable results; without it the tool's progress
        # and "not found" log lines are indistinguishable from real hits in plain text.
        cmd = ["misconfig-mapper", "-target", self.ctx.target.registrable,
               "-as-domain", "-service", "*", "-output-json"]
        out = await self.ctx.runner.run(cmd, timeout=600, label="misconfig-mapper")
        if not out.started:
            res.skipped, res.note = True, "skipped: misconfig-mapper not on PATH"
            return res
        res.raw, res.raw_ext = out.stdout, "json"
        res.findings = P.parse_misconfig_mapper(out.stdout)
        return res

    async def _src_api_leaks(self) -> SourceResult:
        """API-leak discovery: porch-pirate (public Postman) + SwaggerSpy (OpenAPI specs).

        Two independent tools, each optional. Whichever is on PATH runs; if neither is, the
        source skips cleanly. Findings from both are merged.
        """
        res = SourceResult(name="api_leaks")
        keyword = self.ctx.target.registrable
        ran_any = False

        # api_leaks fans out to two tools; write a DEDICATED raw file for EACH, always — even
        # when a tool is absent or empty (porch-pirate.json / swaggerspy.txt), matching the
        # "one file per source, no exceptions" rule.
        # --raw emits JSON so we get structured workspace/collection objects (one finding
        # each) instead of free-text we'd otherwise have to guess at line by line.
        pp = await self.ctx.runner.run(
            ["porch-pirate", "-s", keyword, "-l", "25", "--raw"],
            timeout=600, label="porch-pirate",
        )
        if pp.started:
            ran_any = True
            self.ctx.writer.raw_source_output(self.name, "porch-pirate", pp.stdout, "json")
            pp_findings, pp_subs = P.parse_porch_pirate(
                pp.stdout, target=self.ctx.target.registrable)
            res.findings.extend(pp_findings)
            res.subdomains.extend(pp_subs)  # hostnames leaking in request URLs -> Part 2
        else:
            self.ctx.writer.raw_source_output(self.name, "porch-pirate", "", "json",
                                              header="skipped: porch-pirate not on PATH")

        ss = await self.ctx.runner.run(
            ["swaggerspy", keyword], timeout=600, label="swaggerspy",
        )
        if ss.started:
            ran_any = True
            self.ctx.writer.raw_source_output(self.name, "swaggerspy", ss.stdout, "txt")
            ss_findings, ss_subs = P.parse_swaggerspy(
                ss.stdout, target=self.ctx.target.registrable)
            res.findings.extend(ss_findings)
            res.subdomains.extend(ss_subs)
        else:
            self.ctx.writer.raw_source_output(self.name, "swaggerspy", "", "txt",
                                              header="skipped: swaggerspy not on PATH")

        if not ran_any:
            res.skipped = True
            res.note = "skipped: porch-pirate & swaggerspy not on PATH"
        return res

    async def _src_exposed_git(self) -> SourceResult:
        """Detect a publicly exposed ``/.git/`` directory (in-process, detect-only).

        Uses a reliable check (GET /.git/config → 200 + '[core]' + not HTML) via
        `osint_inproc.check_exposed_git`. No download/reconstruction. Probes the apex host and
        its ``www.`` (broader per-host probing across all discovered subdomains belongs to the
        Hosts/Web stages). Keyless — never skips for a missing tool.
        When /.git/config is exposed, we then confirm it is actually *downloadable* (a bounded
        fetch of HEAD/index/logs — no repo reconstruction). If confirmed, the CRITICAL
        download-confirmed finding supersedes the plain-detection HIGH one for that host.
        """
        res = SourceResult(name="exposed_git")
        candidates = {self.ctx.domain}
        if self.ctx.target.is_apex:
            candidates.add(f"www.{self.ctx.domain}")
        for host in sorted(candidates):
            finding = await osint_inproc.check_exposed_git(host)
            if finding is None:
                continue
            # Exposed — now confirm downloadability. Prefer the upgraded finding if confirmed.
            downloadable = await osint_inproc.download_exposed_git(host)
            res.findings.append(downloadable or finding)
        if not res.findings:
            res.note = "no exposed .git found"
        else:
            dl = sum(1 for f in res.findings if f.severity.value == "critical")
            res.note = f"{len(res.findings)} exposed .git" + (f", {dl} downloadable" if dl else "")
        return res

    async def _src_firebase(self) -> SourceResult:
        """Check for an exposed Firebase Realtime Database (keyless, in-process).

        Distinct from the generic cloud_enum/s3scanner bucket checks: a Firebase RTDB has its
        own REST exposure pattern (``https://<id>.firebaseio.com/.json`` and the regional
        ``firebasedatabase.app`` variants). Candidate project ids reuse the SAME keyword
        variants as cloud-bucket enumeration. A world-readable DB is MEDIUM; if a
        non-destructive empty-merge PATCH is also accepted it is world-writable → HIGH. Always
        writes a dedicated raw file listing the candidates probed."""
        res = SourceResult(name="firebase", raw_ext="txt")
        candidates = osint_inproc._firebase_candidates(self.ctx.target)
        records, findings = await osint_inproc.check_firebase_exposure(candidates)
        res.osint, res.findings = records, findings
        # Raw file: what we probed + any exposures (so the artifact exists even with 0 hits).
        raw_lines = [f"# firebase candidates probed: {', '.join(candidates)}",
                     f"# host families: firebaseio.com + firebasedatabase.app regional", ""]
        if findings:
            for f in findings:
                raw_lines.append(f"[{f.severity.value.upper()}] {f.target} — {f.title}")
        else:
            raw_lines.append("# no exposed Firebase Realtime Database found")
        res.raw = "\n".join(raw_lines)
        if not findings:
            res.note = f"no exposure ({len(candidates)} candidate(s) probed)"
        else:
            hi = sum(1 for f in findings if f.severity.value == "high")
            res.note = f"{len(findings)} exposed DB(s)" + (f", {hi} writable" if hi else "")
        return res

    # -- Reference-parity OSINT sources (mostly keyless in-process) ---------------------------

    async def _src_internetdb(self) -> SourceResult:
        """Shodan InternetDB — free/keyless per-IP ports, CPEs and CVE tags (no packets to
        target). Companion to the paid shodan_host; needs no key."""
        res = SourceResult(name="internetdb", raw_ext="txt")
        ips = await self._resolved_ips()
        if not ips:
            res.skipped, res.note = True, "skipped: no resolvable IP"
            res.raw = "# skipped: no resolvable IP"
            return res
        records, findings = await osint_inproc.internetdb_lookup(ips)
        res.osint, res.findings = records, findings
        res.raw = "\n".join([f"# InternetDB probed {len(ips)} IP(s)"] +
                            [f"{r.value}: {r.detail}" for r in records] or ["# no data"])
        res.note = f"{len(ips)} IP(s), {len(records)} known, {len(findings)} with CVE tags"
        return res

    async def _src_tls_cert(self) -> SourceResult:
        """Extract the live TLS leaf certificate (SANs → subdomains, issuer, validity). Keyless."""
        res = SourceResult(name="tls_cert", raw_ext="txt")
        records, sans = await osint_inproc.extract_tls_cert(self.ctx.domain)
        res.osint = records
        # SANs on the target domain are also subdomain hints.
        for host in sans:
            res.subdomains.append(Subdomain(hostname=host, source="tls_cert"))
        res.raw = "\n".join([f"# TLS certificate for {self.ctx.domain}"] +
                            [f"{r.detail}: {r.value}" for r in records] or ["# no certificate"])
        if not records:
            res.note = "no TLS certificate retrieved"
        else:
            res.note = f"{len(records)} cert field(s), {len(sans)} SAN subdomain(s)"
        return res

    async def _src_gitlab(self) -> SourceResult:
        """Discover a public GitLab.com group/user matching the company (keyless)."""
        res = SourceResult(name="gitlab", raw_ext="txt")
        slugs = osint_inproc._company_slugs(self.ctx.target)
        records = await osint_inproc.discover_gitlab(slugs)
        res.osint = records
        res.raw = "\n".join([f"# GitLab slugs probed: {', '.join(slugs)}"] +
                            [f"{r.value}  ({r.detail})" for r in records] or ["# no match"])
        res.note = f"{len(records)} GitLab namespace(s)" if records else "no GitLab namespace found"
        return res

    async def _src_dockerhub(self) -> SourceResult:
        """List public Docker Hub repositories under a company-matching namespace (keyless)."""
        res = SourceResult(name="dockerhub", raw_ext="txt")
        slugs = osint_inproc._company_slugs(self.ctx.target)
        records = await osint_inproc.discover_dockerhub(slugs)
        res.osint = records
        res.raw = "\n".join([f"# Docker Hub namespaces probed: {', '.join(slugs)}"] +
                            [f"{r.value}  ({r.detail})" for r in records] or ["# no repos"])
        res.note = f"{len(records)} Docker Hub repo(s)" if records else "no Docker Hub repos found"
        return res

    async def _src_mobile_apps(self) -> SourceResult:
        """Discover the org's published mobile apps (Apple + Google Play). Keyless.

        A company's apps are usually published under its real legal/brand name, not the bare
        domain label — so we first resolve RANKED company identities (RDAP registrant org, M365
        tenant brand, social handles, domain label) and search on all of them, tagging each hit
        with the signal that matched it."""
        res = SourceResult(name="mobile_apps", raw_ext="txt")
        # The resolver fetches its own signals (RDAP org, M365 tenant brand, social handles,
        # domain label) so it is self-contained regardless of concurrent source ordering.
        identities = await osint_inproc.resolve_company_identities(self.ctx.target)
        records = await osint_inproc.discover_mobile_apps(identities)
        res.osint = records
        ident_summary = ", ".join(f"{i.name}[{i.signal}:{i.confidence}]" for i in identities)
        res.raw = "\n".join([f"# company identities resolved: {ident_summary}"] +
                            [f"{r.value}  ({r.detail})" for r in records] or ["# no apps"])
        res.note = (f"{len(records)} mobile app(s) via {len(identities)} identity signal(s)"
                    if records else f"no mobile apps ({len(identities)} identities tried)")
        return res

    async def _src_affiliate_domains(self) -> SourceResult:
        """Find affiliate/related domains sharing the org's TLS certs via crt.sh (keyless)."""
        res = SourceResult(name="affiliate_domains", raw_ext="txt")
        slugs = osint_inproc._company_slugs(self.ctx.target)
        records = await osint_inproc.discover_affiliate_domains(slugs, self.ctx.target.registrable)
        res.osint = records
        res.raw = "\n".join([f"# affiliate-domain search (crt.sh) slugs: {', '.join(slugs)}"] +
                            [f"{r.value}  ({r.detail})" for r in records] or ["# no affiliates"])
        res.note = f"{len(records)} affiliate domain(s)" if records else "no affiliate domains found"
        return res

    async def _src_dnstwist(self) -> SourceResult:
        """Typosquatting / look-alike domain discovery via the dnstwist external tool."""
        res = SourceResult(name="dnstwist", raw_ext="json")
        cmd = ["dnstwist", "--format", "json", "--registered", self.ctx.target.registrable]
        out = await self.ctx.runner.run(cmd, timeout=600, label="dnstwist")
        if not out.started:
            res.skipped, res.note = True, "skipped: dnstwist not on PATH"
            res.raw = "# skipped: dnstwist not on PATH"
            return res
        res.raw = out.stdout
        records, findings = P.parse_dnstwist(out.stdout, self.ctx.target.registrable)
        res.osint, res.findings = records, findings
        res.note = f"{len(records)} registered look-alike domain(s)"
        return res

    async def _src_workflow_logs(self) -> SourceResult:
        """Scan the org's GitHub Actions run logs for leaked secrets (needs GITHUB_TOKEN)."""
        res = SourceResult(name="workflow_logs", raw_ext="txt")
        if not self.ctx.secrets.has_github:
            res.skipped, res.note = True, "skipped: GITHUB_TOKEN not set"
            res.raw = "# skipped: GITHUB_TOKEN not set"
            return res
        org = self.ctx.get_shared("github_org")
        if not org:
            res.skipped, res.note = True, "skipped: no target GitHub org identified"
            res.raw = "# skipped: no target GitHub org identified"
            return res
        token = self.ctx.secrets.next_github_token() or ""
        records, findings = await osint_inproc.scan_workflow_logs(org, token)
        res.osint, res.findings = records, findings
        res.raw = "\n".join([f"# workflow-log scan for org: {org}"] +
                            [f"{r.value}: {r.detail}" for r in records] or ["# no logs scanned"])
        res.note = (f"{len(records)} run log(s), {len(findings)} secret(s)"
                    if records else "no accessible run logs")
        return res

    async def _src_github_actions(self) -> SourceResult:
        """Audit the org's GitHub Actions with gato.

        Needs GITHUB_TOKEN (passed via env). Note that a token being *present* is only
        enough to run gato — to actually surface findings the token needs broader scope:
        ``repo`` to enumerate accessible repos/secrets, and ``admin:org`` for org-level
        self-hosted runners and org secrets. With a minimal-scope token gato runs but
        typically returns nothing, so an empty result here is expected, not a failure.
        """
        res = SourceResult(name="github_actions")
        if not self.ctx.secrets.has_github:
            res.skipped, res.note = (
                True,
                "skipped: GITHUB_TOKEN not set (needs repo + admin:org scope for full results)",
            )
            return res
        # Audit the TARGET's org (from the pre-step), never the token owner. No identified
        # org => skip cleanly.
        org = self.ctx.get_shared("github_org")
        if not org:
            res.skipped = True
            res.note = f"skipped: no GitHub org identified for {self.ctx.target.registrable}"
            return res
        json_out = self.ctx.writer.tool_output_dir(self.name) / "_gato.json"
        gh = self.ctx.secrets.next_github_token() or ""
        out = await self.ctx.runner.run(
            ["gato", "enumerate", "-t", org, "--output-json", str(json_out)],
            env={"GITHUB_TOKEN": gh, "GH_TOKEN": gh},
            timeout=900, label="gato",
        )
        if not out.started:
            res.skipped, res.note = True, "skipped: gato not on PATH"
            return res
        res.raw, res.raw_ext = out.stdout, "json"
        # Prefer the structured JSON file; fall back to parsing stdout text.
        try:
            json_text = json_out.read_text(encoding="utf-8")
        except OSError:
            json_text = ""
        gato_json = json_text or out.stdout
        res.findings = P.parse_gato(gato_json)
        if res.findings:
            res.note = f"org={org}"
        else:
            # Ran cleanly but found nothing — diagnose the REAL cause from gato's own JSON
            # (token scope vs. the user not being a member of the target org), not a guess.
            res.note = f"org={org}: {P.diagnose_gato_no_findings(gato_json, org)}"
        return res

    # -- in-process sources ------------------------------------------------------------

    async def _src_mail_dns(self) -> SourceResult:
        res = SourceResult(name="mail_dns")
        domain = self.ctx.target.registrable
        records, findings, caa_emails = await osint_inproc.check_mail_dns_security(domain)
        res.osint, res.findings = records, findings
        # CAA iodef contact emails feed the harvest → breach/leak chain.
        res.emails = caa_emails

        # Spoofability verdict (Spoofy logic) layered on the SPF/DMARC records just fetched —
        # no extra DNS lookup. Only raise a finding when the domain IS spoofable.
        spf = next((r.value for r in records if r.kind == "spf"), None)
        dmarc = next((r.value for r in records if r.kind == "dmarc"), None)
        spoofable, reason = osint_inproc.assess_spoofability(spf, dmarc)
        res.osint.append(OsintRecord(
            kind="spoofable", value="yes" if spoofable else "no",
            detail=reason, source="mail_dns",
        ))
        if spoofable:
            res.findings.append(Finding(
                title="Domain is email-spoofable",
                category="email-security",
                severity=Severity.MEDIUM,
                confidence=Confidence.FIRM,
                target=domain,
                tool="mail_dns",
                description=f"SPF/DMARC posture allows spoofing: {reason}.",
                evidence=reason,
            ))
        return res

    async def _src_ip_info(self) -> SourceResult:
        res = SourceResult(name="ip_info")
        # Resolve the target's IP(s) and fetch geo/ASN/ISP-org/reverse-IP per IP, with automatic
        # fallback across ip-api.com → ipapi.co → ipinfo.io (last only if IPINFO_TOKEN is set).
        res.osint = await osint_inproc.ip_info(
            self.ctx.target.registrable, self.ctx.secrets.ipinfo_token)
        if not res.osint:
            res.note = "no resolvable IP"
        else:
            # Surface whether every IP's lookup exhausted all sources, so a genuine failure is
            # never a silent gap in the live board.
            failed = [r for r in res.osint if r.detail.startswith("failed=1")]
            if failed and len(failed) == len(res.osint):
                res.note = f"{len(res.osint)} IP(s) — geo lookup failed (all sources)"
            elif failed:
                res.note = f"{len(res.osint)} IP(s), {len(failed)} geo lookup failed"
            else:
                res.note = f"{len(res.osint)} IP(s)"
        return res

    async def _src_m365(self) -> SourceResult:
        res = SourceResult(name="m365")
        records, findings = await osint_inproc.map_m365_tenant(self.ctx.target.registrable)
        res.osint, res.findings = records, findings
        if not records:
            res.note = "no Microsoft tenant detected"
        return res

    async def _src_email_harvest(self) -> SourceResult:
        res = SourceResult(name="email_harvest")
        domain = self.ctx.target.registrable
        # Merge three keyless email sources: email-format.com + skymem
        # (harvest_emails), PGP keyservers (pgp), and security.txt Contact: addresses. All
        # filter to on-domain addresses; deduped by address, sources concatenated.
        merged: dict[str, str] = {}

        def _merge(items) -> None:
            for e in items:
                if e.address in merged:
                    if e.source not in merged[e.address]:
                        merged[e.address] = f"{merged[e.address]},{e.source}"
                else:
                    merged[e.address] = e.source

        _merge(await osint_inproc.harvest_emails(domain))
        _merge(await osint_inproc.harvest_pgp_emails(domain))
        sec_emails, sec_records = await osint_inproc.fetch_securitytxt(domain)
        _merge(sec_emails)
        res.emails = [Email(address=a, source=s) for a, s in sorted(merged.items())]
        res.osint = sec_records  # security.txt presence + Contact/Policy URLs
        if not res.emails:
            res.note = "no public emails found"
        return res

    async def _src_social(self) -> SourceResult:
        res = SourceResult(name="social")
        records, _handles, blocked = await osint_inproc.discover_social_profiles(
            self.ctx.target.registrable)
        res.osint = records
        if not records:
            # Distinguish "site blocked our request" (a WAF/403) from a genuine no-profiles
            # result, so the empty file/row isn't misleading.
            res.note = ("homepage blocked (WAF/403) — no social profiles readable"
                        if blocked else "no social profiles found")
        return res

    async def _src_google_dorks(self) -> SourceResult:
        res = SourceResult(name="google_dorks")
        records, by_category = osint_inproc.generate_google_dorks(self.ctx.target.registrable)
        res.osint = records
        # The readable dork list is written by the per-source flush to osint/google_dorks.txt
        # (rendered by the report generator) — no separate file here, to avoid a double write to
        # the same path. Keep a grouped raw payload so tool_output/google_dorks.raw.txt is useful.
        raw_lines: list[str] = []
        total = 0
        for category, urls in by_category.items():
            raw_lines.append(f"### {category}")
            raw_lines.extend(urls)
            raw_lines.append("")
            total += len(urls)
        res.raw = "\n".join(raw_lines)
        res.note = f"{total} dork URLs across {len(by_category)} categories"
        return res

    # -- Shodan-backed sources (key-gated; passive — query Shodan's cache, never the target) --

    async def _resolved_ips(self) -> list[str]:
        """The target apex's resolved IP(s), memoised across Shodan sources so we resolve once.

        Uses the same keyless DoH resolver as ip_info; the Shodan sources consume the result to
        build a ``known_ips`` set (so infrastructure with no DNS trail can be flagged) and to
        drive the per-IP lookups."""
        cached = self.ctx.get_shared("resolved_ips")
        if cached is not None:
            return cached
        ips = await osint_inproc.resolve_ips(self.ctx.target.registrable)
        self.ctx.set_shared("resolved_ips", ips)
        return ips

    def _shodan_client(self, http: httpx.AsyncClient) -> "shodan_inproc.ShodanClient":
        return shodan_inproc.ShodanClient(self.ctx.secrets.shodan_api_key, http)

    async def _src_shodan_org(self) -> SourceResult:
        res = SourceResult(name="shodan_org", raw_ext="txt")
        if not self.ctx.secrets.has_shodan:
            diag = self.ctx.secrets.diagnose_key("SHODAN_API_KEY")
            res.skipped, res.note = True, "skipped: SHODAN_API_KEY not set"
            res.raw = f"# skipped: SHODAN_API_KEY not set\n# {diag}"
            self.log.info("shodan skip — %s", diag)
            return res
        slugs = osint_inproc._company_slugs(self.ctx.target)
        known = set(await self._resolved_ips())
        async with httpx.AsyncClient() as http:
            try:
                records, findings, raw = await shodan_inproc.org_asn_search(
                    self._shodan_client(http), slugs, known)
            except shodan_inproc.ShodanTierError as exc:
                res.skipped, res.note = True, f"skipped: {exc.reason}"
                res.raw = f"# skipped: {exc.reason}"
                return res
        res.osint, res.findings, res.raw = records, findings, raw
        res.note = f"{len(records)} host(s), {len(findings)} with no DNS trail"
        return res

    async def _src_shodan_favicon(self) -> SourceResult:
        res = SourceResult(name="shodan_favicon", raw_ext="txt")
        if not self.ctx.secrets.has_shodan:
            diag = self.ctx.secrets.diagnose_key("SHODAN_API_KEY")
            res.skipped, res.note = True, "skipped: SHODAN_API_KEY not set"
            res.raw = f"# skipped: SHODAN_API_KEY not set\n# {diag}"
            self.log.info("shodan skip — %s", diag)
            return res
        apex = self.ctx.target.registrable
        live_hosts = [f"https://{apex}", f"https://www.{apex}"]
        known = set(await self._resolved_ips())
        async with httpx.AsyncClient(
            headers={"user-agent": "Mozilla/5.0 (Kaalyx OSINT)"}, follow_redirects=True,
        ) as http:
            try:
                records, findings, raw = await shodan_inproc.favicon_search(
                    self._shodan_client(http), http, live_hosts, known)
            except shodan_inproc.ShodanTierError as exc:
                res.skipped, res.note = True, f"skipped: {exc.reason}"
                res.raw = f"# skipped: {exc.reason}"
                return res
        res.osint, res.findings, res.raw = records, findings, raw
        if not records:
            res.note = "no favicon found on apex/www"
        else:
            res.note = f"{len(records)} favicon match record(s), {len(findings)} related host(s)"
        return res

    async def _src_shodan_vulns(self) -> SourceResult:
        return await self._shodan_host_lookup(
            "shodan_vulns", want_vulns=True, want_deep=False, history=False)

    async def _src_shodan_host(self) -> SourceResult:
        return await self._shodan_host_lookup(
            "shodan_host", want_vulns=False, want_deep=True, history=True)

    async def _shodan_host_lookup(
        self, name: str, want_vulns: bool, want_deep: bool, history: bool,
    ) -> SourceResult:
        """Shared driver for the two per-IP capabilities (CVE tags / deep lookup). Both read
        ``/shodan/host/<ip>``; they're separate sources so each can be toggled independently,
        but each resolves the same memoised IP set."""
        res = SourceResult(name=name, raw_ext="txt")
        if not self.ctx.secrets.has_shodan:
            diag = self.ctx.secrets.diagnose_key("SHODAN_API_KEY")
            res.skipped, res.note = True, "skipped: SHODAN_API_KEY not set"
            res.raw = f"# skipped: SHODAN_API_KEY not set\n# {diag}"
            self.log.info("shodan skip — %s", diag)
            return res
        ips = await self._resolved_ips()
        if not ips:
            res.skipped, res.note = True, "skipped: no resolvable IP to look up"
            res.raw = "# skipped: no resolvable IP"
            return res
        async with httpx.AsyncClient() as http:
            try:
                records, findings, raw, summary = await shodan_inproc.host_deep_lookup(
                    self._shodan_client(http), ips, history=history,
                    want_vulns=want_vulns, want_deep=want_deep)
            except shodan_inproc.ShodanTierError as exc:
                res.skipped, res.note = True, f"skipped: {exc.reason}"
                res.raw = f"# skipped: {exc.reason}"
                return res
        res.osint, res.findings, res.raw = records, findings, raw
        # Build an accurate, non-misleading note. All-CDN or all-not-indexed is an EXPECTED
        # outcome (the apex is fronted by a CDN, or Shodan simply hasn't scanned the origin),
        # not a failure — say which, rather than echoing the raw API "no information" text.
        cdn_ips, not_indexed = summary["cdn_ips"], summary["not_indexed"]
        if summary["indexed"] == 0 and cdn_ips and not not_indexed:
            providers = ", ".join(sorted(set(cdn_ips.values())))
            res.note = f"{len(ips)} IP(s) all behind {providers} CDN — no origin host to index"
        elif summary["indexed"] == 0 and not_indexed:
            res.note = (f"{len(ips)} IP(s), none indexed by Shodan"
                        + (f" ({len(cdn_ips)} are CDN edge)" if cdn_ips else ""))
        else:
            note = f"{len(ips)} IP(s), {summary['indexed']} indexed, {len(findings)} finding(s)"
            if cdn_ips:
                note += f", {len(cdn_ips)} CDN edge"
            res.note = note
        return res
