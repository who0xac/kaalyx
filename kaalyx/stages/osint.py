"""Part 1 — OSINT stage.

Runs a fan-out of independent OSINT sources concurrently,
persisting everything to both SQLite and raw files, and rendering a live rich UI. Each
source is isolated: a missing tool, a missing API key, a disabled toggle, or a source that
errors is logged and skipped — it never affects the other sources or the scan.

Design synthesised from BBOT, reNgine and ReconFTW:

* **BBOT** — fine-grained one-source-per-check structure, typed findings/emails, keyless
  email harvesting (email-format/skymem), extended DNS security records, the current
  keyless Azure tenant method (ODC federationprovider), and the "``if not r: return``"
  graceful-skip discipline.
* **reNgine** — theHarvester emails/employees/hosts extraction, the email→breach chaining
  (harvested emails feed the breach lookup), and the categorised Google-dork taxonomy.
* **ReconFTW** — a per-source enable/disable toggle for every sub-check, passing secrets
  via environment (not argv) so tokens don't leak into the process list, and tool-present
  checks with clear skip messages.

Sources:
    external tools (skip if not on PATH):  whois, dnsx, github-subdomains, trufflehog,
        cloud_enum, s3scanner, badsecrets, retire.js, theHarvester, misconfig-mapper.
    in-process keyless:  mail/DNS security posture, M365 tenant mapping, email harvesting,
        Google-dork generation.
    key-dependent (skip cleanly if no key):  breach lookup (h8mail), and the key-gated
        tools above (github-subdomains, trufflehog).
"""

from __future__ import annotations

from ..core.stage import Stage, StageResult
from ..data.models import Confidence, Email, Finding, OsintRecord, Severity
from ..monitor.flags import flag_all
from ..ui import osint_ui
from . import osint_inproc
from ..parsers import osint_parsers as P
from .sources import SourceResult, run_sources

# Human-readable labels for the live progress board, keyed by source name.
SOURCE_LABELS: dict[str, str] = {
    "whois": "WHOIS",
    "dns": "DNS records (dnsx)",
    "mail_dns": "Mail/DNS security",
    "m365": "M365 tenant map",
    "email_harvest": "Email harvest",
    "breach_lookup": "Breach lookup",
    "github_subdomains": "GitHub subdomains",
    "trufflehog": "TruffleHog (org)",
    "cloud_enum": "Cloud enum",
    "s3scanner": "S3 scanner",
    "badsecrets": "badsecrets",
    "retirejs": "retire.js",
    "theharvester": "theHarvester",
    "third_party_misconfig": "3rd-party misconfig",
    "api_leaks": "API leaks (Postman/Swagger)",
    "exposed_git": "Exposed .git",
    "github_actions": "GitHub Actions audit",
    "google_dorks": "Google dorks",
}


class OsintStage(Stage):
    name = "osint"

    async def run(self) -> StageResult:
        ctx = self.ctx
        osint_cfg = ctx.config.osint

        # Map each source name to (enabled?, coroutine). Disabled ones are dropped before
        # running; the toggle comes from config (a --no-<source> CLI flag overrides config
        # by mutating ctx.config.osint before the stage runs).
        candidates = {
            "whois": (osint_cfg.whois, self._src_whois),
            "dns": (osint_cfg.dns, self._src_dnsx),
            "mail_dns": (osint_cfg.mail_dns, self._src_mail_dns),
            "m365": (osint_cfg.m365, self._src_m365),
            "email_harvest": (osint_cfg.email_harvest, self._src_email_harvest),
            "github_subdomains": (osint_cfg.github_subdomains, self._src_github_subdomains),
            "trufflehog": (osint_cfg.trufflehog, self._src_trufflehog),
            "cloud_enum": (osint_cfg.cloud_enum, self._src_cloud_enum),
            "s3scanner": (osint_cfg.s3scanner, self._src_s3scanner),
            "badsecrets": (osint_cfg.badsecrets, self._src_badsecrets),
            "retirejs": (osint_cfg.retirejs, self._src_retirejs),
            "theharvester": (osint_cfg.theharvester, self._src_theharvester),
            "third_party_misconfig": (osint_cfg.third_party_misconfig, self._src_misconfig),
            "api_leaks": (osint_cfg.api_leaks, self._src_api_leaks),
            "exposed_git": (osint_cfg.exposed_git, self._src_exposed_git),
            "github_actions": (osint_cfg.github_actions, self._src_github_actions),
            "google_dorks": (osint_cfg.google_dorks, self._src_google_dorks),
        }
        sources = {name: fn for name, (enabled, fn) in candidates.items() if enabled}
        disabled = [name for name, (enabled, _) in candidates.items() if not enabled]

        osint_ui.print_banner(ctx.domain, len(sources))
        if disabled:
            self.log.info("OSINT sources disabled by config/flags: %s", ", ".join(disabled))

        # Live progress board that updates in place as sources start/finish. Silence the
        # console log handler while the board owns the screen so the two don't interleave
        # (the file log keeps capturing everything).
        from ..core.logging import set_console_logging

        labels = {name: SOURCE_LABELS.get(name, name) for name in sources}
        progress = osint_ui.OsintProgress(labels)
        set_console_logging(False)
        try:
            with progress.live():
                results = await run_sources(sources, progress.hook)
        finally:
            set_console_logging(True)

        # Breach lookup runs AFTER harvesting so it can enrich the emails we found
        # (reNgine's h8mail chaining). It's a post-step, not a concurrent source.
        if ctx.config.osint.breach_lookup:
            await self._enrich_breaches(results)

        return self._persist(results)

    # -- persistence + rendering -------------------------------------------------------

    def _persist(self, results: list[SourceResult]) -> StageResult:
        ctx = self.ctx
        keywords = ctx.config.flagging.interesting_keywords

        all_subs = [s for r in results for s in r.subdomains]
        all_osint = [o for r in results for o in r.osint]
        all_findings = [f for r in results for f in r.findings]
        all_emails = [e for r in results for e in r.emails]
        all_employees = [e for r in results for e in r.employees]

        flag_all(all_subs, keywords)

        if all_subs:
            ctx.repo.bulk_upsert_subdomains(ctx.scan_id, all_subs)
            ctx.writer.write_lines(self.name, "subdomains.txt", [s.hostname for s in all_subs])
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

        self._write_osint_files(all_osint)
        if all_findings:
            ctx.writer.write_lines(
                self.name, "findings.txt",
                [f"[{f.severity.value}] {f.category}: {f.title} ({f.target})"
                 for f in all_findings],
                sort=False,
            )
        self._write_status_file(results)

        # Render result tables + summary panel (read back from DB so dedup/merge is reflected).
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

    def _render_results(self, results: list[SourceResult]) -> None:
        ctx = self.ctx
        console = osint_ui.get_console()

        email_rows = ctx.repo.list_emails(ctx.scan_id)
        emp_rows = ctx.repo.list_employees(ctx.scan_id)
        osint_rows = ctx.repo.list_osint(ctx.scan_id)
        finding_rows = ctx.repo.list_findings(ctx.scan_id)

        for table in (
            osint_ui.mail_hygiene_table(osint_rows),
            osint_ui.emails_table(email_rows),
            osint_ui.employees_table(emp_rows),
            osint_ui.findings_table(finding_rows),
        ):
            if table is not None:
                console.print(table)

        counts = ctx.repo.scan_counts(ctx.scan_id)
        sev_counts = {
            sev: counts.get(f"sev_{sev}", 0)
            for sev in ("critical", "high", "medium", "low", "info")
        }
        source_states = [
            (r.name, "failed" if not r.ok else ("skipped" if (r.skipped or (r.total == 0 and r.note.lower().startswith("skipped"))) else "done"),
             r.total, r.note)
            for r in results
        ]
        duration = sum(r.duration_s for r in results)
        console.print(osint_ui.summary_panel(
            ctx.domain, counts, sev_counts, source_states, duration
        ))

    def _write_osint_files(self, records: list[OsintRecord]) -> None:
        by_kind: dict[str, list[str]] = {}
        for rec in records:
            if rec.kind == "google_dork":
                continue  # dorks get their own grouped file
            line = f"{rec.value}" + (f"  [{rec.detail}]" if rec.detail else "")
            by_kind.setdefault(rec.kind, []).append(line)
        for kind, lines in by_kind.items():
            self.ctx.writer.write_lines(self.name, f"{kind}.txt", lines)

    def _write_status_file(self, results: list[SourceResult]) -> None:
        lines = []
        for r in sorted(results, key=lambda x: x.name):
            state = "ok" if r.ok else "FAILED"
            note = f" — {r.note}" if r.note else (f" — {r.error}" if r.error else "")
            lines.append(f"{r.name:22} {state:7} items={r.total}{note}")
        self.ctx.writer.write_lines(self.name, "_sources_status.txt", lines, sort=False)

    # -- breach enrichment (post-harvest chaining) -------------------------------------

    async def _enrich_breaches(self, results: list[SourceResult]) -> None:
        """Enrich harvested emails with breach data via h8mail (reNgine chaining pattern).

        h8mail needs API keys/config to return meaningful data; without it we skip cleanly.
        The harvested emails are the input, so this only runs if we actually found emails
        and h8mail is on PATH.
        """
        emails = [e for r in results for e in r.emails]
        if not emails:
            return
        if not self.ctx.runner.tool_available("h8mail"):
            self.log.info("breach lookup skipped — h8mail not on PATH (emails kept)")
            return

        # Feed emails via stdin file to avoid a huge argv.
        email_list = "\n".join(sorted({e.address for e in emails}))
        stage_dir = self.ctx.writer.stage_dir(self.name)
        infile = stage_dir / "_h8mail_targets.txt"
        outfile = stage_dir / "_h8mail_out.json"
        try:
            infile.write_text(email_list, encoding="utf-8")
        except OSError:
            return

        out = await self.ctx.runner.run(
            ["h8mail", "-t", str(infile), "--json", str(outfile), "-q", "quiet"],
            timeout=600, label="h8mail",
        )
        if not out.started:
            self.log.info("breach lookup skipped — h8mail not runnable (emails kept)")
            return
        # h8mail writes JSON to outfile; read it back.
        try:
            data = outfile.read_text(encoding="utf-8")
        except OSError:
            data = out.stdout
        breach_map = P.parse_h8mail(data)
        if not breach_map:
            self.log.info("breach lookup: no breach data (likely no API keys configured)")
            return

        enriched: list[Email] = []
        findings: list[Finding] = []
        for e in emails:
            count, detail = breach_map.get(e.address.lower(), (0, ""))
            if count > 0:
                enriched.append(Email(address=e.address, source="h8mail",
                                      breached=True, breach_count=count, breach_detail=detail))
                findings.append(Finding(
                    title=f"Breached credential: {e.address}",
                    category="credential-leak",
                    severity=self._breach_severity(count),
                    tool="h8mail",
                    target=e.address,
                    description=f"Appears in {count} known breach(es): {detail}",
                    evidence=detail,
                ))
        if enriched:
            # Attach to a synthetic result so _persist stores them.
            results.append(SourceResult(
                name="breach_lookup", ok=True, emails=enriched, findings=findings,
                note=f"{len(enriched)} breached",
            ))
            self.log.warning("breach lookup: %d breached email(s) found", len(enriched))

    @staticmethod
    def _breach_severity(count: int) -> Severity:
        return Severity.HIGH if count >= 3 else Severity.MEDIUM

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
            self.ctx.writer.raw_tool_output(self.name, "whois", text)
            for line in text.splitlines():
                low = line.lower().strip()
                for key in ("registrar:", "creation date:", "registrant", "name server:",
                            "registry expiry", "org:"):
                    if low.startswith(key):
                        res.osint.append(OsintRecord(kind="whois", value=line.strip(),
                                                     source="whois"))
                        break
        return res

    async def _src_dnsx(self) -> SourceResult:
        res = SourceResult(name="dnsx")
        cmd = ["dnsx", "-json", "-silent", "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-soa"]
        out = await self.ctx.runner.run(cmd, stdin=self.ctx.target.registrable + "\n",
                                        timeout=120, label="dnsx")
        if not out.started:
            res.skipped, res.note = True, "skipped: dnsx not on PATH"
            return res
        self.ctx.writer.raw_tool_output(self.name, "dnsx", out.stdout)
        res.osint = P.parse_dnsx(out.stdout)
        return res

    async def _src_github_subdomains(self) -> SourceResult:
        res = SourceResult(name="github_subdomains")
        if not self.ctx.secrets.has_github:
            res.skipped, res.note = True, "skipped: GITHUB_TOKEN not set"
            return res
        # Pass the token via env, not argv, so it never appears in the process list.
        cmd = ["github-subdomains", "-d", self.ctx.target.registrable]
        out = await self.ctx.runner.run(
            cmd, env={"GITHUB_TOKEN": self.ctx.secrets.github_token or ""},
            timeout=300, label="github-subdomains",
        )
        if not out.started:
            res.skipped, res.note = True, "skipped: github-subdomains not on PATH"
            return res
        res.subdomains = P.parse_subdomain_lines(out.stdout, "github-subdomains")
        return res

    async def _src_trufflehog(self) -> SourceResult:
        res = SourceResult(name="trufflehog")
        if not self.ctx.secrets.has_github:
            res.skipped, res.note = True, "skipped: GITHUB_TOKEN not set (org scan)"
            return res
        org = self.ctx.target.registrable.split(".")[0]
        cmd = ["trufflehog", "github", "--org", org, "--json"]
        out = await self.ctx.runner.run(
            cmd, env={"GITHUB_TOKEN": self.ctx.secrets.github_token or ""},
            timeout=1800, label="trufflehog",
        )
        if not out.started:
            res.skipped, res.note = True, "skipped: trufflehog not on PATH"
            return res
        self.ctx.writer.raw_tool_output(self.name, "trufflehog", out.stdout)
        res.findings = P.parse_trufflehog(out.stdout)
        res.note = f"org={org}"
        return res

    async def _src_cloud_enum(self) -> SourceResult:
        res = SourceResult(name="cloud_enum")
        keyword = self.ctx.target.registrable.split(".")[0]
        out = await self.ctx.runner.run(["cloud_enum", "-k", keyword, "--quickscan"],
                                        timeout=900, label="cloud_enum")
        if not out.started:
            res.skipped, res.note = True, "skipped: cloud_enum not on PATH"
            return res
        self.ctx.writer.raw_tool_output(self.name, "cloud_enum", out.stdout)
        res.findings = P.parse_cloud_enum(out.stdout)
        return res

    async def _src_s3scanner(self) -> SourceResult:
        res = SourceResult(name="s3scanner")
        keyword = self.ctx.target.registrable.split(".")[0]
        out = await self.ctx.runner.run(["s3scanner", "-bucket", keyword],
                                        timeout=300, label="s3scanner")
        if not out.started:
            res.skipped, res.note = True, "skipped: s3scanner not on PATH"
            return res
        self.ctx.writer.raw_tool_output(self.name, "s3scanner", out.stdout)
        res.findings = P.parse_s3scanner(out.stdout)
        return res

    async def _src_badsecrets(self) -> SourceResult:
        res = SourceResult(name="badsecrets")
        out = await self.ctx.runner.run(["badsecrets", "-u", f"https://{self.ctx.domain}"],
                                        timeout=180, label="badsecrets")
        if not out.started:
            res.skipped, res.note = True, "skipped: badsecrets not on PATH"
            return res
        self.ctx.writer.raw_tool_output(self.name, "badsecrets", out.stdout)
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
        self.ctx.writer.raw_tool_output(self.name, "retirejs", out.stdout)
        res.findings = P.parse_retirejs(out.stdout)
        return res

    async def _src_theharvester(self) -> SourceResult:
        res = SourceResult(name="theharvester")
        stage_dir = self.ctx.writer.stage_dir(self.name)
        out_base = stage_dir / "_theharvester"
        cmd = ["theHarvester", "-d", self.ctx.target.registrable, "-b", "all",
               "-f", str(out_base)]
        out = await self.ctx.runner.run(cmd, timeout=900, label="theHarvester")
        if not out.started:
            res.skipped, res.note = True, "skipped: theHarvester not on PATH"
            return res
        # theHarvester writes <base>.json (and .xml). Read the JSON.
        data = ""
        for candidate in (out_base.with_suffix(".json"),
                          stage_dir / "_theharvester.json"):
            try:
                data = candidate.read_text(encoding="utf-8")
                break
            except OSError:
                continue
        if not data:
            data = out.stdout  # fallback
        emails, employees, subs = P.parse_theharvester(data, self.ctx.target.registrable)
        res.emails, res.employees, res.subdomains = emails, employees, subs
        return res

    async def _src_misconfig(self) -> SourceResult:
        res = SourceResult(name="third_party_misconfig")
        cmd = ["misconfig-mapper", "-target", self.ctx.target.registrable,
               "-as-domain", "-service", "*"]
        out = await self.ctx.runner.run(cmd, timeout=600, label="misconfig-mapper")
        if not out.started:
            res.skipped, res.note = True, "skipped: misconfig-mapper not on PATH"
            return res
        self.ctx.writer.raw_tool_output(self.name, "misconfig-mapper", out.stdout)
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

        pp = await self.ctx.runner.run(
            ["porch-pirate", "-s", keyword, "-l", "25"], timeout=600, label="porch-pirate",
        )
        if pp.started:
            ran_any = True
            self.ctx.writer.raw_tool_output(self.name, "porch-pirate", pp.stdout)
            res.findings.extend(P.parse_porch_pirate(pp.stdout))

        ss = await self.ctx.runner.run(
            ["swaggerspy", keyword], timeout=600, label="swaggerspy",
        )
        if ss.started:
            ran_any = True
            self.ctx.writer.raw_tool_output(self.name, "swaggerspy", ss.stdout)
            res.findings.extend(P.parse_swaggerspy(ss.stdout))

        if not ran_any:
            res.skipped = True
            res.note = "skipped: porch-pirate & swaggerspy not on PATH"
        return res

    async def _src_exposed_git(self) -> SourceResult:
        """Detect a publicly exposed ``/.git/`` directory (in-process, detect-only).

        Uses BBOT git.py's reliable check (GET /.git/config → 200 + '[core]' + not HTML) via
        `osint_inproc.check_exposed_git`. No download/reconstruction. Probes the apex host and
        its ``www.`` (broader per-host probing across all discovered subdomains belongs to the
        Hosts/Web stages). Keyless — never skips for a missing tool.
        """
        res = SourceResult(name="exposed_git")
        candidates = {self.ctx.domain}
        if self.ctx.target.is_apex:
            candidates.add(f"www.{self.ctx.domain}")
        for host in sorted(candidates):
            finding = await osint_inproc.check_exposed_git(host)
            if finding is not None:
                res.findings.append(finding)
        if not res.findings:
            res.note = "no exposed .git found"
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
        org = self.ctx.target.registrable.split(".")[0]
        json_out = self.ctx.writer.stage_dir(self.name) / "_gato.json"
        out = await self.ctx.runner.run(
            ["gato", "enumerate", "-t", org, "--output-json", str(json_out)],
            env={"GITHUB_TOKEN": self.ctx.secrets.github_token or "",
                 "GH_TOKEN": self.ctx.secrets.github_token or ""},
            timeout=900, label="gato",
        )
        if not out.started:
            res.skipped, res.note = True, "skipped: gato not on PATH"
            return res
        self.ctx.writer.raw_tool_output(self.name, "gato", out.stdout)
        # Prefer the structured JSON file; fall back to parsing stdout text.
        try:
            json_text = json_out.read_text(encoding="utf-8")
        except OSError:
            json_text = ""
        res.findings = P.parse_gato(json_text or out.stdout)
        if res.findings:
            res.note = f"org={org}"
        else:
            # Ran cleanly but found nothing — most often a token-scope limitation.
            res.note = f"org={org}: no findings (token may lack repo/admin:org scope)"
        return res

    # -- in-process sources ------------------------------------------------------------

    async def _src_mail_dns(self) -> SourceResult:
        res = SourceResult(name="mail_dns")
        domain = self.ctx.target.registrable
        records, findings = await osint_inproc.check_mail_dns_security(domain)
        res.osint, res.findings = records, findings

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

    async def _src_m365(self) -> SourceResult:
        res = SourceResult(name="m365")
        records, findings = await osint_inproc.map_m365_tenant(self.ctx.target.registrable)
        res.osint, res.findings = records, findings
        if not records:
            res.note = "no Microsoft tenant detected"
        return res

    async def _src_email_harvest(self) -> SourceResult:
        res = SourceResult(name="email_harvest")
        res.emails = await osint_inproc.harvest_emails(self.ctx.target.registrable)
        if not res.emails:
            res.note = "no public emails found"
        return res

    async def _src_google_dorks(self) -> SourceResult:
        res = SourceResult(name="google_dorks")
        records, by_category = osint_inproc.generate_google_dorks(self.ctx.target.registrable)
        res.osint = records
        # Write dorks grouped by category into one readable file for manual review.
        lines: list[str] = []
        total = 0
        for category, urls in by_category.items():
            lines.append(f"### {category}")
            lines.extend(urls)
            lines.append("")
            total += len(urls)
        self.ctx.writer.write_lines(self.name, "google_dorks.txt", lines, sort=False)
        res.note = f"{total} dork URLs across {len(by_category)} categories"
        return res
