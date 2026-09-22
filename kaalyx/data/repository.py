"""Repository — the only module that reads/writes the SQLite database.

Stages and the web layer go through this class rather than touching SQL directly, which
keeps the schema in one place and lets us centralise two pieces of non-trivial logic:

* **Finding de-duplication.** The pipeline runs 2+ tools per vulnerability category by
  design, so the *same* logical issue arrives multiple times. :meth:`upsert_finding`
  merges by :attr:`Finding.dedup_key`, unioning the contributing tools and keeping the
  strongest severity/confidence seen.
* **Continuous-monitoring diffs.** :meth:`previous_scan_id` +
  :meth:`new_subdomains_since` / :meth:`new_findings_since` answer "what's new since the
  last run for this domain".

The connection is created once per scan by :func:`kaalyx.data.db.connect` and injected.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from ..core.logging import get_logger
from .models import (
    Confidence,
    Email,
    Employee,
    Finding,
    Host,
    OsintRecord,
    Severity,
    Subdomain,
    WebURL,
)

logger = get_logger("repository")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _csv(values: list) -> str:
    return ",".join(str(v) for v in values)


def _uncsv(value: str | None) -> list[str]:
    return [v for v in (value or "").split(",") if v]


def _finding_location(finding: Finding) -> tuple[str, str, int | None, str]:
    """Break a finding's location + value out of its packed ``evidence`` into discrete
    (location, file_path, line_no, secret_value) — the queryable columns the web dashboard needs.

    Secret-scan findings pack ``"repo | file:line | value"`` into ``evidence`` (a compact,
    one-line shape). This splits it back into real fields so the dashboard can filter/sort/search
    on them instead of parsing a text blob. Falls back to the finding's own ``target`` for the
    location and to the whole ``evidence`` for the value when the packed shape isn't present, so
    a non-secret finding still records a sensible location/value. The value is stored IN FULL
    (never masked) — the same rule as the text output.
    """
    parts = [p.strip() for p in (finding.evidence or "").split(" | ")]
    location, file_path, line_no, value = "", "", None, ""
    if len(parts) >= 2:
        value = parts[-1]
        loc = parts[-2]
        if len(parts) >= 3:
            location = parts[0]
        if loc:
            if ":" in loc and loc.rsplit(":", 1)[1].isdigit():
                file_path, ln = loc.rsplit(":", 1)
                line_no = int(ln)
            else:
                file_path = loc
    else:
        value = (finding.evidence or "").strip()
    if not location:
        # target often carries "repo:line" or a host — take the repo/host part as the location.
        tgt = (finding.target or "").strip()
        if tgt:
            if ":" in tgt and tgt.rsplit(":", 1)[1].isdigit():
                location, tln = tgt.rsplit(":", 1)
                if line_no is None:
                    line_no = int(tln)
            else:
                location = tgt
    return location, file_path, line_no, value


class Repository:
    """Persistence gateway over a single SQLite connection."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    # -- scans -------------------------------------------------------------------------

    def create_scan(
        self,
        domain: str,
        registrable: str,
        target_type: str,
        options: dict | None = None,
    ) -> int:
        """Insert a new scan row and return its id."""
        cur = self.conn.execute(
            """INSERT INTO scans (domain, registrable, target_type, started_at, status,
                                  options_json)
               VALUES (?, ?, ?, ?, 'running', ?)""",
            (domain, registrable, target_type, _now(), json.dumps(options or {})),
        )
        self.conn.commit()
        scan_id = int(cur.lastrowid)
        logger.debug("Created scan #%d for %s", scan_id, domain)
        return scan_id

    def finish_scan(self, scan_id: int, status: str) -> None:
        """Mark a scan finished with a terminal *status* (completed|failed|aborted)."""
        self.conn.execute(
            "UPDATE scans SET status = ?, finished_at = ? WHERE id = ?",
            (status, _now(), scan_id),
        )
        self.conn.commit()

    def get_scan(self, scan_id: int) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()

    def list_scans(self, limit: int = 100) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()

    def previous_scan_id(self, domain: str, before_scan_id: int) -> int | None:
        """Most recent completed scan for *domain* strictly before *before_scan_id*.

        This is the baseline against which "what's new" diffs are computed.
        """
        row = self.conn.execute(
            """SELECT id FROM scans
               WHERE domain = ? AND id < ? AND status IN ('completed', 'failed')
               ORDER BY id DESC LIMIT 1""",
            (domain, before_scan_id),
        ).fetchone()
        return int(row["id"]) if row else None

    # -- stage runs --------------------------------------------------------------------

    def start_stage(self, scan_id: int, stage: str) -> None:
        self.conn.execute(
            """INSERT INTO stage_runs (scan_id, stage, status, started_at)
               VALUES (?, ?, 'running', ?)
               ON CONFLICT(scan_id, stage)
               DO UPDATE SET status='running', started_at=excluded.started_at,
                             finished_at=NULL, detail=''""",
            (scan_id, stage, _now()),
        )
        self.conn.commit()

    def finish_stage(
        self, scan_id: int, stage: str, status: str, detail: str = ""
    ) -> None:
        self.conn.execute(
            """UPDATE stage_runs SET status = ?, finished_at = ?, detail = ?
               WHERE scan_id = ? AND stage = ?""",
            (status, _now(), detail[:2000], scan_id, stage),
        )
        self.conn.commit()

    def stage_status(self, scan_id: int, stage: str) -> str | None:
        row = self.conn.execute(
            "SELECT status FROM stage_runs WHERE scan_id = ? AND stage = ?",
            (scan_id, stage),
        ).fetchone()
        return row["status"] if row else None

    def list_stage_runs(self, scan_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM stage_runs WHERE scan_id = ? ORDER BY id", (scan_id,)
        ).fetchall()

    # -- subdomains --------------------------------------------------------------------

    def upsert_subdomain(self, scan_id: int, sd: Subdomain) -> None:
        """Insert a subdomain, or merge sources/IPs if the hostname is already present."""
        existing = self.conn.execute(
            "SELECT source, ip_addresses FROM subdomains WHERE scan_id = ? AND hostname = ?",
            (scan_id, sd.hostname),
        ).fetchone()
        if existing is None:
            self.conn.execute(
                """INSERT INTO subdomains (scan_id, hostname, source, resolved,
                       ip_addresses, interesting, interesting_reason, discovered_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id, sd.hostname, sd.source, int(sd.resolved),
                    _csv(sd.ip_addresses), int(sd.interesting), sd.interesting_reason,
                    sd.discovered_at,
                ),
            )
        else:
            sources = set(_uncsv(existing["source"])) | {sd.source} if sd.source else set(_uncsv(existing["source"]))
            ips = set(_uncsv(existing["ip_addresses"])) | set(sd.ip_addresses)
            self.conn.execute(
                """UPDATE subdomains
                   SET source = ?, ip_addresses = ?,
                       resolved = MAX(resolved, ?),
                       interesting = MAX(interesting, ?),
                       interesting_reason = COALESCE(interesting_reason, ?)
                   WHERE scan_id = ? AND hostname = ?""",
                (
                    _csv(sorted(sources)), _csv(sorted(ips)), int(sd.resolved),
                    int(sd.interesting), sd.interesting_reason, scan_id, sd.hostname,
                ),
            )

    def bulk_upsert_subdomains(self, scan_id: int, subs: list[Subdomain]) -> None:
        for sd in subs:
            self.upsert_subdomain(scan_id, sd)
        self.conn.commit()

    def list_subdomains(self, scan_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM subdomains WHERE scan_id = ? ORDER BY hostname", (scan_id,)
        ).fetchall()

    # -- hosts -------------------------------------------------------------------------

    def upsert_host(self, scan_id: int, host: Host) -> None:
        self.conn.execute(
            """INSERT INTO hosts (scan_id, ip, hostname, open_ports, is_cdn, cdn_name,
                   waf, geo, technologies, source, discovered_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(scan_id, ip) DO UPDATE SET
                   hostname     = COALESCE(excluded.hostname, hosts.hostname),
                   open_ports   = excluded.open_ports,
                   is_cdn       = MAX(hosts.is_cdn, excluded.is_cdn),
                   cdn_name     = COALESCE(excluded.cdn_name, hosts.cdn_name),
                   waf          = COALESCE(excluded.waf, hosts.waf),
                   geo          = COALESCE(excluded.geo, hosts.geo),
                   technologies = excluded.technologies""",
            (
                scan_id, host.ip, host.hostname, _csv(host.open_ports), int(host.is_cdn),
                host.cdn_name, host.waf, host.geo, _csv(host.technologies), host.source,
                host.discovered_at,
            ),
        )
        self.conn.commit()

    def list_hosts(self, scan_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM hosts WHERE scan_id = ? ORDER BY ip", (scan_id,)
        ).fetchall()

    # -- web urls ----------------------------------------------------------------------

    def bulk_upsert_urls(self, scan_id: int, urls: list[WebURL]) -> None:
        for u in urls:
            self.conn.execute(
                """INSERT INTO web_urls (scan_id, url, source, status_code, gf_patterns,
                       screenshot_path, discovered_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(scan_id, url) DO UPDATE SET
                       gf_patterns     = excluded.gf_patterns,
                       status_code     = COALESCE(excluded.status_code, web_urls.status_code),
                       screenshot_path = COALESCE(excluded.screenshot_path, web_urls.screenshot_path)""",
                (
                    scan_id, u.url, u.source, u.status_code, _csv(u.gf_patterns),
                    u.screenshot_path, u.discovered_at,
                ),
            )
        self.conn.commit()

    def list_urls(self, scan_id: int, limit: int = 5000) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM web_urls WHERE scan_id = ? ORDER BY url LIMIT ?",
            (scan_id, limit),
        ).fetchall()

    # -- findings ----------------------------------------------------------------------

    def upsert_finding(self, scan_id: int, finding: Finding) -> tuple[int, bool]:
        """Insert or merge a finding by its dedup key.

        Returns ``(finding_id, is_new)``. On merge, the contributing tool is unioned into
        ``tools`` and the strongest severity/confidence is kept — so the "2+ tools per
        category" design surfaces as one consolidated, higher-confidence row.
        """
        row = self.conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? AND dedup_key = ?",
            (scan_id, finding.dedup_key),
        ).fetchone()

        location, file_path, line_no, secret_value = _finding_location(finding)
        verified = 1 if finding.confidence == Confidence.CONFIRMED else 0

        if row is None:
            cur = self.conn.execute(
                """INSERT INTO findings (scan_id, dedup_key, title, category, severity,
                       confidence, target, tools, description, evidence, reference, raw,
                       location, file_path, line_no, secret_value, verified, discovered_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id, finding.dedup_key, finding.title, finding.category,
                    finding.severity.value, finding.confidence.value, finding.target,
                    finding.tool, finding.description, finding.evidence,
                    finding.reference, finding.raw,
                    location, file_path, line_no, secret_value, verified,
                    finding.discovered_at,
                ),
            )
            self.conn.commit()
            return int(cur.lastrowid), True

        # Merge into the existing row.
        tools = set(_uncsv(row["tools"]))
        if finding.tool:
            tools.add(finding.tool)
        best_sev = max(
            Severity.coerce(row["severity"]), finding.severity, key=lambda s: s.rank
        )
        best_conf = self._stronger_confidence(
            Confidence(row["confidence"]) if row["confidence"] else Confidence.UNKNOWN,
            finding.confidence,
        )
        best_verified = 1 if best_conf == Confidence.CONFIRMED else int(row["verified"] or 0)
        self.conn.execute(
            """UPDATE findings SET tools = ?, severity = ?, confidence = ?, verified = ?,
                   evidence = CASE WHEN evidence = '' THEN ? ELSE evidence END,
                   reference = CASE WHEN reference = '' THEN ? ELSE reference END,
                   location = CASE WHEN location = '' THEN ? ELSE location END,
                   file_path = CASE WHEN file_path = '' THEN ? ELSE file_path END,
                   line_no = COALESCE(line_no, ?),
                   secret_value = CASE WHEN secret_value = '' THEN ? ELSE secret_value END
               WHERE id = ?""",
            (
                _csv(sorted(tools)), best_sev.value, best_conf.value, best_verified,
                finding.evidence, finding.reference,
                location, file_path, line_no, secret_value, row["id"],
            ),
        )
        self.conn.commit()
        return int(row["id"]), False

    @staticmethod
    def _stronger_confidence(a: Confidence, b: Confidence) -> Confidence:
        order = {
            Confidence.CONFIRMED: 3,
            Confidence.FIRM: 2,
            Confidence.TENTATIVE: 1,
            Confidence.UNKNOWN: 0,
        }
        return a if order[a] >= order[b] else b

    def mark_alerted(self, finding_id: int) -> None:
        self.conn.execute("UPDATE findings SET alerted = 1 WHERE id = ?", (finding_id,))
        self.conn.commit()

    def list_findings(
        self, scan_id: int, min_severity: Severity | None = None
    ) -> list[sqlite3.Row]:
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY discovered_at", (scan_id,)
        ).fetchall()
        if min_severity is None:
            return rows
        return [r for r in rows if Severity.coerce(r["severity"]).rank >= min_severity.rank]

    def unalerted_findings(
        self, scan_id: int, min_severity: Severity
    ) -> list[sqlite3.Row]:
        """Findings at/above *min_severity* that have not yet triggered an alert."""
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? AND alerted = 0", (scan_id,)
        ).fetchall()
        return [r for r in rows if Severity.coerce(r["severity"]).rank >= min_severity.rank]

    # -- osint -------------------------------------------------------------------------

    def bulk_insert_osint(self, scan_id: int, records: list[OsintRecord]) -> None:
        for rec in records:
            self.conn.execute(
                """INSERT INTO osint (scan_id, kind, value, detail, source, discovered_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(scan_id, kind, value) DO UPDATE SET
                       detail = CASE WHEN osint.detail = '' THEN excluded.detail ELSE osint.detail END""",
                (scan_id, rec.kind, rec.value, rec.detail, rec.source, rec.discovered_at),
            )
        self.conn.commit()

    def list_osint(self, scan_id: int, kind: str | None = None) -> list[sqlite3.Row]:
        if kind:
            return self.conn.execute(
                "SELECT * FROM osint WHERE scan_id = ? AND kind = ? ORDER BY value",
                (scan_id, kind),
            ).fetchall()
        return self.conn.execute(
            "SELECT * FROM osint WHERE scan_id = ? ORDER BY kind, value", (scan_id,)
        ).fetchall()

    # -- emails & employees ------------------------------------------------------------

    def upsert_email(self, scan_id: int, email: Email) -> None:
        """Insert an email, or enrich an existing one with breach data (h8mail chaining)."""
        self.conn.execute(
            """INSERT INTO emails (scan_id, address, source, breached, breach_count,
                   breach_detail, discovered_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(scan_id, address) DO UPDATE SET
                   source        = CASE WHEN emails.source = '' THEN excluded.source
                                        WHEN instr(emails.source, excluded.source) > 0 THEN emails.source
                                        ELSE emails.source || ',' || excluded.source END,
                   breached      = MAX(emails.breached, excluded.breached),
                   breach_count  = MAX(emails.breach_count, excluded.breach_count),
                   breach_detail = CASE WHEN excluded.breach_detail = '' THEN emails.breach_detail
                                        ELSE excluded.breach_detail END""",
            (
                scan_id, email.address.lower(), email.source, int(email.breached),
                email.breach_count, email.breach_detail, email.discovered_at,
            ),
        )

    def bulk_upsert_emails(self, scan_id: int, emails: list[Email]) -> None:
        for email in emails:
            self.upsert_email(scan_id, email)
        self.conn.commit()

    def list_emails(self, scan_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM emails WHERE scan_id = ? ORDER BY address", (scan_id,)
        ).fetchall()

    def bulk_upsert_employees(self, scan_id: int, employees: list[Employee]) -> None:
        for emp in employees:
            self.conn.execute(
                """INSERT INTO employees (scan_id, name, source, role, discovered_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(scan_id, name, source) DO UPDATE SET
                       role = CASE WHEN employees.role = '' THEN excluded.role ELSE employees.role END""",
                (scan_id, emp.name, emp.source, emp.role, emp.discovered_at),
            )
        self.conn.commit()

    def list_employees(self, scan_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM employees WHERE scan_id = ? ORDER BY name", (scan_id,)
        ).fetchall()

    # -- monitoring / diff -------------------------------------------------------------

    def new_subdomains_since(self, scan_id: int, baseline_scan_id: int) -> list[str]:
        """Hostnames present in *scan_id* but not in *baseline_scan_id*."""
        rows = self.conn.execute(
            """SELECT hostname FROM subdomains WHERE scan_id = ?
               AND hostname NOT IN (SELECT hostname FROM subdomains WHERE scan_id = ?)
               ORDER BY hostname""",
            (scan_id, baseline_scan_id),
        ).fetchall()
        return [r["hostname"] for r in rows]

    def new_findings_since(
        self, scan_id: int, baseline_scan_id: int
    ) -> list[sqlite3.Row]:
        """Findings (by dedup_key) present in *scan_id* but not in the baseline."""
        return self.conn.execute(
            """SELECT * FROM findings WHERE scan_id = ?
               AND dedup_key NOT IN (SELECT dedup_key FROM findings WHERE scan_id = ?)
               ORDER BY discovered_at""",
            (scan_id, baseline_scan_id),
        ).fetchall()

    # -- summary -----------------------------------------------------------------------

    def scan_counts(self, scan_id: int) -> dict[str, int]:
        """Row counts per table for a scan — powers dashboard tiles and the final summary."""
        def count(table: str) -> int:
            return int(
                self.conn.execute(
                    f"SELECT COUNT(*) AS c FROM {table} WHERE scan_id = ?", (scan_id,)
                ).fetchone()["c"]
            )

        counts = {
            "subdomains": count("subdomains"),
            "hosts": count("hosts"),
            "web_urls": count("web_urls"),
            "findings": count("findings"),
            "osint": count("osint"),
            "emails": count("emails"),
            "employees": count("employees"),
        }
        sev_rows = self.conn.execute(
            "SELECT severity, COUNT(*) AS c FROM findings WHERE scan_id = ? GROUP BY severity",
            (scan_id,),
        ).fetchall()
        for r in sev_rows:
            counts[f"sev_{r['severity']}"] = int(r["c"])
        return counts
