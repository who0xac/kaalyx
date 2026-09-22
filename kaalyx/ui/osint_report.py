"""Full, human-readable OSINT report generator.

Produces a single plain-text file (``<domain>/osint/osint_report.txt``) that captures EVERY
source's output in a clean, field-labeled layout — one labeled value per line, a blank line
between entries, a clearly headed section per source, and never a wall of run-together text or
a raw JSON dump. The terminal shows only a compact summary; this file is where the full detail
lives, readable source by source without having to parse raw output.

Design: each source's data shape gets a fitting set of labeled fields. A registry maps a source
name to a renderer; sources without a bespoke renderer fall back to a generic field-labeled
layout driven by their typed ``SourceResult`` records. A source with a data-integrity concern
(e.g. an org that could not be confidently identified) gets a warning callout at the top of its
section.

This module is deliberately free of rich/color: it writes flat text meant to be opened in any
editor or `less`. It never raises — a renderer that hits unexpected data degrades to the
generic layout rather than breaking report generation.
"""

from __future__ import annotations

from typing import Callable

from ..stages.sources import SourceResult
from .osint_ui import _DISPLAY_NAMES, _SOURCE_DESC


# ---------------------------------------------------------------------------------------------
# Low-level text helpers — a consistent field-labeled idiom shared by every renderer.
# ---------------------------------------------------------------------------------------------

_INDENT = "    "           # entry body indent
_LABEL_W = 12              # label column width so values line up


def _sev(value) -> str:
    """Severity as an upper-case string, tolerant of enum or plain string."""
    return (getattr(value, "value", None) or str(value or "")).upper() or "UNKNOWN"


def _conf(value) -> str:
    """Confidence as a lower-case string, tolerant of enum or plain string."""
    return (getattr(value, "value", None) or str(value or "")).lower() or "unknown"


def _field(label: str, value, indent: str = _INDENT, width: int = _LABEL_W) -> str:
    """One labeled line: ``    Label:  value`` with the label column padded so values align.
    A blank/None value is rendered as ``—`` so every declared field is visible (never omitted
    silently — the reader sees the field was checked). *width* pads the label column; a caller
    with long/variable labels passes a width computed from its own label set so values still
    line up rather than being knocked out of column."""
    v = "" if value is None else str(value).strip()
    return f"{indent}{(label + ':'):<{width}} {v if v else '—'}"


def _align_width(labels: list[str], minimum: int = _LABEL_W) -> int:
    """Label-column width that fits the longest label in *labels* (+ the colon), so a section
    with long field names still aligns its values."""
    longest = max((len(x) for x in labels), default=0) + 1
    return max(minimum, longest + 1)


def _multiline(label: str, text: str, indent: str = _INDENT) -> list[str]:
    """A labeled block whose value may span several lines — the label sits on its own line and
    the wrapped body is indented under it, so long free text (a banner, a description) stays
    readable and never runs together with the next field."""
    body = (text or "").strip()
    if not body:
        return [f"{indent}{(label + ':'):<{_LABEL_W}} —"]
    lines = [f"{indent}{label}:"]
    for ln in body.splitlines() or [body]:
        lines.append(f"{indent}    {ln.rstrip()}")
    return lines


def _entry_header(index: int, title: str) -> str:
    """The ``[N] Title`` line that opens one entry inside a section."""
    return f"{_INDENT}[{index}] {title}"


def _section_header(display: str, desc: str) -> list[str]:
    """A clearly delimited section header for one source."""
    bar = "=" * 78
    head = f"  {display}" + (f"  —  {desc}" if desc else "")
    return [bar, head, bar]


def _status_line(r: SourceResult) -> str | None:
    """A single status line for a source that did not produce data (skipped / failed / empty).
    Returns None when the source ran and produced records (so the renderer body handles it)."""
    if not r.ok:
        return _field("Status", f"FAILED — {r.error or r.note or 'unknown error'}")
    if r.skipped:
        return _field("Status", r.note or "skipped")
    if r.total == 0:
        return _field("Status", "ran — no results" + (f" ({r.note})" if r.note else ""))
    return None


# ---------------------------------------------------------------------------------------------
# Per-source renderers. Each takes a SourceResult and returns the section BODY lines (the header
# and any warning callout are added by the driver). A renderer only handles the "has data" case;
# the empty/skipped/failed case is handled uniformly before dispatch.
# ---------------------------------------------------------------------------------------------

# WHOIS records arrive as OsintRecords (kind="whois") with value = "field: content" or
# value/detail pairs. Group them into labeled sub-sections so registrar/dates/nameservers read
# cleanly rather than as one blob.
_WHOIS_ORDER = [
    ("registrar", "Registrar"), ("registrant", "Registrant"), ("org", "Organization"),
    ("created", "Created"), ("creation", "Created"), ("updated", "Updated"),
    ("expiry", "Expires"), ("expires", "Expires"), ("expiration", "Expires"),
    ("nameserver", "Nameserver"), ("name_server", "Nameserver"), ("ns", "Nameserver"),
    ("status", "Status"), ("dnssec", "DNSSEC"), ("email", "Contact Email"),
]


def _render_whois(r: SourceResult) -> list[str]:
    # Each WHOIS datum is a (kind-ish label, value). value may be "Label: content" or the
    # content with the label in detail — normalize both to (label, content).
    pairs: list[tuple[str, str]] = []
    for o in r.osint:
        val = (o.value or "").strip()
        det = (o.detail or "").strip()
        if det and not val.lower().startswith(det.lower()):
            label, content = det, val
        elif ":" in val:
            label, content = val.split(":", 1)
        else:
            label, content = o.kind, val
        pairs.append((label.strip().rstrip(":"), content.strip()))
    if not pairs:
        return [_field("Status", "ran — no WHOIS data returned")]
    labels = [label.title() for label, _ in pairs]
    w = _align_width(labels)
    lines: list[str] = []
    for label, content in pairs:
        lines.append(_field(label.title(), content, width=w))
    return lines


def _render_dns(r: SourceResult) -> list[str]:
    # DNS records: group by record type (A/AAAA/MX/NS/TXT/CNAME/SOA) from the OsintRecord kind
    # or detail, one value per line under each type.
    by_type: dict[str, list[str]] = {}
    for o in r.osint:
        rtype = (o.detail or o.kind or "record").strip().upper()
        # detail sometimes carries "A" / "MX 10 mail..." — take the leading token as the type.
        rtype = rtype.split()[0] if rtype else "RECORD"
        by_type.setdefault(rtype, []).append((o.value or "").strip())
    if not by_type:
        return [_field("Status", "ran — no DNS records returned")]
    w = _align_width(list(by_type))
    lines: list[str] = []
    for rtype in sorted(by_type):
        for i, v in enumerate(by_type[rtype]):
            lines.append(_field(rtype if i == 0 else "", v, width=w))
    return lines


def _render_mail_dns(r: SourceResult) -> list[str]:
    # Anti-spoofing / mail DNS posture: SPF/DMARC/DKIM/CAA/BIMI/MTA-STS/TLS-RPT — each on its own
    # labeled line, present-or-absent explicit.
    lines: list[str] = []
    for o in r.osint:
        key = (o.kind or "record").upper().replace("_", "-")
        val = (o.value or "").strip()
        if o.detail:
            val = f"{val}  ({o.detail.strip()})" if val else o.detail.strip()
        lines.append(_field(key, val))
    return lines or [_field("Status", "ran — no mail-DNS records returned")]


def _split_secret_evidence(evidence: str) -> dict[str, str]:
    """Secret-scan findings pack location + value into evidence as ``repo | file:line | value``
    (a compact, on-one-line shape). Split it back into Repo / File / Line / Value fields for the
    report so each reads on its own labeled line. Returns {} if the shape doesn't match, so a
    non-secret finding falls through to a plain Value line."""
    parts = [p.strip() for p in (evidence or "").split(" | ")]
    if len(parts) < 2:
        return {}
    out: dict[str, str] = {}
    # Last part is the value; a middle part shaped file:line is the location; the first is repo.
    out["Value"] = parts[-1]
    loc = parts[-2] if len(parts) >= 2 else ""
    if len(parts) >= 3:
        out["Repo"] = parts[0]
    if loc:
        if ":" in loc and loc.rsplit(":", 1)[1].isdigit():
            f, ln = loc.rsplit(":", 1)
            out["File"], out["Line"] = f, ln
        else:
            out["File"] = loc
    return out


def _render_findings(r: SourceResult) -> list[str]:
    """Secret / vulnerability / misconfig findings — the field-labeled entry layout the user
    specified: ``[N] SEVERITY · Title (verified/unverified)`` then Repo/File/Line/Value/etc.
    Used for every finding-bearing source (TruffleHog, gitGraber, badsecrets, exposed_git,
    firebase, api_leaks, workflow_logs, github_actions, …). Fields are drawn from the Finding's
    typed attributes; the location/value evidence is split into labeled fields when it carries
    the ``repo | file:line | value`` shape, and the value is always shown IN FULL (never masked
    or truncated)."""
    ind = _INDENT + "    "
    lines: list[str] = []
    for i, f in enumerate(r.findings, 1):
        ver = "verified" if _conf(f.confidence) == "confirmed" else "unverified"
        lines.append(_entry_header(i, f"{_sev(f.severity)} · {f.title}  ({ver})"))
        loc = _split_secret_evidence(f.evidence)
        # Repo / File / Line from the split evidence (secret-scan shape), else Target.
        if loc.get("Repo"):
            lines.append(_field("Repo", loc["Repo"], indent=ind))
        elif f.target:
            lines.append(_field("Target", f.target, indent=ind))
        if loc.get("File"):
            lines.append(_field("File", loc["File"], indent=ind))
        if loc.get("Line"):
            lines.append(_field("Line", loc["Line"], indent=ind))
        if f.tool:
            lines.append(_field("Tool", f.tool, indent=ind))
        if f.reference:
            lines.append(_field("Reference", f.reference, indent=ind))
        # Description carries the same value/location text in secret findings — only show it as a
        # Detail block when it adds something beyond the split fields (non-secret findings).
        if f.description and not loc:
            lines += _multiline("Detail", f.description, indent=ind)
        # The actual value/secret — shown IN FULL, always, on its own line(s).
        value = loc.get("Value") or f.evidence
        if value:
            lines += _multiline("Value", value, indent=ind)
        lines.append("")
    if lines and lines[-1] == "":
        lines.pop()
    return lines or [_field("Status", "ran — no findings")]


def _render_emails(r: SourceResult) -> list[str]:
    lines: list[str] = []
    for i, e in enumerate(r.emails, 1):
        lines.append(_entry_header(i, e.address))
        lines.append(_field("Source", e.source, indent=_INDENT + "    "))
        if e.breached or e.breach_count:
            lines.append(_field("Breached", f"yes ({e.breach_count})", indent=_INDENT + "    "))
            if e.breach_detail:
                lines.append(_field("Breaches", e.breach_detail, indent=_INDENT + "    "))
        lines.append("")
    if lines and lines[-1] == "":
        lines.pop()
    return lines or [_field("Status", "ran — no emails harvested")]


def _render_employees(r: SourceResult) -> list[str]:
    lines: list[str] = []
    for i, e in enumerate(r.employees, 1):
        lines.append(_entry_header(i, e.name))
        lines.append(_field("Role", e.role, indent=_INDENT + "    "))
        lines.append(_field("Source", e.source, indent=_INDENT + "    "))
        lines.append("")
    # theHarvester also yields emails/hosts as OSINT records — append them so nothing is dropped.
    if r.emails:
        lines.append(f"{_INDENT}Emails:")
        for e in r.emails:
            lines.append(f"{_INDENT}    {e.address}")
        lines.append("")
    if lines and lines[-1] == "":
        lines.pop()
    return lines or [_field("Status", "ran — no people/emails found")]


def _render_mobile_apps(r: SourceResult) -> list[str]:
    # Mobile apps: App Name / Package ID / Store / Developer / Signal (which identity matched).
    # An app is an OsintRecord kind="mobile_app"; value = app name, detail carries the rest as
    # "store=… id=… dev=… signal=…" or a free string — parse the structured hints when present.
    lines: list[str] = []
    for i, o in enumerate(r.osint, 1):
        name = (o.value or "app").strip()
        meta = _parse_kv(o.detail or "")
        lines.append(_entry_header(i, name))
        lines.append(_field("Store", meta.get("store") or _guess_store(o), indent=_INDENT + "    "))
        lines.append(_field("Package ID", meta.get("id") or meta.get("package") or meta.get("bundle"),
                            indent=_INDENT + "    "))
        lines.append(_field("Developer", meta.get("dev") or meta.get("developer"),
                            indent=_INDENT + "    "))
        lines.append(_field("Signal", meta.get("signal") or meta.get("match") or o.source,
                            indent=_INDENT + "    "))
        if not meta and o.detail:
            lines += _multiline("Detail", o.detail, indent=_INDENT + "    ")
        lines.append("")
    if lines and lines[-1] == "":
        lines.pop()
    return lines or [_field("Status", "ran — no apps found")]


def _render_shodan(r: SourceResult) -> list[str]:
    # Shodan-family results (org/host/vulns/favicon): IP / Port / Service / Banner / CVE.
    # These arrive as OsintRecords and/or Findings; render both, host-centric.
    lines: list[str] = []
    n = 0
    for o in r.osint:
        n += 1
        meta = _parse_kv(o.detail or "")
        lines.append(_entry_header(n, (o.value or "host").strip()))
        lines.append(_field("Port", meta.get("port"), indent=_INDENT + "    "))
        lines.append(_field("Service", meta.get("service") or meta.get("product") or o.kind,
                            indent=_INDENT + "    "))
        if meta.get("cve") or meta.get("vulns"):
            lines.append(_field("CVE", meta.get("cve") or meta.get("vulns"), indent=_INDENT + "    "))
        if meta.get("banner"):
            lines += _multiline("Banner", meta["banner"], indent=_INDENT + "    ")
        elif not meta and o.detail:
            lines += _multiline("Detail", o.detail, indent=_INDENT + "    ")
        lines.append("")
    for f in r.findings:
        n += 1
        lines.append(_entry_header(n, f"{_sev(f.severity)} · {f.title}"))
        lines.append(_field("Target", f.target, indent=_INDENT + "    "))
        if f.reference:
            lines.append(_field("CVE/Ref", f.reference, indent=_INDENT + "    "))
        if f.description:
            lines += _multiline("Detail", f.description, indent=_INDENT + "    ")
        lines.append("")
    if lines and lines[-1] == "":
        lines.pop()
    return lines or [_field("Status", "ran — no Shodan data returned")]


def _render_dnstwist(r: SourceResult) -> list[str]:
    # Typosquat / look-alike domains: Lookalike Domain / Registered / Has MX / Resembles site.
    lines: list[str] = []
    for i, o in enumerate(r.osint, 1):
        meta = _parse_kv(o.detail or "")
        lines.append(_entry_header(i, (o.value or "domain").strip()))
        lines.append(_field("Registered", meta.get("registered") or _yn(meta.get("dns_a") or meta.get("a")),
                            indent=_INDENT + "    "))
        lines.append(_field("Has MX", _yn(meta.get("mx") or meta.get("dns_mx")), indent=_INDENT + "    "))
        lines.append(_field("Resembles", meta.get("resembles") or meta.get("similarity"),
                            indent=_INDENT + "    "))
        if not meta and o.detail:
            lines += _multiline("Detail", o.detail, indent=_INDENT + "    ")
        lines.append("")
    if lines and lines[-1] == "":
        lines.pop()
    return lines or [_field("Status", "ran — no look-alike domains found")]


def _render_leak(r: SourceResult) -> list[str]:
    # Leaked/breached credentials: Email / Source / Date / Password-or-Hash (shown in full).
    lines: list[str] = []
    n = 0
    for i, f in enumerate(r.findings, 1):
        n += 1
        lines.append(_entry_header(n, f.title or "leaked credential"))
        lines.append(_field("Target", f.target, indent=_INDENT + "    "))
        meta = _parse_kv(f.description or "")
        if meta.get("source") or f.tool:
            lines.append(_field("Source", meta.get("source") or f.tool, indent=_INDENT + "    "))
        if meta.get("date"):
            lines.append(_field("Date", meta["date"], indent=_INDENT + "    "))
        # The recovered password/hash — full value per no-mask rule.
        if f.evidence:
            lines += _multiline("Credential", f.evidence, indent=_INDENT + "    ")
        elif f.description and not meta:
            lines += _multiline("Detail", f.description, indent=_INDENT + "    ")
        lines.append("")
    for e in r.emails:
        n += 1
        lines.append(_entry_header(n, e.address))
        lines.append(_field("Breached", f"yes ({e.breach_count})" if e.breached else "no",
                            indent=_INDENT + "    "))
        if e.breach_detail:
            lines.append(_field("Breaches", e.breach_detail, indent=_INDENT + "    "))
        lines.append("")
    if lines and lines[-1] == "":
        lines.pop()
    return lines or [_field("Status", "ran — no leaked credentials found")]


def _render_google_dorks(r: SourceResult) -> list[str]:
    # Ready-to-run dork URLs — one per line, grouped is unnecessary; just list them cleanly.
    urls = [(o.value or "").strip() for o in r.osint if (o.value or "").strip()]
    if not urls:
        return [_field("Status", "ran — no dork URLs generated")]
    return [f"{_INDENT}{u}" for u in urls]


# ---------------------------------------------------------------------------------------------
# Small parsing helpers for the semi-structured `detail` strings some sources carry.
# ---------------------------------------------------------------------------------------------

def _parse_kv(text: str) -> dict[str, str]:
    """Parse a ``k=v k2=v2`` or ``k: v; k2: v2`` detail string into a dict, lower-cased keys.
    Tolerant: returns {} for free text that isn't key/value shaped."""
    out: dict[str, str] = {}
    if not text:
        return out
    # Split on ; or , (but not inside a value); then k=v or k: v.
    import re
    for chunk in re.split(r"[;\n]", text):
        m = re.match(r"\s*([A-Za-z_][\w \-]*?)\s*[:=]\s*(.+)", chunk)
        if m:
            out[m.group(1).strip().lower()] = m.group(2).strip()
    return out


def _yn(value) -> str:
    if value is None or value == "":
        return "—"
    s = str(value).strip().lower()
    if s in ("y", "yes", "true", "1"):
        return "yes"
    if s in ("n", "no", "false", "0"):
        return "no"
    return str(value)


def _guess_store(o) -> str:
    src = (getattr(o, "source", "") or "").lower()
    if "apple" in src or "ios" in src or "app store" in src:
        return "Apple App Store"
    if "play" in src or "google" in src or "android" in src:
        return "Google Play"
    return ""


# ---------------------------------------------------------------------------------------------
# Generic renderer — field-labeled fallback for any source without a bespoke layout. Renders
# whatever typed records the source carried (findings / osint / subdomains / urls / emails)
# each in a clean labeled form, never as a raw blob.
# ---------------------------------------------------------------------------------------------

def _render_generic(r: SourceResult) -> list[str]:
    lines: list[str] = []
    if r.findings:
        lines += _render_findings(r)
    if r.osint:
        if lines:
            lines.append("")
        for i, o in enumerate(r.osint, 1):
            head = (o.value or "").strip() or o.kind
            lines.append(_entry_header(i, head))
            if o.kind and o.kind != head:
                lines.append(_field("Type", o.kind, indent=_INDENT + "    "))
            if o.detail:
                meta = _parse_kv(o.detail)
                if meta:
                    for k, v in meta.items():
                        lines.append(_field(k.title(), v, indent=_INDENT + "    "))
                else:
                    lines += _multiline("Detail", o.detail, indent=_INDENT + "    ")
            if o.source:
                lines.append(_field("Source", o.source, indent=_INDENT + "    "))
            lines.append("")
        if lines and lines[-1] == "":
            lines.pop()
    if r.subdomains:
        if lines:
            lines.append("")
        lines.append(f"{_INDENT}Subdomains ({len(r.subdomains)}):")
        for s in r.subdomains:
            flag = "  [interesting]" if getattr(s, "interesting", False) else ""
            lines.append(f"{_INDENT}    {s.hostname}{flag}")
    if r.urls:
        if lines:
            lines.append("")
        lines.append(f"{_INDENT}URLs / endpoints ({len(r.urls)}):")
        for u in r.urls:
            lines.append(f"{_INDENT}    {u.url}")
    return lines or [_field("Status", "ran — no results")]


# name -> renderer. Finding-heavy secret/vuln sources share _render_findings; the rest map to
# their data-shaped renderer, and anything absent uses _render_generic.
_RENDERERS: dict[str, Callable[[SourceResult], list[str]]] = {
    "whois": _render_whois,
    "dns": _render_dns,
    "mail_dns": _render_mail_dns,
    "email_harvest": _render_emails,
    "theharvester": _render_employees,
    "mobile_apps": _render_mobile_apps,
    "dnstwist": _render_dnstwist,
    "google_dorks": _render_google_dorks,
    "breach_lookup": _render_leak,
    "leak_search": _render_leak,
    "shodan_org": _render_shodan,
    "shodan_favicon": _render_shodan,
    "shodan_vulns": _render_shodan,
    "shodan_host": _render_shodan,
    "internetdb": _render_shodan,
    # Finding-bearing secret/vuln/misconfig sources.
    "trufflehog": _render_findings,
    "gitgraber": _render_findings,
    "workflow_logs": _render_findings,
    "github_actions": _render_findings,
    "badsecrets": _render_findings,
    "retirejs": _render_findings,
    "exposed_git": _render_findings,
    "firebase": _render_findings,
    "api_leaks": _render_findings,
    "third_party_misconfig": _render_findings,
    "cloud_enum": _render_findings,
    "s3scanner": _render_findings,
}


def _warning_for(r: SourceResult, org_note: str | None) -> str | None:
    """A data-integrity warning to print at the top of a source's section, or None. Currently
    the GitHub-org-scanning sources carry the org-identification note so the reader knows exactly
    which account was (or was NOT) scanned — the guard against silently trusting a wrong-org
    scan."""
    if r.name in ("trufflehog", "github_actions", "workflow_logs") and org_note:
        return org_note
    return None


def build_osint_report(
    domain: str,
    results: list[SourceResult],
    *,
    org: str | None = None,
    org_reason: str | None = None,
    duration_s: float = 0.0,
    flagged: list[str] | None = None,
) -> str:
    """Render the full field-labeled OSINT report for *domain* as one text string.

    Every source in *results* gets its own headed section (in pipeline order), rendered with the
    renderer registered for it or the generic field-labeled fallback — never a raw blob. Sources
    that skipped / failed / found nothing still get a section stating so, so the reader sees the
    full set of checks. A data-integrity concern (e.g. the GitHub org used by the secret scanners)
    is called out at the top of the affected section and summarized in the header.
    """
    flagged = flagged or []
    total_findings = sum(len(r.findings) for r in results)
    ran = sum(1 for r in results if r.ok and not r.skipped)
    skipped = sum(1 for r in results if r.skipped)
    failed = sum(1 for r in results if not r.ok)

    # The org note the secret-scanning sections warn with.
    if org:
        org_note = f"GitHub org scanned: {org}" + (f" ({org_reason})" if org_reason else "")
    else:
        org_note = ("No GitHub org was confidently identified — the org secret scanners "
                    "(TruffleHog / gato / workflow logs) were SKIPPED rather than risk scanning an "
                    "unrelated account"
                    + (f". {org_reason}" if org_reason else "."))

    lines: list[str] = []
    lines.append("#" * 78)
    lines.append(f"# KAALYX OSINT REPORT — {domain}")
    lines.append(f"# {len(results)} sources · {ran} ran · {skipped} skipped · {failed} failed "
                 f"· {total_findings} findings")
    if flagged:
        lines.append(f"# {len(flagged)} flagged for review:")
        for item in flagged:
            lines.append(f"#   - {item}")
    lines.append("#" * 78)
    lines.append("")

    for r in results:
        display = _DISPLAY_NAMES.get(r.name, r.name.upper())
        desc = _SOURCE_DESC.get(r.name, "")
        lines += _section_header(display, desc)
        lines.append("")

        warn = _warning_for(r, org_note)
        if warn:
            lines.append(f"{_INDENT}!! {warn}")
            lines.append("")

        status = _status_line(r)
        if status is not None:
            lines.append(status)
        else:
            renderer = _RENDERERS.get(r.name, _render_generic)
            try:
                body = renderer(r)
            except Exception as exc:  # a renderer must never break report generation
                body = _render_generic(r) + [_field("(render note)", f"{type(exc).__name__}: {exc}")]
            lines += body
        if r.note and status is None:
            lines.append("")
            lines.append(_field("Note", r.note))
        lines.append("")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"
