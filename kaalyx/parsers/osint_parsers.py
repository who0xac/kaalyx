"""Parsers for the tool outputs consumed by the OSINT stage.

Kept deliberately defensive: each function accepts a tool's raw stdout and returns
normalised models, skipping anything it doesn't recognise. Tool output formats drift over
versions, so we read the fields we need and ignore the rest rather than asserting a
schema.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from . import iter_json_lines, try_load_json
from ..data.models import (
    Confidence,
    Email,
    Employee,
    Finding,
    OsintRecord,
    Severity,
    Subdomain,
)


def _target_labels(target: str) -> tuple[str, str]:
    """Return ``(registrable, base_label)`` for *target*, both lower-cased.

    e.g. ``"Stripe.com"`` -> ``("stripe.com", "stripe")``. Empty target yields ``("", "")``.
    """
    t = (target or "").strip().lower().strip(".")
    if not t:
        return "", ""
    base = t.split(".")[0]
    return t, base


def assess_target_relevance(text: str, target: str) -> str:
    """How strongly a discovered artifact (bucket name, URL, workspace text) ties to *target*.

    Keyword-seeded sources (cloud_enum, s3scanner, porch-pirate, SwaggerSpy) are fed the
    target's *name* and match on it, so a hit can be a generic-word over-match rather than a
    genuinely target-owned resource — the same class of risk as the GitHub-org bug, just
    milder. This grades that tie so callers can verify where possible and, where not, mark the
    finding as keyword-match rather than presenting it like an exact-match source (whois/dnsx):

      * ``"direct"``  — text contains the full registrable domain (``stripe.com``) or a
        subdomain of it (``x.stripe.com``). Strong tie to the target; keep confidence as-is.
      * ``"keyword"`` — text contains only the bare base label (``stripe``) but not the full
        domain. Plausible but unverified; downgrade + flag.
      * ``"none"``    — no visible tie at all (tool matched something for the seed keyword).
        Weakest; downgrade + flag most explicitly.
    """
    reg, base = _target_labels(target)
    low = (text or "").lower()
    if not reg or not low:
        return "none"
    # Full-domain mention: as a bare domain, or as the host part of a subdomain. Word-ish
    # boundaries so "notstripe.com" doesn't count as stripe.com.
    if re.search(r"(?:^|[^a-z0-9.-])(?:[a-z0-9-]+\.)*" + re.escape(reg) + r"(?:[^a-z0-9.-]|$)", low):
        return "direct"
    if base and re.search(r"(?:^|[^a-z0-9])" + re.escape(base) + r"(?:[^a-z0-9]|$)", low):
        return "keyword"
    return "none"


# Confidence must never exceed TENTATIVE for a keyword/none-relevance finding — it isn't
# verified as target-owned. Callers pass their intended confidence and get it capped.
def _cap_for_relevance(intended: Confidence, relevance: str) -> Confidence:
    if relevance == "direct":
        return intended
    return Confidence.TENTATIVE


def _relevance_note(relevance: str, target: str) -> str:
    """Human-readable caveat appended to a keyword-seeded finding's description."""
    reg, _ = _target_labels(target)
    if relevance == "direct":
        return ""
    if relevance == "keyword":
        return (f" [keyword-match: name resembles '{reg}' but the resource does not "
                f"reference {reg} directly — verify it is target-owned]")
    return (f" [keyword-match only: matched the search seed for '{reg}' but shows no direct "
            f"reference to {reg} — verify it is target-owned]")


def parse_dnsx(stdout: str, source: str = "dnsx") -> list[OsintRecord]:
    """Parse ``dnsx -json`` output into DNS OSINT records.

    dnsx JSON lines look like::

        {"host":"example.com","a":["93.184.216.34"],"aaaa":[...],"mx":[...],
         "ns":[...],"txt":[...],"cname":[...]}

    We flatten each record type into ``kind='dns'`` OSINT rows of the form
    ``"<host> <TYPE> <value>"`` so they're greppable in the raw file and queryable in DB.
    """
    records: list[OsintRecord] = []
    record_fields = {
        "a": "A", "aaaa": "AAAA", "cname": "CNAME", "mx": "MX",
        "ns": "NS", "txt": "TXT", "soa": "SOA", "ptr": "PTR", "srv": "SRV",
    }
    for obj in iter_json_lines(stdout):
        host = obj.get("host") or obj.get("name") or ""
        if not host:
            continue
        for field_name, rtype in record_fields.items():
            values = obj.get(field_name)
            if not values:
                continue
            if isinstance(values, str):
                values = [values]
            for value in values:
                # MX/SOA can be dicts depending on version; stringify defensively.
                text = value if isinstance(value, str) else str(value)
                records.append(
                    OsintRecord(
                        kind="dns",
                        value=f"{host} {rtype} {text}",
                        detail=rtype,
                        source=source,
                    )
                )
    return records


def parse_subdomain_lines(stdout: str, source: str) -> list[Subdomain]:
    """Parse plain host-per-line output (github-subdomains, subfinder-style)."""
    subs: list[Subdomain] = []
    seen: set[str] = set()
    for line in stdout.splitlines():
        host = line.strip().lower().rstrip(".")
        # Some tools prefix with URLs or annotate; keep only bare-hostname-looking tokens.
        host = host.split()[0] if host else host
        if not host or "." not in host or "/" in host or host in seen:
            continue
        seen.add(host)
        subs.append(Subdomain(hostname=host, source=source))
    return subs


def _owner_of_repo_url(url: str) -> str | None:
    """Extract the owner login from a GitHub repo URL/full-name in trufflehog metadata.

    Handles ``https://github.com/<owner>/<repo>(.git)`` and bare ``<owner>/<repo>`` forms.
    Returns the lower-cased owner, or ``None`` if it can't be determined.
    """
    if not url:
        return None
    s = url.strip()
    m = re.search(r"github\.com[:/]+([^/]+)/", s)
    if m:
        return m.group(1).lower()
    # Bare "owner/repo" form (no scheme, no leading slash): first segment is the owner.
    if "://" not in s and not s.startswith("/") and "/" in s:
        first = s.split("/", 1)[0].strip().lower()
        return first or None
    return None


def mask_secret(value: str) -> str:
    """Mask a secret for safe on-screen display: keep the first & last few chars, hide the
    middle (``AKIA…len=40…3F9c``). Short values are fully masked so nothing usable leaks.

    The masking is deliberate: the findings table is shown in a terminal (and may be
    screenshotted/shared), so we never print a usable secret there — enough to recognise
    which key it is and eyeball whether it's a placeholder, but not to use it. The full raw
    value stays only in the on-disk raw file / DB for deliberate manual verification.
    """
    v = (value or "").strip()
    if not v:
        return ""
    n = len(v)
    if n <= 8:
        return f"{'•' * n} (len={n})"
    head, tail = v[:4], v[-4:]
    return f"{head}…{'•' * min(6, n - 8)}…{tail} (len={n})"


def _trufflehog_location(meta: dict) -> tuple[str, str, str]:
    """Pull ``(repository, file, line)`` from a trufflehog SourceMetadata block.

    trufflehog v3 nests these under ``SourceMetadata.Data.<SourceType>`` (e.g. ``Github``),
    with keys ``repository``, ``file``, ``line``/``line_number`` and ``link``. Returns
    best-effort strings ("" when absent). ``repository`` falls back to any ``link``.
    """
    repo = file = line = link = ""
    data = meta.get("Data") if isinstance(meta, dict) else None
    if isinstance(data, dict):
        for block in data.values():
            if not isinstance(block, dict):
                continue
            repo = block.get("repository") or repo
            file = block.get("file") or file
            link = block.get("link") or link
            ln = block.get("line", block.get("line_number", ""))
            if ln not in ("", None):
                line = str(ln)
    return (repo or link, file, line)


def parse_trufflehog(
    stdout: str, source: str = "trufflehog", restrict_owner: str | None = None
) -> list[Finding]:
    """Parse ``trufflehog --json`` output into secret findings.

    trufflehog v3 emits one JSON object per detected secret with ``DetectorName``,
    ``Verified``, ``Raw``, and a ``SourceMetadata`` block. Verified secrets are treated as
    higher severity/confidence than unverified ones.

    Each finding surfaces enough to triage at a glance WITHOUT running jq: a masked preview of
    the detected value (via :func:`mask_secret`) and the exact file + line inside the repo,
    packed into ``evidence`` as ``repo | file:line | <masked value>``. The unmasked value and
    full JSON live only in ``raw`` (persisted to disk/DB), never shown on screen.

    When *restrict_owner* is given, only secrets whose source repository is owned by that
    GitHub org/user are kept. This is a safety net: ``trufflehog github --org X`` can fall
    back to scanning the *authenticated* account if ``X`` resolves oddly, and we must never
    surface the token owner's own repo secrets as if they belonged to the target. Findings
    whose owner can't be determined are dropped under this restriction (fail closed).
    """
    findings: list[Finding] = []
    want_owner = restrict_owner.lower() if restrict_owner else None
    for obj in iter_json_lines(stdout):
        detector = obj.get("DetectorName") or obj.get("detector_name") or "secret"
        verified = bool(obj.get("Verified") or obj.get("verified"))
        raw_secret = obj.get("Raw") or obj.get("raw") or ""
        meta = obj.get("SourceMetadata") or {}
        repo, file, line = _trufflehog_location(meta)
        location = repo or file or "github-org"
        if want_owner is not None and _owner_of_repo_url(repo) != want_owner:
            # Not the target org's repo (or unattributable) — drop it, so a trufflehog
            # fallback to the authenticated account can never surface the token owner's
            # secrets under the target's report.
            continue
        # Where it was found (file:line) + a masked preview of the value — enough to triage
        # without opening the raw file, but the value is never shown usable on screen.
        where = f"{file}:{line}" if file and line else (file or "")
        masked = mask_secret(raw_secret)
        evidence = " | ".join(p for p in (repo, where, masked) if p)
        desc = (
            f"{detector} secret "
            + ("verified (authenticates)" if verified else "detected (unverified)")
            + (f" at {where}" if where else "")
            + (f". Value: {masked}" if masked else "")
            + "."
        )
        findings.append(
            Finding(
                title=f"Exposed secret: {detector}",
                category="secret",
                severity=Severity.HIGH if verified else Severity.MEDIUM,
                confidence=Confidence.CONFIRMED if verified else Confidence.TENTATIVE,
                target=(f"{location}:{line}" if line else location),
                tool=source,
                description=desc,
                evidence=evidence,
                raw=str(obj)[:2000],  # full JSON incl. unmasked Raw — on-disk/DB only
            )
        )
    return findings


def parse_s3scanner(stdout: str, source: str = "s3scanner",
                    target: str = "") -> list[Finding]:
    """Parse s3scanner output into bucket findings.

    s3scanner prints lines describing bucket existence/permissions. We flag buckets that
    are reported as existing and (especially) open/listable.

    Buckets are found by brute-forcing keyword variants of the target name, so a matched
    bucket may not actually belong to the target. When *target* is given we grade the bucket
    line's tie to it (:func:`assess_target_relevance`): a bucket name that only matches the
    base keyword — the common case, since bucket names rarely contain a full domain — is
    capped at TENTATIVE and flagged as a keyword match, so an unverified bucket is never
    presented with exact-match confidence. (Nothing is dropped: a bucket named ``stripe-prod``
    may well be the target's, so we keep it and flag it rather than lose a real finding.)
    """
    findings: list[Finding] = []
    seen: set[str] = set()
    for line in stdout.splitlines():
        text = line.strip()
        low = text.lower()
        # Skip blanks, non-existent buckets, and progress/status noise.
        if not text or "not_exist" in low or "not exist" in low:
            continue
        if any(w in low for w in ("scanning", "checking", "loading", "usage:", "error")):
            continue
        # Only lines that actually name a bucket resource (existing/permission report).
        if "bucket" not in low and "s3" not in low and "://" not in low:
            continue
        if "exists" not in low and "://" not in low and "permission" not in low \
                and "open" not in low and "public" not in low:
            continue
        if text in seen:
            continue
        seen.add(text)
        open_bucket = any(k in low for k in ("open", "public", "listable", "read", "write"))
        relevance = assess_target_relevance(text, target) if target else "direct"
        confidence = _cap_for_relevance(
            Confidence.FIRM if open_bucket else Confidence.TENTATIVE, relevance)
        findings.append(
            Finding(
                title="S3 bucket exposure" if open_bucket else "S3 bucket discovered",
                category="cloud",
                severity=Severity.HIGH if open_bucket else Severity.INFO,
                confidence=confidence,
                target=text[:200],
                tool=source,
                description="s3scanner reported this bucket."
                            + _relevance_note(relevance, target),
                evidence=text[:300],
                raw=text[:500],
            )
        )
    return findings


def parse_badsecrets(stdout: str, source: str = "badsecrets") -> list[Finding]:
    """Parse badsecrets output into crypto/secret-misconfig findings (tolerant)."""
    findings: list[Finding] = []
    for obj in iter_json_lines(stdout):
        detecting = obj.get("detecting_module") or obj.get("type") or "badsecret"
        description = obj.get("description") or str(obj)[:200]
        findings.append(
            Finding(
                title=f"Known secret / crypto misconfig: {detecting}",
                category="secret",
                severity=Severity.MEDIUM,
                confidence=Confidence.FIRM,
                tool=source,
                description=str(description)[:500],
                raw=str(obj)[:1000],
            )
        )
    # Fallback: non-JSON textual hits.
    if not findings:
        for line in stdout.splitlines():
            if "identify" in line.lower() or "known" in line.lower():
                findings.append(
                    Finding(
                        title="badsecrets hit",
                        category="secret",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.TENTATIVE,
                        tool=source,
                        description=line.strip()[:500],
                        raw=line.strip()[:500],
                    )
                )
    return findings


def parse_retirejs(stdout: str, source: str = "retirejs") -> list[Finding]:
    """Parse ``retire --outputformat json`` results into vulnerable-JS findings."""
    from . import try_load_json

    findings: list[Finding] = []
    doc = try_load_json(stdout)
    # retire.js JSON: {"data":[{"file":..,"results":[{"component":..,"version":..,
    #                  "vulnerabilities":[{"severity":..,"identifiers":..,"info":..}]}]}]}
    entries = []
    if isinstance(doc, dict):
        entries = doc.get("data") or []
    elif isinstance(doc, list):
        entries = doc
    for entry in entries:
        file_ref = entry.get("file", "") if isinstance(entry, dict) else ""
        for res in (entry.get("results") or []) if isinstance(entry, dict) else []:
            component = res.get("component", "?")
            version = res.get("version", "?")
            for vuln in res.get("vulnerabilities") or []:
                sev = Severity.coerce(str(vuln.get("severity", "medium")))
                ids = vuln.get("identifiers") or {}
                cve = ", ".join(ids.get("CVE", [])) if isinstance(ids, dict) else ""
                summary = ids.get("summary", "") if isinstance(ids, dict) else ""
                findings.append(
                    Finding(
                        title=f"Vulnerable JS: {component} {version}",
                        category="vulnerable-dependency",
                        severity=sev,
                        confidence=Confidence.FIRM,
                        target=file_ref,
                        tool=source,
                        description=summary or f"{component} {version} has known vulns.",
                        reference=cve,
                        raw=str(vuln)[:1000],
                    )
                )
    return findings


def parse_cloud_enum(stdout: str, source: str = "cloud_enum",
                     target: str = "") -> list[Finding]:
    """Parse cloud_enum output into one finding per discovered cloud resource.

    cloud_enum prints ``[+] ...`` for genuine finds and a lot of progress/status text. The
    reliable signal for a real resource is a URL on the line, so we only create a finding
    from a ``[+]`` line that contains a URL, dedup by that URL, and skip progress/negatives.

    cloud_enum is seeded with the target's name, so a hit can be a generic-word over-match.
    When *target* is given we grade each resource's tie to it (:func:`assess_target_relevance`
    on the resource URL): a URL that references the target domain keeps its confidence; one
    that only matches the base keyword is capped at TENTATIVE and flagged, so it is never
    presented with the same confidence as an exact-match source.
    """
    findings: list[Finding] = []
    seen: set[str] = set()
    url_re = re.compile(r"https?://[^\s\"'<>]+")
    for line in stdout.splitlines():
        text = line.strip()
        low = text.lower()
        if not text.startswith("[+]"):
            continue
        if any(neg in low for neg in ("not found", "no results", "nothing")):
            continue
        m = url_re.search(text)
        if not m:
            continue
        url = m.group(0).rstrip(".,)")
        if url in seen:
            continue
        seen.add(url)
        open_res = "open" in low or "public" in low
        relevance = assess_target_relevance(url, target) if target else "direct"
        confidence = _cap_for_relevance(
            Confidence.FIRM if open_res else Confidence.TENTATIVE, relevance)
        findings.append(
            Finding(
                title="Open cloud resource" if open_res else "Cloud resource discovered",
                category="cloud",
                severity=Severity.MEDIUM if open_res else Severity.INFO,
                confidence=confidence,
                target=url[:200],
                tool=source,
                description="cloud_enum reported this cloud resource."
                            + _relevance_note(relevance, target),
                evidence=text[:300],
                raw=text[:500],
            )
        )
    return findings


def parse_theharvester(stdout_or_json: str, domain: str,
                       source: str = "theHarvester") -> tuple[list[Email], list[Employee], list[Subdomain]]:
    """Parse theHarvester JSON output into emails, employees, and subdomains.

    theHarvester (run with ``-f out.json``) writes a JSON document with keys such as
    ``emails``, ``hosts``, ``linkedin_people`` and ``twitter_people``. We read
    defensively and only keep on-domain emails.
    """
    emails: list[Email] = []
    employees: list[Employee] = []
    subs: list[Subdomain] = []

    doc = try_load_json(stdout_or_json)
    if not isinstance(doc, dict):
        return emails, employees, subs

    for addr in doc.get("emails") or []:
        addr = str(addr).strip().lower()
        if "@" in addr and (addr.endswith("@" + domain) or addr.endswith("." + domain)):
            emails.append(Email(address=addr, source=source))

    for person in doc.get("linkedin_people") or []:
        employees.append(Employee(name=str(person).strip(), source="linkedin"))
    for person in doc.get("twitter_people") or []:
        employees.append(Employee(name=str(person).strip(), source="twitter"))

    for host in doc.get("hosts") or []:
        # theHarvester hosts look like "sub.example.com:1.2.3.4" or just the hostname.
        name = str(host).split(":")[0].strip().lower().rstrip(".")
        if name and "." in name and (name == domain or name.endswith("." + domain)):
            subs.append(Subdomain(hostname=name, source=source))

    return emails, employees, subs


# One recovered credential row from a breach source: the source's name and the value it
# returned (a cleartext password, a hash, or another datum such as an IP). ``kind`` classifies
# the value so the stage can label a finding correctly.
@dataclass
class BreachCredential:
    email: str
    source: str          # breach/source name, e.g. "BreachCompilation", "Snusbase"
    value: str           # the leaked value: cleartext password, hash, etc.
    kind: str            # "password" | "hash" | "other"


@dataclass
class H8mailResult:
    """Per-email breach outcome: a count/detail summary plus any recovered credentials."""
    count: int
    detail: str
    credentials: list[BreachCredential] = field(default_factory=list)


# h8mail source labels whose returned value is a password vs. a hash vs. neither. h8mail tags
# local-breach hits generically, so we also sniff the value's shape.
_HASH_RE = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$|^\$[0-9a-z]{1,4}\$", re.I)


def _classify_breach_value(source: str, value: str) -> str:
    """Classify a breach value as ``"password"``, ``"hash"``, or ``"other"``.

    A hash is detected by shape (hex of a common digest length, or a ``$id$`` crypt prefix);
    anything else that looks like a credential value is treated as a cleartext password. An
    empty value is ``"other"`` (nothing recovered — just a breach source name).
    """
    v = value.strip()
    if not v:
        return "other"
    if _HASH_RE.match(v):
        return "hash"
    low = source.lower()
    if "hash" in low:
        return "hash"
    return "password"


def parse_h8mail(stdout_or_json: str, source: str = "h8mail") -> dict[str, H8mailResult]:
    """Parse h8mail JSON output into a map of email -> :class:`H8mailResult`.

    h8mail (run with ``-j out.json``) writes ``{"targets": [{"target": email, "pwned": N,
    "data": [[source, value], ...]}]}``. NOTE: the count field is ``pwned`` (h8mail's
    attribute name), NOT ``pwn_num`` — and ``data`` entries are 2-item ``[source, value]``
    lists/tuples: element 0 is the breach source, **element 1 is the recovered value** (a
    cleartext password or hash when h8mail is run against a local breach compilation
    (``-bc``/``-lb``) or a credential-returning API via ``-c``; empty when the source only
    confirms membership). We keep BOTH — the earlier parser discarded element 1, so actual
    leaked passwords never surfaced. The stage uses the summary to enrich harvested emails and
    the credentials to raise per-credential findings.
    """
    result: dict[str, H8mailResult] = {}
    doc = try_load_json(stdout_or_json)
    if not isinstance(doc, dict):
        return result
    for target in doc.get("targets") or []:
        if not isinstance(target, dict):
            continue
        email = str(target.get("target", "")).strip().lower()
        if not email:
            continue
        # h8mail's count attribute is `pwned`; accept `pwn_num` too for other versions.
        count = int(target.get("pwned", target.get("pwn_num", 0)) or 0)

        names: list[str] = []
        creds: list[BreachCredential] = []
        for entry in target.get("data") or []:
            src_name, value = "", ""
            if isinstance(entry, (list, tuple)):
                if entry:
                    src_name = str(entry[0])
                if len(entry) > 1:
                    value = str(entry[1])
            elif isinstance(entry, str):
                # Older/variant shape "source:value" — split once, value is the remainder.
                src_name, _, value = entry.partition(":")
            src_name = src_name.strip()
            value = value.strip()
            if src_name:
                names.append(src_name[:40])
            if value:
                creds.append(BreachCredential(
                    email=email, source=src_name[:60] or source,
                    value=value, kind=_classify_breach_value(src_name, value),
                ))
        detail = ", ".join(dict.fromkeys(n for n in names if n))[:300]

        # A target counts as breached if the count is positive OR it carries breach data.
        if count == 0 and names:
            count = len(names)
        result[email] = H8mailResult(count=count, detail=detail, credentials=creds)
    return result


def parse_leaksearch(stdout_or_json: str, source: str = "LeakSearch",
                     target: str = "") -> list[Finding]:
    """Parse LeakSearch output into per-credential leak findings.

    LeakSearch (``-o out.json``) returns entries from the ProxyNova/COMB credential dump. The
    shape varies by version, so we read defensively: a list (or a dict wrapping a list under
    ``results``/``data``/``leaks``) of records, each either a dict with ``user``/``username``/
    ``email`` + ``password`` (and optional ``database``/``source``) or a raw ``"user:password"``
    string. Every recovered credential becomes ONE finding carrying the actual leaked value —
    that is the actionable OSINT (a real password, reusable/pattern-worthy) that a breach
    *count* does not give. Nothing is masked; the full value is stored and shown.
    """
    findings: list[Finding] = []
    doc = try_load_json(stdout_or_json)

    records: list = []
    if isinstance(doc, list):
        records = doc
    elif isinstance(doc, dict):
        for key in ("results", "data", "leaks", "credentials"):
            if isinstance(doc.get(key), list):
                records = doc[key]
                break
        if not records and doc:  # a single record object
            records = [doc]
    elif doc is None:
        # Not JSON — fall back to line-oriented "user:password" text (the -o txt form).
        for line in (stdout_or_json or "").splitlines():
            line = line.strip()
            if line and ":" in line and " " not in line.split(":", 1)[0]:
                records.append(line)

    seen: set[str] = set()
    for rec in records:
        user = password = db = ""
        if isinstance(rec, dict):
            user = str(rec.get("user") or rec.get("username") or rec.get("email") or "").strip()
            password = str(rec.get("password") or rec.get("pass") or rec.get("value") or "").strip()
            db = str(rec.get("database") or rec.get("source") or rec.get("db") or "").strip()
        elif isinstance(rec, str):
            user, _, password = rec.partition(":")
            user, password = user.strip(), password.strip()
        if not user and not password:
            continue
        dedup = f"{user}:{password}:{db}"
        if dedup in seen:
            continue
        seen.add(dedup)
        # Relevance: a credential whose username/email ties to the target is a direct hit;
        # a bare keyword match (LeakSearch was seeded with the domain) is downgraded + flagged.
        relevance = assess_target_relevance(user, target) if target else "direct"
        has_pw = bool(password)
        findings.append(Finding(
            title=("Leaked credential (plaintext password)" if has_pw
                   else "Leaked credential (account in dump)"),
            category="credential-leak",
            severity=Severity.HIGH if has_pw else Severity.MEDIUM,
            confidence=_cap_for_relevance(
                Confidence.FIRM if has_pw else Confidence.TENTATIVE, relevance),
            target=user or password,
            tool=source,
            description=(f"Credential dump exposure for '{user}'"
                         + (f" in {db}" if db else "")
                         + (": password recovered." if has_pw else " (no plaintext password in this record).")
                         + _relevance_note(relevance, target)),
            evidence=(f"{user}:{password}" if has_pw else user)[:300],
            raw=str(rec)[:500],
        ))
    return findings


def parse_misconfig_mapper(stdout: str, source: str = "misconfig-mapper") -> list[Finding]:
    """Parse misconfig-mapper output into findings — ONLY genuine positive detections.

    Run with ``-output-json``, so the reliable path is JSON: each result carries a boolean
    (``vulnerable``/``exists``); a finding is created only when that is true.

    The text fallback is deliberately strict. misconfig-mapper's plain output mixes real
    hits with progress lines (``[+] Checking 100 possible target URLs...``) and NEGATIVE
    results (``[-] No vulnerable ... instance found``). We therefore require an explicit
    positive phrase AND reject anything that is a progress line or a negative result — never
    matching on the bare word "vulnerable" (which appears in "No vulnerable ... found").
    """
    findings: list[Finding] = []

    def _finding(target: str, detail: str) -> Finding:
        return Finding(
            title="Third-party service misconfiguration",
            category="third-party-misconfig",
            severity=Severity.MEDIUM,
            confidence=Confidence.FIRM,
            target=target[:200],
            tool=source,
            description="misconfig-mapper detected a misconfigured third-party service.",
            evidence=detail[:300],
            raw=detail[:500],
        )

    # --- JSON path (preferred): report only entries explicitly flagged vulnerable. ---
    doc = try_load_json(stdout)
    if doc is not None:
        # Output shape varies by version: a list of results, or {"results": [...]} /
        # {"services": [...]}. Walk defensively and key off a truthy vulnerable/exists flag.
        entries = []
        if isinstance(doc, list):
            entries = doc
        elif isinstance(doc, dict):
            entries = doc.get("results") or doc.get("services") or doc.get("data") or []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            vulnerable = bool(
                entry.get("vulnerable") or entry.get("exists") or entry.get("misconfigured")
            )
            if not vulnerable:
                continue
            name = (
                entry.get("service") or entry.get("name") or entry.get("target")
                or entry.get("url") or "third-party service"
            )
            findings.append(_finding(str(name), str(entry)))
        return findings  # JSON parsed — trust it, don't fall through to text heuristics

    # --- Strict text fallback (only if JSON wasn't available). ---
    negative_markers = (
        "no vulnerable", "not vulnerable", "no misconfig", "not found",
        "0 vulnerable", "nothing found", "no instance",
    )
    progress_markers = ("checking", "possible target", "scanning", "loading", "trying")
    positive_markers = (
        "is vulnerable", "misconfigured", "vulnerable instance found",
        "found a vulnerable", "open signup", "exposed instance", "detected a misconfig",
    )
    for line in stdout.splitlines():
        text = line.strip()
        low = text.lower()
        if not text:
            continue
        if any(m in low for m in negative_markers) or any(m in low for m in progress_markers):
            continue
        if not any(m in low for m in positive_markers):
            continue
        findings.append(_finding(text, text))
    return findings


# A "literal credential" is a hardcoded, non-templated secret value found in a request's
# headers/auth — NOT a Postman variable like ``{{auth_token}}``. We look for values that pair a
# credential-ish key (authorization/token/apikey/secret/…) with a value that (a) isn't a
# ``{{...}}`` placeholder and (b) looks like a real secret (long, high-entropy-ish token, or a
# Bearer/Basic/Token scheme carrying such a value).
_CRED_KEY_RE = re.compile(r"(authorization|api[-_]?key|x-api-key|token|secret|access[-_]?token|"
                          r"client[-_]?secret|password|bearer)", re.I)
_TEMPLATE_RE = re.compile(r"\{\{.*?\}\}")               # Postman variable, e.g. {{auth_token}}
# A literal secret-looking value: an optional scheme word then a 20+ char token of secret-y
# characters (letters/digits/_-.+/=), no spaces, not a pure URL.
_LITERAL_SECRET_RE = re.compile(
    r"(?:^|\b)(?:bearer|token|basic|apikey|api_key)?\s*([A-Za-z0-9_\-\.\+/=]{20,})\s*$", re.I)
_HOST_RE = re.compile(r"https?://([a-zA-Z0-9][a-zA-Z0-9.\-]*[a-zA-Z0-9])(?::\d+)?", re.I)


def _looks_literal_secret(value: str) -> str | None:
    """Return the literal secret token in *value* if it's a hardcoded (non-templated) secret,
    else ``None``. Rejects Postman ``{{variable}}`` placeholders and short/empty values."""
    v = (value or "").strip()
    if not v or _TEMPLATE_RE.search(v):
        return None
    m = _LITERAL_SECRET_RE.search(v)
    if not m:
        return None
    token = m.group(1)
    # Guard against obvious non-secrets that pass the length filter (URLs, content types).
    if "://" in token or "/" in token and "." in token and len(token) < 40:
        return None
    return token


def _postman_hostnames(node, out: set[str]) -> None:
    """Collect hostnames from every ``url`` string anywhere in the Postman JSON tree."""
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, str) and (k.lower() in ("raw", "url", "host") or "://" in v):
                for hm in _HOST_RE.finditer(v):
                    out.add(hm.group(1).lower())
            else:
                _postman_hostnames(v, out)
    elif isinstance(node, list):
        for item in node:
            _postman_hostnames(item, out)
    elif isinstance(node, str) and "://" in node:
        for hm in _HOST_RE.finditer(node):
            out.add(hm.group(1).lower())


def _first_url(node) -> str:
    """Return the first request URL string found under *node* (raw > url > any '://' string)."""
    if isinstance(node, dict):
        raw = node.get("url")
        if isinstance(raw, dict):
            r = raw.get("raw")
            if isinstance(r, str) and "://" in r:
                return r
        if isinstance(raw, str) and "://" in raw:
            return raw
        for v in node.values():
            found = _first_url(v)
            if found:
                return found
    elif isinstance(node, list):
        for item in node:
            found = _first_url(item)
            if found:
                return found
    return ""


def _postman_literal_creds(node, out: list[dict]) -> None:
    """Find hardcoded credential values in headers/auth across the Postman JSON tree.

    Appends a dict ``{request, key, token, url}`` for each literal (non-templated) secret.
    Handles the header shape ``{"key": "Authorization", "value": "Token <literal>"}`` and
    cred-ish string values. ``request``/``url`` are best-effort from the nearest enclosing
    request item.
    """
    def _scan(n, req_name: str, req_url: str) -> None:
        if isinstance(n, dict):
            name = str(n.get("name") or req_name or "").strip() or req_name
            # If this dict is (or contains) a request, capture its URL for the children.
            url = req_url or _first_url(n)
            key = n.get("key")
            val = n.get("value")
            if isinstance(key, str) and isinstance(val, str) and _CRED_KEY_RE.search(key):
                token = _looks_literal_secret(val)
                if token:
                    out.append({"request": name, "key": key, "token": token, "url": url})
            for k, v in n.items():
                if isinstance(v, str) and _CRED_KEY_RE.search(k):
                    token = _looks_literal_secret(v)
                    if token:
                        out.append({"request": name, "key": k, "token": token, "url": url})
                else:
                    _scan(v, name, url)
        elif isinstance(n, list):
            for item in n:
                _scan(item, req_name, req_url)
    _scan(node, "", "")


def parse_porch_pirate(stdout: str, source: str = "porch-pirate",
                       target: str = "") -> tuple[list[Finding], list[Subdomain]]:
    """Parse porch-pirate ``--raw`` JSON into per-workspace + per-credential findings, plus any
    hostnames leaking in request URLs.

    Returns ``(findings, subdomains)``:
      * one workspace finding per public Postman workspace referencing the target;
      * one HIGH-severity finding per HARDCODED credential found in a request's headers/auth
        (literal values only — Postman ``{{variable}}`` placeholders are ignored), with the
        value masked the same way as secret findings elsewhere;
      * every hostname appearing in a request URL is returned as a discovered subdomain (real
        infrastructure that often appears nowhere else in OSINT output).
    Non-JSON output yields nothing rather than a line-by-line text dump.
    """
    findings: list[Finding] = []
    subs: list[Subdomain] = []
    seen: set[str] = set()

    def _walk(node) -> list[dict]:
        """Collect workspace/collection-like dicts from arbitrary nested JSON."""
        out: list[dict] = []
        if isinstance(node, dict):
            if node.get("id") and any(k in node for k in ("name", "slug", "type", "publicHandle")):
                out.append(node)
            for v in node.values():
                out.extend(_walk(v))
        elif isinstance(node, list):
            for item in node:
                out.extend(_walk(item))
        return out

    doc = try_load_json(stdout)
    if doc is None:
        return findings, subs

    for ws in _walk(doc):
        ws_id = str(ws.get("id", "")).strip()
        if not ws_id or ws_id in seen:
            continue
        seen.add(ws_id)
        name = str(ws.get("name") or ws.get("slug") or "workspace").strip()
        desc = " ".join(str(ws.get("description", "")).split())
        if len(desc) > 160:
            desc = desc[:157] + "…"
        blob = json.dumps(ws).lower() if isinstance(ws, dict) else str(ws).lower()
        leaky = any(k in blob for k in ("apikey", "api_key", "token", "secret", "bearer", "authorization", "password"))
        relevance = assess_target_relevance(blob, target) if target else "direct"
        confidence = _cap_for_relevance(
            Confidence.FIRM if leaky else Confidence.TENTATIVE, relevance)
        findings.append(Finding(
            title="Potential API leak in public Postman workspace" if leaky
                  else "Public Postman workspace references target",
            category="api-leak",
            severity=Severity.HIGH if leaky else Severity.LOW,
            confidence=confidence,
            target=f"{name} ({ws_id})"[:200],
            tool=source,
            description=(f"Public Postman workspace '{name}'"
                        + (f": {desc}" if desc else "") + "."
                        + _relevance_note(relevance, target)),
            evidence=desc[:300],
            raw=json.dumps(ws)[:800],
        ))

    # (1) Hardcoded credentials embedded in request headers/auth — each its own HIGH finding.
    # The finding carries STRUCTURED detail in ``evidence`` as newline-separated ``Label: value``
    # lines so the UI can render it as a spacious card (never truncated), while ``description``
    # stays a one-line human summary. The full unmasked token lives only in ``raw``.
    creds: list[dict] = []
    _postman_literal_creds(doc, creds)
    seen_creds: set[str] = set()
    for c in creds:
        token = c["token"]
        if token in seen_creds:
            continue
        seen_creds.add(token)
        req_name, key, url = c.get("request", ""), c.get("key", ""), c.get("url", "")
        masked = mask_secret(token)
        detail_lines = []
        if req_name:
            detail_lines.append(f"Request: {req_name}")
        detail_lines.append(f"Header:  {key}")
        detail_lines.append(f"Value:   {masked}")
        if url:
            detail_lines.append(f"URL:     {url}")
        findings.append(Finding(
            title="Hardcoded API credential in public Postman request",
            category="secret",
            severity=Severity.HIGH,
            confidence=Confidence.FIRM,
            target=(f"postman:{req_name or key}")[:200],
            tool=source,
            description=(f"A literal (non-templated) credential is hardcoded in the "
                         f"'{key}' header of "
                         + (f"request '{req_name}'" if req_name else "a Postman request")
                         + f". Value: {masked}."),
            evidence="\n".join(detail_lines)[:600],
            raw=f"{req_name} | {key} | {url} | {token}"[:600],
        ))

    # (2) Hostnames leaking in request URLs -> discovered subdomains (feed Part 2).
    hosts: set[str] = set()
    _postman_hostnames(doc, hosts)
    for host in sorted(hosts):
        if "." not in host or host in ("localhost",):
            continue
        # Keep only real hostnames; if a target is known, keep on-domain hosts (the valuable
        # ones), but also keep any FQDN so nothing is silently dropped.
        subs.append(Subdomain(hostname=host, source="postman"))
    return findings, subs


def parse_swaggerspy(stdout: str, source: str = "SwaggerSpy",
                     target: str = "") -> tuple[list[Finding], list[Subdomain]]:
    """Parse SwaggerSpy output (exposed Swagger/OpenAPI specs) into findings + subdomains.

    Exposed API documentation reveals endpoints, parameters and sometimes embedded creds.
    We treat each discovered spec URL as an informational finding (endpoint-surface), bump
    severity when the line hints at secrets, and extract the spec's hostname as a discovered
    subdomain (real infrastructure).

    SwaggerSpy searches by the target name, so a spec URL may belong to an unrelated host.
    When *target* is given we grade the spec URL's tie to it: a spec hosted on the target
    domain keeps its confidence; one that only matches the base keyword is capped at
    TENTATIVE and flagged.
    """
    findings: list[Finding] = []
    subs_seen: set[str] = set()
    subs: list[Subdomain] = []
    seen: set[str] = set()
    url_re = re.compile(r"https?://[^\s\"'<>]+")
    for line in stdout.splitlines():
        text = line.strip()
        low = text.lower()
        m = url_re.search(text)
        if not m:
            continue
        if "swagger" not in low and "openapi" not in low and "api-docs" not in low and "api/docs" not in low:
            continue
        url = m.group(0).rstrip(".,)")
        # Extract the spec's hostname as a discovered subdomain.
        hm = _HOST_RE.match(url)
        if hm:
            host = hm.group(1).lower()
            if "." in host and host not in subs_seen:
                subs_seen.add(host)
                subs.append(Subdomain(hostname=host, source="swaggerspy"))
        if url in seen:
            continue
        seen.add(url)
        leaky = any(k in low for k in ("key", "token", "secret", "password", "credential"))
        relevance = assess_target_relevance(url, target) if target else "direct"
        confidence = _cap_for_relevance(Confidence.FIRM, relevance)
        findings.append(Finding(
            title="Exposed API secret in Swagger/OpenAPI" if leaky
                  else "Exposed Swagger/OpenAPI documentation",
            category="api-leak",
            severity=Severity.HIGH if leaky else Severity.INFO,
            confidence=confidence,
            target=url[:200],
            tool=source,
            description="SwaggerSpy found exposed API documentation for the target."
                        + _relevance_note(relevance, target),
            evidence=text[:300],
            raw=text[:500],
        ))
    return findings, subs


def parse_gato(output: str, source: str = "gato") -> list[Finding]:
    """Parse gato output (GitHub Actions security audit) into findings.

    gato audits an org/repo's GitHub Actions for self-hosted-runner takeover, secret leaks,
    and injection. Prefers gato's structured JSON (``--output-json``): repos may carry
    ``sh_workflow_names``/``self_hosted_workflows`` (self-hosted runners), ``secrets``/
    ``org_secrets`` (accessible secrets), and ``pwn_requests``/``injection`` findings. Falls
    back to parsing the text report (``[!]`` markers) when JSON isn't available.
    """
    findings: list[Finding] = []

    doc = try_load_json(output)
    if doc is not None:
        # gato JSON is org-shaped: {"organization":..,"repositories":[{...}]} (version-variant).
        repos = []
        if isinstance(doc, dict):
            repos = doc.get("repositories") or doc.get("repos") or []
        elif isinstance(doc, list):
            repos = doc
        for repo in repos:
            if not isinstance(repo, dict):
                continue
            name = repo.get("name") or repo.get("repo_name") or "repo"
            if repo.get("self_hosted_workflows") or repo.get("sh_workflow_names") \
                    or repo.get("runners"):
                findings.append(Finding(
                    title="GitHub Actions self-hosted runner exposure",
                    category="ci-cd", severity=Severity.HIGH, confidence=Confidence.FIRM,
                    target=str(name), tool=source,
                    description="Repository uses self-hosted runners (possible RCE/takeover).",
                    raw=str(repo)[:800],
                ))
            for sec in (repo.get("secrets") or []) + (repo.get("org_secrets") or []):
                findings.append(Finding(
                    title="Accessible GitHub Actions secret",
                    category="ci-cd", severity=Severity.HIGH, confidence=Confidence.FIRM,
                    target=f"{name}:{sec if isinstance(sec, str) else sec.get('name','secret')}",
                    tool=source, description="Secret reachable via workflow scope.",
                    raw=str(sec)[:400],
                ))
            for pwn in (repo.get("pwn_requests") or []) + (repo.get("injection") or []):
                findings.append(Finding(
                    title="GitHub Actions injection / pwn-request risk",
                    category="ci-cd", severity=Severity.HIGH, confidence=Confidence.TENTATIVE,
                    target=str(name), tool=source,
                    description="Workflow may be vulnerable to injection / pwn-request.",
                    raw=str(pwn)[:400],
                ))
        if findings:
            return findings
        # JSON parsed but no issues found -> return empty (clean audit), don't fall through.
        return findings

    # --- text fallback ---
    for line in output.splitlines():
        text = line.strip()
        low = text.lower()
        if not text:
            continue
        flagged = text.startswith("[!]") or "vulnerable" in low or "injection" in low \
            or "self-hosted" in low or "secret" in low or "misconfig" in low
        if not flagged:
            continue
        high = "injection" in low or "self-hosted" in low or "takeover" in low
        findings.append(Finding(
            title="GitHub Actions security issue",
            category="ci-cd",
            severity=Severity.HIGH if high else Severity.MEDIUM,
            confidence=Confidence.TENTATIVE,
            target=text[:200],
            tool=source,
            description="gato flagged a GitHub Actions workflow security issue.",
            evidence=text[:300],
            raw=text[:500],
        ))
    return findings


# Scopes gato needs to actually enumerate a target org's repos/secrets.
_GATO_REQUIRED_SCOPES = ("repo", "admin:org")


def diagnose_gato_no_findings(output: str, org: str = "") -> str:
    """Explain WHY a gato run surfaced nothing, from its own JSON — not a canned guess.

    gato's JSON reports the token's ``scopes`` and the user's relationship to the org
    (``org_admin_user`` / ``org_member``). The common false diagnosis is "token lacks scope"
    when the real reason is that the authenticated user simply isn't a MEMBER of the target
    org (so GitHub returns nothing regardless of scope). We check scope first, then membership:

      * missing a required scope        -> "token is missing scope(s): …"
      * has scope but not an org member -> "authenticated as a non-member of org X …"
      * otherwise                       -> a neutral "no accessible … (org is clean or private)".
    """
    doc = try_load_json(output)
    scopes: list[str] = []
    org_member = org_admin = None
    if isinstance(doc, dict):
        raw_scopes = doc.get("scopes") or doc.get("token_scopes") or []
        if isinstance(raw_scopes, str):
            raw_scopes = [s.strip() for s in raw_scopes.split(",")]
        scopes = [str(s).strip().lower() for s in raw_scopes if s]
        # membership flags may live at the top level or under an org block
        for src in (doc, doc.get("organization") or {}, doc.get("org") or {}):
            if isinstance(src, dict):
                if org_member is None and "org_member" in src:
                    org_member = bool(src.get("org_member"))
                if org_admin is None and "org_admin_user" in src:
                    org_admin = bool(src.get("org_admin_user"))

    org_txt = f" {org}" if org else ""
    if scopes:
        missing = [s for s in _GATO_REQUIRED_SCOPES if s not in scopes]
        if missing:
            return (f"no findings — token is missing scope(s): {', '.join(missing)} "
                    f"(has: {', '.join(scopes)})")
    # Scope is fine (or unknown). If we know the user isn't a member/admin of the org, that's
    # the real cause — not scope.
    if org_member is False and not org_admin:
        return (f"no findings — authenticated as a non-member of org{org_txt}; "
                f"no accessible repo/org secrets (token scope is sufficient)")
    if scopes:
        return (f"no findings — org{org_txt} appears clean or private to this token "
                f"(scopes ok: {', '.join(scopes)})")
    return f"no findings — could not determine cause from gato output (org{org_txt})"
