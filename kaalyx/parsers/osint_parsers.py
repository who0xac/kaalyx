"""Parsers for the tool outputs consumed by the OSINT stage.

Kept deliberately defensive: each function accepts a tool's raw stdout and returns
normalised models, skipping anything it doesn't recognise. Tool output formats drift over
versions, so we read the fields we need and ignore the rest rather than asserting a
schema.
"""

from __future__ import annotations

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


def parse_trufflehog(stdout: str, source: str = "trufflehog") -> list[Finding]:
    """Parse ``trufflehog --json`` output into secret findings.

    trufflehog v3 emits one JSON object per detected secret with ``DetectorName``,
    ``Verified``, ``Raw``, and a ``SourceMetadata`` block. Verified secrets are treated as
    higher severity/confidence than unverified ones.
    """
    findings: list[Finding] = []
    for obj in iter_json_lines(stdout):
        detector = obj.get("DetectorName") or obj.get("detector_name") or "secret"
        verified = bool(obj.get("Verified") or obj.get("verified"))
        raw_secret = obj.get("Raw") or obj.get("raw") or ""
        meta = obj.get("SourceMetadata") or {}
        # Best-effort extraction of a location string across trufflehog metadata shapes.
        location = ""
        data = meta.get("Data") if isinstance(meta, dict) else None
        if isinstance(data, dict):
            for block in data.values():
                if isinstance(block, dict):
                    location = (
                        block.get("repository")
                        or block.get("file")
                        or block.get("link")
                        or location
                    )
        findings.append(
            Finding(
                title=f"Exposed secret: {detector}",
                category="secret",
                severity=Severity.HIGH if verified else Severity.MEDIUM,
                confidence=Confidence.CONFIRMED if verified else Confidence.TENTATIVE,
                target=location or "github-org",
                tool=source,
                description=(
                    f"{detector} secret {'verified' if verified else 'detected'} by trufflehog."
                ),
                evidence=(raw_secret[:120] + "…") if len(raw_secret) > 120 else raw_secret,
                raw=str(obj)[:2000],
            )
        )
    return findings


def parse_s3scanner(stdout: str, source: str = "s3scanner") -> list[Finding]:
    """Parse s3scanner output into bucket findings.

    s3scanner prints lines describing bucket existence/permissions. We flag buckets that
    are reported as existing and (especially) open/listable.
    """
    findings: list[Finding] = []
    for line in stdout.splitlines():
        text = line.strip()
        low = text.lower()
        if not text or "not_exist" in low or "not exist" in low:
            continue
        if "bucket" not in low and "s3" not in low and "://" not in low:
            continue
        open_bucket = any(k in low for k in ("open", "public", "listable", "read", "write"))
        findings.append(
            Finding(
                title="S3 bucket exposure" if open_bucket else "S3 bucket discovered",
                category="cloud",
                severity=Severity.HIGH if open_bucket else Severity.INFO,
                confidence=Confidence.FIRM if open_bucket else Confidence.TENTATIVE,
                target=text[:200],
                tool=source,
                description="s3scanner reported this bucket.",
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


def parse_cloud_enum(stdout: str, source: str = "cloud_enum") -> list[Finding]:
    """Parse cloud_enum textual output into cloud-resource findings.

    cloud_enum prints ``[+] ...`` lines for found resources and flags open ones.
    """
    findings: list[Finding] = []
    for line in stdout.splitlines():
        text = line.strip()
        low = text.lower()
        if not text.startswith("[+]") and "found" not in low and "open" not in low:
            continue
        open_res = "open" in low or "public" in low
        findings.append(
            Finding(
                title="Open cloud resource" if open_res else "Cloud resource discovered",
                category="cloud",
                severity=Severity.MEDIUM if open_res else Severity.INFO,
                confidence=Confidence.TENTATIVE,
                target=text[:200],
                tool=source,
                description="cloud_enum reported this resource.",
                evidence=text[:300],
                raw=text[:500],
            )
        )
    return findings


def parse_theharvester(stdout_or_json: str, domain: str,
                       source: str = "theHarvester") -> tuple[list[Email], list[Employee], list[Subdomain]]:
    """Parse theHarvester JSON output into emails, employees, and subdomains.

    theHarvester (run with ``-f out.json``) writes a JSON document with keys such as
    ``emails``, ``hosts``, ``linkedin_people`` and ``twitter_people`` (reNgine reads the
    same fields). We read defensively and only keep on-domain emails.
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


def parse_h8mail(stdout_or_json: str, source: str = "h8mail") -> dict[str, tuple[int, str]]:
    """Parse h8mail JSON output into a map of email -> (breach_count, breach_detail).

    h8mail (run with ``--json out.json``) writes ``{"targets": [{"target": email,
    "pwn_num": N, "data": [...]}]}``. The stage uses this to enrich already-harvested
    emails with breach counts (reNgine's h8mail chaining), rather than as standalone rows.
    """
    result: dict[str, tuple[int, str]] = {}
    doc = try_load_json(stdout_or_json)
    if not isinstance(doc, dict):
        return result
    for target in doc.get("targets") or []:
        if not isinstance(target, dict):
            continue
        email = str(target.get("target", "")).strip().lower()
        if not email:
            continue
        count = int(target.get("pwn_num", 0) or 0)
        data = target.get("data") or []
        # `data` entries are typically "source:detail" strings; summarise the breach names.
        names = []
        for entry in data if isinstance(data, list) else []:
            text = str(entry)
            names.append(text.split(":")[0][:40])
        detail = ", ".join(dict.fromkeys(names))[:300]
        result[email] = (count, detail)
    return result


def parse_misconfig_mapper(stdout: str, source: str = "misconfig-mapper") -> list[Finding]:
    """Parse misconfig-mapper output (ReconFTW's third-party misconfig tool) into findings.

    misconfig-mapper reports third-party SaaS services that may be misconfigured for the
    target (e.g. an open Atlassian/Jira/GitHub org). Its text output marks hits with
    ``[+]``/``vulnerable``/``misconfigured``; we surface those as medium findings.
    """
    findings: list[Finding] = []
    for line in stdout.splitlines():
        text = line.strip()
        low = text.lower()
        if not text:
            continue
        hit = text.startswith("[+]") or "misconfig" in low or "vulnerable" in low or "exposed" in low
        if not hit:
            continue
        findings.append(
            Finding(
                title="Third-party service misconfiguration",
                category="third-party-misconfig",
                severity=Severity.MEDIUM,
                confidence=Confidence.TENTATIVE,
                target=text[:200],
                tool=source,
                description="misconfig-mapper flagged a third-party service.",
                evidence=text[:300],
                raw=text[:500],
            )
        )
    return findings


def parse_porch_pirate(stdout: str, source: str = "porch-pirate") -> list[Finding]:
    """Parse porch-pirate output (public Postman workspace/collection leaks) into findings.

    porch-pirate surfaces public Postman workspaces, collections and requests mentioning the
    target, which frequently embed API keys, bearer tokens and internal URLs. Output format
    varies by version (text or JSON), so we read defensively: JSON objects first, then any
    text line that references a Postman entity.
    """
    findings: list[Finding] = []
    seen: set[str] = set()

    def _add(target: str, evidence: str) -> None:
        key = target[:200]
        if key in seen:
            return
        seen.add(key)
        low = evidence.lower()
        leaky = any(k in low for k in ("key", "token", "secret", "authorization", "bearer", "password"))
        findings.append(Finding(
            title="Potential API leak in public Postman data" if leaky
                  else "Public Postman workspace/collection references target",
            category="api-leak",
            severity=Severity.HIGH if leaky else Severity.LOW,
            confidence=Confidence.TENTATIVE,
            target=target[:200],
            tool=source,
            description="porch-pirate found public Postman data referencing the target.",
            evidence=evidence[:400],
            raw=evidence[:800],
        ))

    for obj in iter_json_lines(stdout):
        ref = str(obj.get("url") or obj.get("id") or obj.get("name") or obj)[:200]
        _add(ref, str(obj)[:400])
    if not findings:
        for line in stdout.splitlines():
            text = line.strip()
            low = text.lower()
            if not text:
                continue
            if "postman" in low or "workspace" in low or "collection" in low or "getpostman" in low:
                _add(text, text)
    return findings


def parse_swaggerspy(stdout: str, source: str = "SwaggerSpy") -> list[Finding]:
    """Parse SwaggerSpy output (exposed Swagger/OpenAPI specs) into findings.

    Exposed API documentation reveals endpoints, parameters and sometimes embedded creds.
    We treat each discovered spec URL as an informational finding (endpoint-surface), and
    bump severity when the line hints at secrets.
    """
    findings: list[Finding] = []
    for line in stdout.splitlines():
        text = line.strip()
        low = text.lower()
        if not text:
            continue
        if "swagger" not in low and "openapi" not in low and "://" not in low:
            continue
        leaky = any(k in low for k in ("key", "token", "secret", "password", "credential"))
        findings.append(Finding(
            title="Exposed API secret in Swagger/OpenAPI" if leaky
                  else "Exposed Swagger/OpenAPI documentation",
            category="api-leak",
            severity=Severity.HIGH if leaky else Severity.INFO,
            confidence=Confidence.TENTATIVE,
            target=text[:200],
            tool=source,
            description="SwaggerSpy found exposed API documentation for the target.",
            evidence=text[:300],
            raw=text[:500],
        ))
    return findings


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
