"""In-process (keyless) OSINT sources implemented in Python rather than as external tools.

These cover OSINT items from Part 1 that have no single obvious CLI binary and are cleanly
doable over plain HTTP/DNS without an API key. The set was expanded after studying BBOT,
reNgine and ReconFTW:

* **Email / DNS security posture** — SPF and DMARC (missing/weak policies) plus the wider
  keyless DNS security records BBOT checks: CAA, BIMI, MTA-STS and TLS-RPT. Resolved via
  DNS-over-HTTPS (Cloudflare, then Google) so no local resolver tool is required.
* **M365 / Azure tenant mapping** — Microsoft's public, unauthenticated endpoints:
  ``getuserrealm`` (managed/federated + brand), the ODC ``federationprovider`` endpoint
  (tenant id + brand — BBOT's current keyless method), and OpenID metadata (tenant GUID).
  The old SOAP ``GetFederationInformation`` tenant-domain trick is deliberately NOT used:
  Microsoft patched it on 2025-05-23 (MC1081538) and it no longer returns tenant domains.
* **Keyless email harvesting** — query email-format.com (BBOT's ``emailformat`` approach)
  and skymem.info for addresses at the domain. No API key needed.
* **Categorised Google dork generation** — ready-to-click Google search URLs grouped by
  purpose (login/admin/config/git/db/docs/cloud), inspired by reNgine's dork taxonomy.
  No scraping (ToS/CAPTCHA/ban risk); the user reviews these manually.

Breach/credential lookup remains key-dependent and is handled by the stage: harvested
emails are the input, and the lookup is skipped cleanly when no breach API key is present.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field

import httpx

from ..core.logging import get_logger
from ..data.models import Confidence, Email, Finding, OsintRecord, Severity

logger = get_logger("osint.inproc")

_DOH_ENDPOINTS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
]

# DNS record type numbers we read via DoH.
_TXT, _CAA = 16, 257

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


async def _doh_query(domain: str, rtype: str) -> list[dict]:
    """Low-level DoH query returning raw Answer dicts (empty on failure)."""
    async with httpx.AsyncClient(timeout=15, headers={"accept": "application/dns-json"}) as client:
        for endpoint in _DOH_ENDPOINTS:
            try:
                resp = await client.get(endpoint, params={"name": domain, "type": rtype})
                if resp.status_code != 200:
                    continue
                data = resp.json()
                answers = data.get("Answer") or []
                if answers:
                    return answers
            except (httpx.HTTPError, ValueError, KeyError) as exc:
                logger.debug("DoH %s (%s) failed for %s: %s", endpoint, rtype, domain, exc)
                continue
    return []


async def resolve_txt(domain: str) -> list[str]:
    """Resolve TXT records for *domain* via DNS-over-HTTPS, trying providers in order.

    Returns the list of TXT strings (quotes stripped). Empty list on total failure —
    callers treat "no records" and "lookup failed" the same benign way.
    """
    answers = await _doh_query(domain, "TXT")
    out: list[str] = []
    for ans in answers:
        if ans.get("type") != _TXT:
            continue
        value = str(ans.get("data", "")).strip()
        # DoH returns TXT wrapped in quotes, possibly concatenated segments.
        value = value.replace('" "', "").strip('"')
        if value:
            out.append(value)
    return out


async def check_mail_dns_security(
    domain: str,
) -> tuple[list[OsintRecord], list[Finding], list[Email]]:
    """Assess *domain*'s email/DNS security posture (keyless DNS lookups).

    Covers SPF and DMARC (the classic anti-spoofing pair) plus the wider keyless DNS
    security records BBOT checks — CAA (certificate issuance control), BIMI, MTA-STS and
    TLS-RPT. Records are stored for the dashboard; only genuinely weak/missing anti-spoofing
    posture produces findings (we don't cry wolf about optional records like BIMI).

    Findings raised:
      * missing SPF (low: email spoofing surface),
      * SPF ``+all``/``?all`` (low: permissive),
      * missing DMARC (low),
      * DMARC ``p=none`` (info: monitoring-only, no enforcement),
      * missing CAA (info: any CA may issue certs for the domain).

    Returns ``(records, findings, emails)`` — ``emails`` are any ``iodef:mailto:`` contact
    addresses extracted from CAA records (BBOT dnscaa), for the harvest/breach chain.
    """
    records: list[OsintRecord] = []
    findings: list[Finding] = []
    source = "mail_dns"

    # --- SPF ---
    txts = await resolve_txt(domain)
    spf = next((t for t in txts if t.lower().startswith("v=spf1")), None)
    if spf:
        records.append(OsintRecord(kind="spf", value=spf, source=source))
        # Match the `all` mechanism's qualifier anywhere in the record. A bare `all` with no
        # qualifier defaults to `+all` (pass), so it is permissive too.
        all_match = re.search(r"(?:^|\s)([+?~-]?)all(?:\s|$)", spf.lower())
        qualifier = all_match.group(1) if all_match else ""
        if all_match and qualifier in ("+", "?", ""):
            shown = f"{qualifier}all" if qualifier else "all (defaults to +all)"
            findings.append(
                Finding(
                    title="Weak SPF policy (permissive 'all')",
                    category="email-security",
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    target=domain,
                    tool=source,
                    description=f"SPF allows unlisted senders ({shown}), weakening anti-spoofing.",
                    evidence=spf,
                )
            )
    else:
        findings.append(
            Finding(
                title="Missing SPF record",
                category="email-security",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                target=domain,
                tool=source,
                description="No SPF (v=spf1) TXT record found; increases email-spoofing surface.",
            )
        )

    # --- DMARC ---
    dmarc_txts = await resolve_txt(f"_dmarc.{domain}")
    dmarc = next((t for t in dmarc_txts if t.lower().startswith("v=dmarc1")), None)
    if dmarc:
        records.append(OsintRecord(kind="dmarc", value=dmarc, source=source))
        low = dmarc.lower()
        if "p=none" in low:
            findings.append(
                Finding(
                    title="DMARC policy is p=none (monitoring only)",
                    category="email-security",
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    target=domain,
                    tool=source,
                    description="DMARC is present but not enforcing (p=none); spoofed mail is not rejected/quarantined.",
                    evidence=dmarc,
                )
            )
    else:
        findings.append(
            Finding(
                title="Missing DMARC record",
                category="email-security",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                target=domain,
                tool=source,
                description="No DMARC (_dmarc TXT) record found; domain lacks a published anti-spoofing policy.",
            )
        )

    # --- CAA (certificate issuance control) ---
    caa_answers = await _doh_query(domain, "CAA")
    caa_values = [str(a.get("data", "")).strip() for a in caa_answers if a.get("type") == _CAA]
    caa_values = [v for v in caa_values if v]
    caa_emails: list[Email] = []
    if caa_values:
        for v in caa_values:
            records.append(OsintRecord(kind="caa", value=v, source=source))
            # BBOT dnscaa: a CAA `iodef` violation-reporting destination often exposes an
            # internal contact email (or URL). Extract mailto: addresses as harvested emails
            # so they feed the breach/leak lookups — an on-domain address here is real OSINT.
            for m in re.findall(r"mailto:([^\s\"';]+@[^\s\"';]+)", v, re.IGNORECASE):
                addr = m.strip().lower().strip(".")
                if "@" in addr:
                    caa_emails.append(Email(address=addr, source="caa-iodef"))
    else:
        findings.append(
            Finding(
                title="No CAA record",
                category="email-security",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                target=domain,
                tool=source,
                description="No CAA record: any CA may issue certificates for this domain.",
            )
        )

    # --- BIMI / MTA-STS / TLS-RPT (informational presence checks) ---
    for label, kind in (
        (f"default._bimi.{domain}", "bimi"),
        (f"_mta-sts.{domain}", "mta_sts"),
        (f"_smtp._tls.{domain}", "tls_rpt"),
    ):
        txt = await resolve_txt(label)
        prefix = {"bimi": "v=bimi1", "mta_sts": "v=stsv1", "tls_rpt": "v=tlsrptv1"}[kind]
        hit = next((t for t in txt if t.lower().startswith(prefix)), None)
        if hit:
            records.append(OsintRecord(kind=kind, value=hit, source=source))
            # TLS-RPT (and MTA-STS) records carry rua/mailto reporting addresses (BBOT
            # dnstlsrpt) — harvest any so they feed the email → breach/leak chain.
            for m in re.findall(r"mailto:([^\s\"';,!]+@[^\s\"';,!]+)", hit, re.IGNORECASE):
                addr = m.strip().lower().strip(".")
                if "@" in addr:
                    caa_emails.append(Email(address=addr, source=f"{kind}-rua"))

    return records, findings, caa_emails


# Backwards-compatible alias (older name used before the DNS-security expansion).
check_spf_dmarc = check_mail_dns_security


async def map_m365_tenant(domain: str) -> tuple[list[OsintRecord], list[Finding]]:
    """Map a domain to a Microsoft 365 / Entra ID tenant via public endpoints.

    Uses three unauthenticated Microsoft endpoints:
      * ``getuserrealm.srf`` — reveals whether the namespace is Managed/Federated and,
        for federated domains, the federation brand/auth URL.
      * OpenID configuration (``login.microsoftonline.com/<domain>/.well-known/...``) —
        reveals the tenant GUID when the domain is a Microsoft tenant.
      * ODC ``federationprovider`` (``odc.officeapps.live.com``) — BBOT's current keyless
        method; returns the tenant id and federation brand reliably. The old SOAP
        ``GetFederationInformation`` domain-enumeration trick is intentionally not used
        (Microsoft patched it 2025-05-23, MC1081538).
    """
    records: list[OsintRecord] = []
    findings: list[Finding] = []

    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        # 1) User realm.
        try:
            probe_user = urllib.parse.quote(f"info@{domain}")
            resp = await client.get(
                "https://login.microsoftonline.com/getuserrealm.srf",
                params={"login": probe_user, "xml": "1"},
            )
            if resp.status_code == 200 and resp.text:
                text = resp.text
                ns_type = _xml_value(text, "NameSpaceType")
                if ns_type and ns_type.lower() != "unknown":
                    records.append(
                        OsintRecord(
                            kind="m365",
                            value=f"{domain} namespace: {ns_type}",
                            detail=ns_type,
                            source="m365",
                        )
                    )
                    if ns_type.lower() == "federated":
                        auth_url = _xml_value(text, "AuthURL") or ""
                        brand = _xml_value(text, "FederationBrandName") or ""
                        records.append(
                            OsintRecord(
                                kind="m365",
                                value=f"{domain} federated via {brand}",
                                detail=auth_url,
                                source="m365",
                            )
                        )
                        findings.append(
                            Finding(
                                title="Microsoft 365 domain is federated",
                                category="tenant-mapping",
                                severity=Severity.INFO,
                                confidence=Confidence.CONFIRMED,
                                target=domain,
                                tool="m365",
                                description=f"Federated identity ({brand}); auth at {auth_url}.",
                                evidence=auth_url,
                            )
                        )
        except (httpx.HTTPError, ValueError) as exc:
            logger.debug("getuserrealm failed for %s: %s", domain, exc)

        # 2) OpenID metadata -> tenant GUID.
        try:
            resp = await client.get(
                f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"
            )
            if resp.status_code == 200:
                data = resp.json()
                issuer = data.get("issuer", "")
                # issuer looks like https://sts.windows.net/<tenant-guid>/
                tenant_id = issuer.rstrip("/").split("/")[-1] if issuer else ""
                if tenant_id:
                    records.append(
                        OsintRecord(
                            kind="m365",
                            value=f"{domain} tenant id: {tenant_id}",
                            detail=issuer,
                            source="m365",
                        )
                    )
                    findings.append(
                        Finding(
                            title="Microsoft 365 / Entra ID tenant identified",
                            category="tenant-mapping",
                            severity=Severity.INFO,
                            confidence=Confidence.CONFIRMED,
                            target=domain,
                            tool="m365",
                            description=f"Domain is backed by Microsoft tenant {tenant_id}.",
                            evidence=issuer,
                        )
                    )
        except (httpx.HTTPError, ValueError) as exc:
            logger.debug("openid-config failed for %s: %s", domain, exc)

        # 3) ODC federationprovider -> tenant id + brand (BBOT's current keyless method).
        try:
            resp = await client.get(
                "https://odc.officeapps.live.com/odc/v2.1/federationprovider",
                params={"domain": domain},
            )
            if resp.status_code == 200:
                data = resp.json()
                tenant_id = data.get("tenantId") or data.get("TenantId") or ""
                brand = data.get("FederationBrandName") or data.get("brandName") or ""
                already = any(tenant_id and tenant_id in r.value for r in records)
                if tenant_id and not already:
                    records.append(
                        OsintRecord(
                            kind="m365",
                            value=f"{domain} tenant id: {tenant_id}",
                            detail=f"ODC federationprovider; brand={brand}",
                            source="m365",
                        )
                    )
                elif brand:
                    records.append(
                        OsintRecord(
                            kind="m365",
                            value=f"{domain} federation brand: {brand}",
                            detail="ODC federationprovider",
                            source="m365",
                        )
                    )
        except (httpx.HTTPError, ValueError) as exc:
            logger.debug("ODC federationprovider failed for %s: %s", domain, exc)

        # 4) Extra tenant domains — other domains registered to the SAME tenant.
        #    Uses azmap.dev (the current keyless source BBOT's azure_tenant relies on).
        #    The old SOAP GetFederationInformation domain list was patched (2025-05-23).
        try:
            resp = await client.get(
                "https://azmap.dev/api/tenant",
                params={"domain": domain, "extract": "true"},
            )
            if resp.status_code == 200:
                data = resp.json()
                other = data.get("email_domains") or data.get("domains") or []
                extra = sorted(
                    {str(d).lower().strip() for d in other
                     if str(d).lower().strip() and str(d).lower().strip() != domain}
                )
                if extra:
                    for d in extra:
                        records.append(OsintRecord(
                            kind="m365", value=f"tenant domain: {d}",
                            detail="same Azure/M365 tenant (azmap.dev)", source="m365",
                        ))
                    findings.append(Finding(
                        title=f"{len(extra)} additional domain(s) in the same M365 tenant",
                        category="tenant-mapping",
                        severity=Severity.INFO,
                        confidence=Confidence.FIRM,
                        target=domain,
                        tool="m365",
                        description="Other domains share this Azure/Entra tenant — expands scope.",
                        evidence=", ".join(extra[:20]),
                    ))
        except (httpx.HTTPError, ValueError) as exc:
            logger.debug("azmap.dev tenant-domain lookup failed for %s: %s", domain, exc)

    return records, findings


def assess_spoofability(spf: str | None, dmarc: str | None) -> tuple[bool, str]:
    """Combine SPF + DMARC (incl. subdomain policy ``sp=`` and alignment) into a single
    "is this domain spoofable?" verdict, implementing MattKeeley/Spoofy's core logic.

    This does NOT do its own DNS lookup — it is layered on the SPF/DMARC records that
    ``check_mail_dns_security`` already fetched (passed in), so we never duplicate the query.

    Returns ``(spoofable, reason)``. The reasoning mirrors Spoofy's decision table: a domain
    is protected only when SPF is restrictive AND DMARC enforces (p=quarantine/reject) with
    aligned policy; permissive/missing SPF, or DMARC at p=none / missing / sp=none, leaves it
    spoofable (organizational or subdomain spoofing).
    """
    spf_l = (spf or "").lower()
    dmarc_l = (dmarc or "").lower()

    def _kv(record: str, key: str) -> str:
        for part in record.replace(" ", "").split(";"):
            if part.startswith(key + "="):
                return part[len(key) + 1:]
        return ""

    has_spf = spf_l.startswith("v=spf1")
    spf_all = ""
    for token in ("-all", "~all", "?all", "+all"):
        if token in spf_l:
            spf_all = token
            break

    has_dmarc = dmarc_l.startswith("v=dmarc1")
    p = _kv(dmarc_l, "p")
    sp = _kv(dmarc_l, "sp") or p  # sp defaults to the org policy p when absent

    # No DMARC (or p=none) => organisational spoofing is possible regardless of SPF.
    if not has_dmarc:
        return True, "no DMARC record — organisational spoofing possible"
    if p in ("", "none"):
        return True, "DMARC p=none (not enforcing) — organisational spoofing possible"
    # DMARC enforces on the org domain. Check subdomain policy for subdomain spoofing.
    if sp == "none":
        return True, f"DMARC p={p} but sp=none — subdomain spoofing possible"
    # Enforcing org + subdomain policy. Weak/absent SPF still eases delivery but DMARC blocks.
    if not has_spf:
        return False, f"DMARC enforcing (p={p}, sp={sp}) despite missing SPF"
    if spf_all in ("+all", "?all"):
        return False, f"SPF permissive ({spf_all}) but DMARC enforcing (p={p}, sp={sp})"
    return False, f"protected: SPF {spf_all or 'present'} + DMARC p={p}, sp={sp}"


async def check_exposed_git(host: str) -> Finding | None:
    """Detect a publicly exposed ``/.git/`` directory on *host* (detect-only, no download).

    Uses BBOT ``git.py``'s reliable confirmation: GET ``/.git/config``, and only report if
    the response is HTTP 200, the body contains the ``[core]`` git-config marker, and the
    body is not HTML (guards against soft-404 pages that return 200 with a page). Reported as
    HIGH/FIRM — an exposed .git typically allows full source-code reconstruction.

    *host* is a bare hostname; both https and http are tried.
    """
    html_re = re.compile(r"<html|<body", re.IGNORECASE)
    async with httpx.AsyncClient(timeout=15, follow_redirects=True,
                                 headers={"user-agent": "Mozilla/5.0 (Kaalyx OSINT)"}) as client:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/.git/config"
            try:
                resp = await client.get(url)
            except httpx.HTTPError as exc:
                logger.debug("exposed-git probe failed for %s: %s", url, exc)
                continue
            if resp.status_code != 200:
                continue
            body = resp.text
            if "[core]" not in body:
                continue
            if html_re.search(body):
                continue  # soft-404 / HTML page, not a real .git/config
            return Finding(
                title="Exposed .git directory",
                category="exposed-git",
                severity=Severity.HIGH,
                confidence=Confidence.FIRM,
                target=url,
                tool="exposed_git",
                description="A publicly readable /.git/config was found; the repository "
                            "(and full source history) may be reconstructable.",
                evidence=body.strip()[:200],
            )
    return None


async def harvest_emails(domain: str) -> list[Email]:
    """Keyless email harvesting from email-format.com and skymem.info.

    Mirrors BBOT's ``emailformat`` module (querying email-format.com, decoding Cloudflare
    ``data-cfemail`` obfuscation) plus a skymem.info pass. Both are free/keyless. Any HTTP
    failure is swallowed and simply yields fewer results — never an error.

    Returns the list of :class:`Email`; emails are persisted to their own table (not
    mirrored as generic OSINT rows) so counts stay honest.
    """
    found: dict[str, str] = {}  # address -> source(s)

    def _add(addr: str, src: str) -> None:
        addr = addr.strip().lower().strip(".")
        if not addr or "@" not in addr:
            return
        local, _, host = addr.partition("@")
        # Reject malformed local parts (empty, leading/trailing dot, consecutive dots) and
        # placeholder patterns where the local part is the domain itself — these are template
        # artifacts from the source pages, not real addresses.
        if not local or local.startswith(".") or local.endswith(".") or ".." in local:
            return
        if local == domain or local == host:
            return
        # Keep only addresses actually at the target domain (or a subdomain of it).
        if not (host == domain or host.endswith("." + domain)):
            return
        if addr in found:
            if src not in found[addr]:
                found[addr] = f"{found[addr]},{src}"
        else:
            found[addr] = src

    async with httpx.AsyncClient(timeout=20, follow_redirects=True,
                                 headers={"user-agent": "Mozilla/5.0 (Kaalyx OSINT)"}) as client:
        # --- email-format.com (with Cloudflare cfemail decoding) ---
        try:
            resp = await client.get(f"https://www.email-format.com/d/{domain}/")
            if resp.status_code == 200:
                for addr in _EMAIL_RE.findall(resp.text):
                    _add(addr, "email-format")
                for enc in re.findall(r'data-cfemail="([0-9a-fA-F]+)"', resp.text):
                    decoded = _decode_cfemail(enc)
                    if decoded:
                        _add(decoded, "email-format")
        except httpx.HTTPError as exc:
            logger.debug("email-format failed for %s: %s", domain, exc)

        # --- skymem.info ---
        try:
            resp = await client.get(f"https://www.skymem.info/srch?q={urllib.parse.quote(domain)}")
            if resp.status_code == 200:
                for addr in _EMAIL_RE.findall(resp.text):
                    _add(addr, "skymem")
        except httpx.HTTPError as exc:
            logger.debug("skymem failed for %s: %s", domain, exc)

    return [Email(address=addr, source=src) for addr, src in sorted(found.items())]


def _decode_cfemail(enc: str) -> str | None:
    """Decode a Cloudflare ``data-cfemail`` obfuscated email (XOR with first byte key)."""
    try:
        key = int(enc[:2], 16)
        return "".join(
            chr(int(enc[i:i + 2], 16) ^ key) for i in range(2, len(enc), 2)
        )
    except (ValueError, IndexError):
        return None


def _xml_value(xml_text: str, tag: str) -> str | None:
    """Extract the text of ``<tag>...</tag>`` from a small XML blob (no XML dep needed)."""
    open_tag = f"<{tag}>"
    close_tag = f"</{tag}>"
    start = xml_text.find(open_tag)
    if start == -1:
        return None
    start += len(open_tag)
    end = xml_text.find(close_tag, start)
    if end == -1:
        return None
    return xml_text[start:end].strip()


# Google dork templates grouped by intent. ``{d}`` is replaced with the domain; each
# category is a purpose an experienced hunter searches for. These generate ready-to-click
# search URLs only — Kaalyx never scrapes results.
_DORK_CATEGORIES: dict[str, list[str]] = {
    "overview": [
        'site:{d}',
        'site:{d} -www',
    ],
    "login_admin": [
        'site:{d} inurl:admin OR inurl:login OR inurl:signin OR inurl:dashboard OR inurl:portal',
        'site:{d} intitle:"login" OR intitle:"admin"',
    ],
    "auth_recovery": [
        'site:{d} inurl:reset OR inurl:forgot OR inurl:recover OR inurl:password-reset',
        'site:{d} intitle:"reset password" OR intitle:"forgot password" OR intitle:"account recovery"',
    ],
    "nonprod_env": [
        'site:{d} inurl:dev OR inurl:staging OR inurl:stage OR inurl:test OR inurl:uat OR inurl:qa OR inurl:preprod',
        'site:{d} intitle:"staging" OR intitle:"dev" OR intitle:"test environment"',
    ],
    "api": [
        'site:{d} inurl:api OR inurl:graphql OR inurl:rest OR inurl:v1 OR inurl:v2',
        'site:{d} ext:json inurl:api',
    ],
    "swagger_apidocs": [
        'site:{d} inurl:swagger OR inurl:swagger-ui OR inurl:openapi OR inurl:api-docs',
        'site:{d} ext:json "swagger" OR ext:yaml "openapi"',
    ],
    "file_upload": [
        'site:{d} inurl:upload OR inurl:fileupload OR inurl:import OR inurl:attachment',
        'site:{d} intitle:"upload" intext:"choose file" OR intext:"drag and drop"',
    ],
    "config_files": [
        'site:{d} ext:env OR ext:conf OR ext:cfg OR ext:ini OR ext:yaml OR ext:yml',
        'site:{d} ext:xml OR ext:json filetype:config',
    ],
    "server_config": [
        'site:{d} ext:htaccess OR ext:htpasswd OR filetype:htaccess',
        'site:{d} inurl:web.config OR ext:config "connectionString"',
    ],
    "ci_cd": [
        'site:{d} inurl:jenkins OR inurl:.gitlab-ci.yml OR inurl:.travis.yml OR inurl:circleci',
        'site:{d} ext:yml "pipeline" OR ext:yaml "workflow" OR inurl:.github/workflows',
    ],
    "db_files": [
        'site:{d} ext:sql OR ext:db OR ext:dbf OR ext:bak OR ext:backup',
    ],
    "backups": [
        'site:{d} ext:zip OR ext:tar OR ext:gz OR ext:rar OR ext:7z OR ext:tgz',
        'site:{d} ext:bak OR ext:old OR ext:swp OR ext:save OR "backup" filetype:sql',
    ],
    "error_debug": [
        'site:{d} intext:"Warning: " OR intext:"Fatal error" OR intext:"Notice: " OR intext:"stack trace"',
        'site:{d} intext:"SQL syntax" OR intext:"ORA-" OR intext:"Traceback (most recent call last)"',
        'site:{d} inurl:phpinfo OR intitle:"phpinfo()" OR inurl:debug OR intext:"DEBUG = True"',
    ],
    "source_maps": [
        'site:{d} ext:map "sourceMappingURL" OR inurl:.js.map',
    ],
    "git_exposure": [
        'site:{d} inurl:.git OR inurl:.svn OR inurl:.gitignore OR inurl:.gitconfig',
    ],
    "open_redirect": [
        'site:{d} inurl:redirect OR inurl:redir OR inurl:url= OR inurl:next= OR inurl:return=',
    ],
    "exposed_documents": [
        'site:{d} ext:pdf OR ext:doc OR ext:docx OR ext:xls OR ext:xlsx OR ext:ppt OR ext:pptx',
        'site:{d} "internal use only" OR "confidential" OR "not for distribution"',
    ],
    "directory_listing": [
        'site:{d} intitle:"index of"',
        'site:{d} intitle:"index of" "parent directory"',
    ],
    "secrets": [
        'site:{d} intext:password OR intext:apikey OR intext:"api key" OR intext:secret OR intext:token',
        'site:{d} ext:log OR ext:old OR ext:txt intext:password',
    ],
    "well_known": [
        'site:{d} inurl:.well-known/security.txt',
        'site:{d} inurl:.well-known',
    ],
    "cms_wordpress": [
        'site:{d} inurl:wp-content OR inurl:wp-admin OR inurl:wp-includes',
        'site:{d} inurl:wp-config OR inurl:xmlrpc.php OR inurl:wp-json OR inurl:debug.log',
    ],
    "google_cache": [
        # `cache:` surfaces Google's cached copy — useful for content removed from the live
        # site but still in the index.
        'cache:{d}',
    ],
    "code_sharing": [
        'site:github.com "{d}"',
        'site:gitlab.com "{d}"',
        'site:pastebin.com "{d}"',
        'site:stackoverflow.com "{d}"',
        'site:gist.github.com "{d}"',
        'site:jsfiddle.net OR site:codepen.io OR site:ideone.com "{d}"',
        'site:npmjs.com OR site:hub.docker.com "{d}"',
    ],
    "project_management": [
        'site:trello.com "{d}"',
        'site:atlassian.net "{d}"',
        'site:notion.so OR site:coda.io "{d}"',
    ],
    "social_profiles": [
        'site:linkedin.com/company "{d}" OR site:linkedin.com/in "{d}"',
        'site:twitter.com OR site:x.com "{d}"',
        'site:facebook.com OR site:instagram.com "{d}"',
    ],
    "cloud_storage": [
        'site:s3.amazonaws.com "{d}"',
        'site:blob.core.windows.net "{d}"',
        'site:storage.googleapis.com "{d}"',
        'site:digitaloceanspaces.com OR site:s3.wasabisys.com "{d}"',
    ],
}


def generate_google_dorks(domain: str) -> tuple[list[OsintRecord], dict[str, list[str]]]:
    """Build ready-to-click Google dork URLs for *domain*, grouped by category.

    No scraping is performed (ToS/CAPTCHA/ban risk); the URLs are for manual review.

    Returns ``(osint_records, urls_by_category)`` — records go to the DB (each tagged with
    its category in ``detail``), and ``urls_by_category`` is written to a grouped raw file.
    """
    records: list[OsintRecord] = []
    urls_by_category: dict[str, list[str]] = {}
    for category, templates in _DORK_CATEGORIES.items():
        cat_urls: list[str] = []
        for template in templates:
            query = template.format(d=domain)
            url = "https://www.google.com/search?q=" + urllib.parse.quote_plus(query)
            cat_urls.append(url)
            records.append(
                OsintRecord(kind="google_dork", value=query, detail=category, source="dorks")
            )
        urls_by_category[category] = cat_urls
    return records, urls_by_category


# --- GitHub org discovery (feeds trufflehog + gato with the TARGET's org, not the token's) --
#
# The token-owning account is NEVER a valid answer for a target scan: trufflehog/gato must
# scan the *target company's* GitHub org, and if we can't confidently identify one they must
# skip — not silently scan whoever owns GITHUB_TOKEN. That earlier shortcut (guessing the org
# is simply ``registrable.split(".")[0]`` and letting trufflehog fall back to the authenticated
# user when that guess isn't a real org) produced findings from the operator's personal repos
# labelled as the target's — zero recon value, and a privacy problem. We instead discover the
# org from real signals and verify it exists before handing it downstream.

_GH_API = "https://api.github.com"


def _github_headers(token: str) -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "kaalyx-osint",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _company_slugs(target) -> list[str]:
    """Candidate company identifiers derived from the target domain.

    e.g. ``kycaid.com`` -> ``["kycaid"]``; ``my-corp.co.uk`` -> ``["my-corp", "mycorp"]``.
    These are only *hints* — every candidate is verified against the API before use, and a
    name match alone is low confidence (many unrelated orgs share common words).
    """
    base = target.registrable.split(".")[0].strip().lower()
    slugs = {base}
    if "-" in base:
        slugs.add(base.replace("-", ""))
    return [s for s in slugs if s]


@dataclass
class GithubOrgCandidate:
    login: str
    kind: str           # "org" | "user"
    confidence: str     # "high" | "medium" | "low"
    reason: str
    evidence: list[str] = field(default_factory=list)  # e.g. repos mentioning the domain


async def _gh_get(client: "httpx.AsyncClient", path: str, params: dict | None = None) -> dict | None:
    try:
        resp = await client.get(f"{_GH_API}{path}", params=params)
        if resp.status_code == 200:
            return resp.json()
        # 403 with rate-limit headers is the common non-fatal case; log and move on.
        logger.debug("GitHub API %s -> HTTP %s", path, resp.status_code)
    except (httpx.HTTPError, ValueError) as exc:
        logger.debug("GitHub API %s failed: %s", path, exc)
    return None


async def _verify_account(client, login: str) -> str | None:
    """Return ``"org"``/``"user"`` if *login* is a real GitHub account, else ``None``."""
    data = await _gh_get(client, f"/users/{urllib.parse.quote(login)}")
    if not data:
        return None
    t = str(data.get("type", "")).lower()
    return "org" if t == "organization" else ("user" if t == "user" else None)


async def _owners_mentioning_domain(client, domain: str, token_owner: str | None) -> dict[str, list[str]]:
    """Owners of repos whose CODE mentions *domain* (GitHub code search).

    This is the strongest signal: it's the same mechanism github-subdomains uses, and a repo
    that references the target's domain is very likely the target's own (or a close vendor's).
    Returns ``{owner_login: [repo_full_name, ...]}``. The token owner is excluded — their
    repos mentioning the domain don't make *them* the target org.
    """
    owners: dict[str, list[str]] = {}
    data = await _gh_get(
        client, "/search/code",
        params={"q": f'"{domain}"', "per_page": 100},  # GitHub's max page — take as many signals as possible
    )
    for item in (data or {}).get("items", []) or []:
        repo = item.get("repository") or {}
        owner = (repo.get("owner") or {}).get("login")
        full = repo.get("full_name")
        if not owner or not full:
            continue
        if token_owner and owner.lower() == token_owner.lower():
            continue  # never let the operator's own repos identify the target
        owners.setdefault(owner, [])
        if full not in owners[owner]:
            owners[owner].append(full)
    return owners


async def _authenticated_login(client) -> str | None:
    data = await _gh_get(client, "/user")
    return data.get("login") if data else None


async def discover_github_org(target, token: str | None, max_candidates: int = 5) -> list[GithubOrgCandidate]:
    """Identify the TARGET's GitHub org(s), ranked by confidence. Never the token owner.

    Strategy (thorough by design — we would rather spend a few extra API calls than settle
    for scanning the wrong account):

    1. **Code search for the domain.** Owners of repos whose code mentions the target domain
       are strong candidates ("high" when the owner is an organization). This is the correct,
       evidence-backed signal the bug report pointed at.
    2. **Org search by company slug.** ``GET /search/users?q=<slug>+type:org`` finds orgs
       whose name/login matches the company; a slug that *also* appears in (1) is "high",
       otherwise "medium" (a plain name match — real but weaker).
    3. **Exact-login probe.** If an org literally named after the slug exists, include it.

    Every candidate is verified to be a real account via the API. The account that owns the
    token is filtered out at every step so a company scan can never resolve to the operator's
    personal account. Returns ``[]`` when nothing can be confidently identified — the caller
    then skips trufflehog/gato with a clear reason rather than scanning anyone by default.
    """
    if not token:
        return []

    candidates: dict[str, GithubOrgCandidate] = {}
    slugs = _company_slugs(target)

    async with httpx.AsyncClient(timeout=20, headers=_github_headers(token), follow_redirects=True) as client:
        token_owner = await _authenticated_login(client)

        # (1) code-search owners mentioning the domain
        domain_owners = await _owners_mentioning_domain(client, target.registrable, token_owner)
        for login, repos in domain_owners.items():
            kind = await _verify_account(client, login)
            if kind is None:
                continue
            name_match = any(s in login.lower() for s in slugs)
            conf = "high" if (kind == "org" or name_match) else "medium"
            candidates[login.lower()] = GithubOrgCandidate(
                login=login, kind=kind, confidence=conf,
                reason=("owns repo(s) whose code mentions "
                        f"{target.registrable}" + (" and name matches target" if name_match else "")),
                evidence=repos[:5],
            )

        # (2) org search by company slug
        for slug in slugs:
            data = await _gh_get(client, "/search/users", params={"q": f"{slug} type:org", "per_page": 10})
            for item in (data or {}).get("items", []) or []:
                login = item.get("login")
                if not login:
                    continue
                if token_owner and login.lower() == token_owner.lower():
                    continue
                low = login.lower()
                # An exact slug==login is a strong match; a fuzzy search hit is weaker.
                exact = low == slug
                if low in candidates:
                    # Already found via domain code search — upgrade to high (two signals).
                    candidates[low].confidence = "high"
                    candidates[low].reason += "; also matches org name search"
                    continue
                candidates[low] = GithubOrgCandidate(
                    login=login, kind="org",
                    confidence="high" if exact else "low",
                    reason=(f"org name {'exactly matches' if exact else 'matches'} "
                            f"target company slug '{slug}'"),
                )

        # (3) exact-login probe (an org literally named after the slug)
        for slug in slugs:
            if slug in candidates:
                continue
            kind = await _verify_account(client, slug)
            if kind == "org":
                candidates[slug] = GithubOrgCandidate(
                    login=slug, kind="org", confidence="high",
                    reason=f"an organization named '{slug}' exists on GitHub",
                )

    # Rank: high > medium > low, orgs before users, more evidence first.
    order = {"high": 3, "medium": 2, "low": 1}
    ranked = sorted(
        candidates.values(),
        key=lambda c: (order.get(c.confidence, 0), c.kind == "org", len(c.evidence)),
        reverse=True,
    )
    return ranked[:max_candidates]


# --- Additional keyless OSINT harvests (BBOT parity: pgp, securitytxt, social) ------------

# Public PGP keyservers expose a HKP search endpoint that returns UIDs (name <email>) for a
# domain — BBOT's `pgp` module. Keyless.
_PGP_KEYSERVERS = [
    "https://keys.openpgp.org/pks/lookup",
    "https://pgp.mit.edu/pks/lookup",
    "https://keyserver.ubuntu.com/pks/lookup",
]


async def harvest_pgp_emails(domain: str) -> list[Email]:
    """Harvest emails for *domain* from public PGP keyservers (BBOT ``pgp``). Keyless.

    Queries each keyserver's HKP ``index`` endpoint for the domain and extracts on-domain
    addresses from the returned key UIDs. Any network failure just yields fewer results.
    """
    found: dict[str, str] = {}
    async with httpx.AsyncClient(timeout=20, follow_redirects=True,
                                 headers={"user-agent": "Mozilla/5.0 (Kaalyx OSINT)"}) as client:
        for base in _PGP_KEYSERVERS:
            try:
                resp = await client.get(base, params={"search": domain, "op": "index",
                                                       "fingerprint": "on"})
                if resp.status_code != 200:
                    continue
                for addr in _EMAIL_RE.findall(resp.text):
                    a = addr.strip().lower().strip(".")
                    host = a.partition("@")[2]
                    if host == domain or host.endswith("." + domain):
                        found.setdefault(a, "pgp")
            except httpx.HTTPError as exc:
                logger.debug("pgp keyserver %s failed for %s: %s", base, domain, exc)
                continue
    return [Email(address=a, source=s) for a, s in sorted(found.items())]


async def fetch_securitytxt(domain: str) -> tuple[list[Email], list[OsintRecord]]:
    """Fetch and parse ``security.txt`` (BBOT ``securitytxt``). Keyless, two HTTP GETs.

    RFC 9116 puts the file at ``/.well-known/security.txt`` (legacy: ``/security.txt``). We
    extract ``Contact:`` emails (on-domain) and record any Contact/Policy URLs. Returns
    ``(emails, records)``.
    """
    emails: dict[str, str] = {}
    records: list[OsintRecord] = []
    async with httpx.AsyncClient(timeout=15, follow_redirects=True,
                                 headers={"user-agent": "Mozilla/5.0 (Kaalyx OSINT)"}) as client:
        for path in ("/.well-known/security.txt", "/security.txt"):
            try:
                resp = await client.get(f"https://{domain}{path}")
            except httpx.HTTPError as exc:
                logger.debug("security.txt %s failed for %s: %s", path, domain, exc)
                continue
            if resp.status_code != 200 or "contact" not in resp.text.lower():
                continue
            records.append(OsintRecord(kind="security_txt", value=f"https://{domain}{path}",
                                       detail="present", source="securitytxt"))
            for line in resp.text.splitlines():
                low = line.strip().lower()
                if low.startswith(("contact:", "policy:", "encryption:")):
                    val = line.split(":", 1)[1].strip()
                    records.append(OsintRecord(kind="security_txt", value=val,
                                               detail=low.split(":", 1)[0], source="securitytxt"))
                    for addr in _EMAIL_RE.findall(val):
                        a = addr.strip().lower().strip(".")
                        host = a.partition("@")[2]
                        if host == domain or host.endswith("." + domain):
                            emails.setdefault(a, "securitytxt")
            break  # first file that exists wins; don't double-count the legacy path
    return ([Email(address=a, source=s) for a, s in sorted(emails.items())], records)


# Social-profile patterns BBOT's `social` module recognises in page links.
_SOCIAL_PATTERNS = {
    "github": re.compile(r"https?://(?:www\.)?github\.com/([A-Za-z0-9-]+)/?", re.I),
    "gitlab": re.compile(r"https?://(?:www\.)?gitlab\.com/([A-Za-z0-9._-]+)/?", re.I),
    "linkedin": re.compile(r"https?://(?:[a-z]{2,3}\.)?linkedin\.com/(company|in)/([A-Za-z0-9._-]+)", re.I),
    "twitter": re.compile(r"https?://(?:www\.)?(?:twitter|x)\.com/([A-Za-z0-9_]+)/?", re.I),
    "facebook": re.compile(r"https?://(?:www\.)?facebook\.com/([A-Za-z0-9.]+)/?", re.I),
    "instagram": re.compile(r"https?://(?:www\.)?instagram\.com/([A-Za-z0-9._]+)/?", re.I),
    "youtube": re.compile(r"https?://(?:www\.)?youtube\.com/(@[A-Za-z0-9._-]+|c/[A-Za-z0-9._-]+|channel/[A-Za-z0-9_-]+)", re.I),
}
# Handles that are the platform's own chrome, not the target's profile.
_SOCIAL_IGNORE = {"share", "sharer", "intent", "home", "login", "signup", "about", "help",
                  "privacy", "policies", "tos", "legal", "features"}


async def discover_social_profiles(domain: str) -> tuple[list[OsintRecord], list[str]]:
    """Find the org's social profiles from its homepage (BBOT ``social``). Keyless.

    Fetches the apex over https (then http) and extracts social-media profile links from the
    HTML — one lightweight page fetch, NOT a crawl. Returns ``(records, github_handles)``;
    the GitHub/GitLab handles are candidate org names that strengthen org discovery.
    """
    records: list[OsintRecord] = []
    handles: list[str] = []
    seen: set[str] = set()
    html = ""
    async with httpx.AsyncClient(timeout=15, follow_redirects=True,
                                 headers={"user-agent": "Mozilla/5.0 (Kaalyx OSINT)"}) as client:
        for scheme in ("https", "http"):
            try:
                resp = await client.get(f"{scheme}://{domain}/")
                if resp.status_code < 400 and resp.text:
                    html = resp.text
                    break
            except httpx.HTTPError as exc:
                logger.debug("social homepage %s://%s failed: %s", scheme, domain, exc)
                continue
    if not html:
        return records, handles
    for platform, pat in _SOCIAL_PATTERNS.items():
        for m in pat.finditer(html):
            handle = (m.group(m.lastindex) if m.lastindex else m.group(1)).strip("/").lower()
            if not handle or handle in _SOCIAL_IGNORE:
                continue
            key = f"{platform}:{handle}"
            if key in seen:
                continue
            seen.add(key)
            records.append(OsintRecord(kind="social", value=f"{platform}: {handle}",
                                       detail=platform, source="social"))
            if platform in ("github", "gitlab"):
                handles.append(handle)
    return records, handles
