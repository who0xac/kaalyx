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


async def check_mail_dns_security(domain: str) -> tuple[list[OsintRecord], list[Finding]]:
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
    """
    records: list[OsintRecord] = []
    findings: list[Finding] = []
    source = "mail_dns"

    # --- SPF ---
    txts = await resolve_txt(domain)
    spf = next((t for t in txts if t.lower().startswith("v=spf1")), None)
    if spf:
        records.append(OsintRecord(kind="spf", value=spf, source=source))
        low = spf.lower()
        if low.rstrip().endswith("+all") or "?all" in low:
            findings.append(
                Finding(
                    title="Weak SPF policy (permissive 'all')",
                    category="email-security",
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    target=domain,
                    tool=source,
                    description="SPF record allows unlisted senders (+all/?all), weakening anti-spoofing.",
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
    if caa_values:
        for v in caa_values:
            records.append(OsintRecord(kind="caa", value=v, source=source))
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

    return records, findings


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
        addr = addr.strip().lower()
        if not addr or "@" not in addr:
            return
        # Keep only addresses actually at the target domain (or a subdomain of it).
        _, _, host = addr.partition("@")
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


# Google dork templates grouped by intent (taxonomy inspired by reNgine's dork categories).
# ``{d}`` is replaced with the domain. Each category is a purpose the user scans for.
_DORK_CATEGORIES: dict[str, list[str]] = {
    "overview": [
        'site:{d}',
        'site:{d} -www',
    ],
    "login_admin": [
        'site:{d} inurl:admin OR inurl:login OR inurl:signin OR inurl:dashboard OR inurl:portal',
        'site:{d} intitle:"login" OR intitle:"admin"',
    ],
    "api": [
        'site:{d} inurl:api OR inurl:swagger OR inurl:graphql OR inurl:rest',
        'site:{d} ext:json inurl:api',
    ],
    "config_files": [
        'site:{d} ext:env OR ext:conf OR ext:cfg OR ext:ini OR ext:yaml OR ext:yml',
        'site:{d} ext:xml OR ext:json filetype:config',
    ],
    "db_files": [
        'site:{d} ext:sql OR ext:db OR ext:dbf OR ext:bak OR ext:backup',
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
    "cms": [
        'site:{d} inurl:wp-content OR inurl:wp-admin OR inurl:wp-includes',
    ],
    "code_sharing": [
        'site:github.com "{d}"',
        'site:gitlab.com "{d}"',
        'site:pastebin.com "{d}"',
        'site:stackoverflow.com "{d}"',
    ],
    "project_management": [
        'site:trello.com "{d}"',
        'site:atlassian.net "{d}"',
    ],
    "cloud_storage": [
        'site:s3.amazonaws.com "{d}"',
        'site:blob.core.windows.net "{d}"',
        'site:storage.googleapis.com "{d}"',
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
