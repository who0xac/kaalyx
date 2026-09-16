"""In-process (keyless) OSINT sources implemented in Python rather than as external tools.

These cover OSINT items from Part 1 that have no single obvious CLI binary and are cleanly
doable over plain HTTP/DNS without an API key:

* **Email / DNS security posture** — SPF and DMARC (missing/weak policies) plus the wider
  keyless DNS security records: CAA, BIMI, MTA-STS and TLS-RPT. Resolved via
  DNS-over-HTTPS (Cloudflare, then Google) so no local resolver tool is required.
* **M365 / Azure tenant mapping** — Microsoft's public, unauthenticated endpoints:
  ``getuserrealm`` (managed/federated + brand), the ODC ``federationprovider`` endpoint
  (tenant id + brand — a keyless method), and OpenID metadata (tenant GUID).
  The old SOAP ``GetFederationInformation`` tenant-domain trick is deliberately NOT used:
  Microsoft patched it on 2025-05-23 (MC1081538) and it no longer returns tenant domains.
* **Keyless email harvesting** — query email-format.com and skymem.info for addresses at
  the domain. No API key needed.
* **Categorised Google dork generation** — ready-to-click Google search URLs grouped by
  purpose (login/admin/config/git/db/docs/cloud). No scraping (ToS/CAPTCHA/ban risk); the
  user reviews these manually.

Breach/credential lookup remains key-dependent and is handled by the stage: harvested
emails are the input, and the lookup is skipped cleanly when no breach API key is present.
"""

from __future__ import annotations

import asyncio
import re
import ssl
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone

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

# Common/provider-default DKIM selectors to probe. DKIM selectors are NOT discoverable from
# DNS (there's no enumeration), so the standard approach is to guess widely-used ones. A
# not-found here is normal — the domain may use a custom selector we can't guess.
_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "s1", "s2", "k1", "k2",
    "mail", "dkim", "smtp", "mandrill", "mailgun", "sendgrid", "amazonses",
    "protonmail", "protonmail2", "protonmail3", "zoho", "zmail", "everlytickey1",
    "everlytickey2", "mxvault", "dk", "dkim1", "sig1", "mailjet",
]


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


# DNS A/AAAA record type numbers (for resolving a domain to its IPs via DoH).
_A, _AAAA = 1, 28


async def resolve_ips(domain: str) -> list[str]:
    """Resolve *domain*'s A (and AAAA) addresses via DNS-over-HTTPS. De-duped, order-stable."""
    ips: list[str] = []
    seen: set[str] = set()
    for rtype, want in (("A", _A), ("AAAA", _AAAA)):
        for ans in await _doh_query(domain, rtype):
            if ans.get("type") != want:
                continue
            ip = str(ans.get("data", "")).strip()
            if ip and ip not in seen:
                seen.add(ip)
                ips.append(ip)
    return ips


# Geo/ASN lookup sources, tried in order. Each is keyless except ipinfo.io, which is only
# attempted when an IPINFO_TOKEN is configured (its free tier still needs a token). The order
# is: ip-api.com (richest keyless single-call response) → ipapi.co (keyless) → ipinfo.io
# (token, most reliable but rate-limited without one). We fall through to the next source
# whenever one errors OR returns no usable data, and only report failure if ALL of them fail.
def _classify_geo_error(exc: Exception) -> str:
    """Turn a fetch exception/status into a short human reason: timeout / rate-limited / etc."""
    if isinstance(exc, httpx.TimeoutException):
        return "timeout"
    if isinstance(exc, httpx.ConnectError):
        return "connection refused"
    if isinstance(exc, httpx.HTTPError):
        return "network error"
    return f"{type(exc).__name__}"


async def _geo_via_ipapi_com(client: "httpx.AsyncClient", ip: str) -> dict:
    """ip-api.com — one keyless call returns country/asn/isp/org/reverse. May raise; may return
    ``{}`` (source reachable but no data / rate-limited via its own status field)."""
    resp = await client.get(
        f"http://ip-api.com/json/{ip}",
        params={"fields": "status,message,country,countryCode,isp,org,as,asname,reverse,query"},
        timeout=8,
    )
    if resp.status_code == 429:
        raise httpx.HTTPStatusError("rate-limited", request=resp.request, response=resp)
    resp.raise_for_status()
    d = resp.json()
    if d.get("status") != "success":
        return {}  # e.g. {"status":"fail","message":"reserved range"} — no usable data
    return {
        "ip": ip, "via": "ip-api.com",
        "country": d.get("country") or "", "cc": d.get("countryCode") or "",
        "asn": d.get("as") or "", "asname": d.get("asname") or "",
        "isp": d.get("isp") or "", "org": d.get("org") or "",
        "reverse": d.get("reverse") or "",
    }


async def _geo_via_ipapi_co(client: "httpx.AsyncClient", ip: str) -> dict:
    """ipapi.co — keyless JSON. Returns ``{}`` when it signals an error (rate-limit/reserved)."""
    resp = await client.get(f"https://ipapi.co/{ip}/json/", timeout=8)
    if resp.status_code == 429:
        raise httpx.HTTPStatusError("rate-limited", request=resp.request, response=resp)
    resp.raise_for_status()
    d = resp.json()
    if d.get("error"):
        return {}
    asn = (f"AS{d['asn']}" if d.get("asn") else "").replace("ASAS", "AS")
    return {
        "ip": ip, "via": "ipapi.co",
        "country": d.get("country_name") or "", "cc": d.get("country") or "",
        "asn": asn, "asname": d.get("org") or "",
        "isp": d.get("org") or "", "org": d.get("org") or "",
        "reverse": "",
    }


async def _geo_via_ipinfo_io(client: "httpx.AsyncClient", ip: str, token: str) -> dict:
    """ipinfo.io free tier (requires IPINFO_TOKEN). ``org`` is like ``AS16509 Amazon.com, Inc.``."""
    resp = await client.get(f"https://ipinfo.io/{ip}/json",
                            params={"token": token}, timeout=8)
    if resp.status_code == 429:
        raise httpx.HTTPStatusError("rate-limited", request=resp.request, response=resp)
    resp.raise_for_status()
    d = resp.json()
    org = d.get("org") or ""            # "AS16509 Amazon.com, Inc."
    m = re.match(r"(AS\d+)\s+(.*)", org)
    asn = m.group(1) if m else ""
    orgname = m.group(2) if m else org
    return {
        "ip": ip, "via": "ipinfo.io",
        "country": d.get("country") or "", "cc": d.get("country") or "",
        "asn": (f"{asn} {orgname}".strip() if asn else ""), "asname": orgname,
        "isp": orgname, "org": orgname,
        "reverse": d.get("hostname") or "",
    }


async def _geo_ip(client: "httpx.AsyncClient", ip: str, ipinfo_token: str | None = None) -> dict:
    """Geolocation + ASN + ISP/org + reverse-DNS for one IP, with automatic source fallback.

    Tries ip-api.com → ipapi.co → ipinfo.io (the last only if *ipinfo_token* is set), moving on
    whenever a source errors or returns no usable data. On success returns the normalised dict
    from the first source that worked (including a ``via`` key naming that source). On total
    failure returns ``{"ip": ip, "failed": True, "tried": [(source, reason), ...]}`` so the
    caller can report exactly which sources were attempted and why each failed — never a silent
    blank.
    """
    attempts = [
        ("ip-api.com", lambda: _geo_via_ipapi_com(client, ip)),
        ("ipapi.co", lambda: _geo_via_ipapi_co(client, ip)),
    ]
    if ipinfo_token:
        attempts.append(("ipinfo.io", lambda: _geo_via_ipinfo_io(client, ip, ipinfo_token)))

    tried: list[tuple[str, str]] = []
    for name, call in attempts:
        try:
            info = await call()
        except Exception as exc:  # noqa: BLE001 — any failure just falls through to next source
            reason = _classify_geo_error(exc)
            logger.debug("geo source %s failed for %s: %s (%s)", name, ip, exc, reason)
            tried.append((name, reason))
            continue
        if info:
            if tried:
                logger.debug("geo for %s recovered via %s after %s", ip, name, tried)
            return info
        tried.append((name, "no data returned"))
    return {"ip": ip, "failed": True, "tried": tried}


def _encode_ip_detail(info: dict) -> str:
    """Encode a geo result into a stable ``key=value|key=value`` detail string the UI parses.

    On success: ``country=..|cc=..|asn=..|org=..|isp=..|reverse=..|via=<source>``.
    On total failure: ``failed=1|tried=ip-api.com:timeout,ipapi.co:rate-limited,..``.
    Missing individual fields are simply absent (the UI renders them ``[unavailable]``).
    """
    if info.get("failed"):
        trail = ",".join(f"{name}:{reason}" for name, reason in info.get("tried", []))
        return f"failed=1|tried={trail}"
    fields = [
        ("country", info.get("country", "")),
        ("cc", info.get("cc", "")),
        ("asn", info.get("asn", "")),
        ("org", (info.get("org") or info.get("isp") or "")),
        ("isp", info.get("isp", "")),
        ("reverse", info.get("reverse", "")),
        ("via", info.get("via", "")),
    ]
    # `|` and `=` never appear in these provider values; keep only populated fields.
    return "|".join(f"{k}={v}" for k, v in fields if v)


async def ip_info(domain: str, ipinfo_token: str | None = None) -> list[OsintRecord]:
    """Reverse-IP / geolocation / ASN / whois-org intelligence for the domain's resolved IP(s).

    Resolves the domain to its A/AAAA addresses, then fetches geo+ASN+ISP+reverse-DNS for each
    with automatic source fallback (ip-api.com → ipapi.co → ipinfo.io when a token is set) and
    returns them as ``kind="ip_info"`` OsintRecords (rendered in the tree-style IP intel view).
    ``value`` is the IP; ``detail`` is a parseable ``key=value|..`` string carrying every field
    plus the source used — or, when all sources fail, the list of sources tried and why each
    failed. Empty only when the domain has no resolvable IP. Never raises.
    """
    ips = await resolve_ips(domain)
    if not ips:
        return []
    records: list[OsintRecord] = []
    async with httpx.AsyncClient(timeout=15, follow_redirects=True,
                                 headers={"user-agent": "Mozilla/5.0 (Kaalyx OSINT)"}) as client:
        for ip in ips:
            info = await _geo_ip(client, ip, ipinfo_token)
            records.append(OsintRecord(kind="ip_info", value=ip,
                                        detail=_encode_ip_detail(info), source="ip_info"))
    return records


async def check_mail_dns_security(
    domain: str,
) -> tuple[list[OsintRecord], list[Finding], list[Email]]:
    """Assess *domain*'s email/DNS security posture (keyless DNS lookups).

    Covers SPF and DMARC (the classic anti-spoofing pair) plus the wider keyless DNS
    security records — CAA (certificate issuance control), BIMI, MTA-STS and
    TLS-RPT. Records are stored for the dashboard; only genuinely weak/missing anti-spoofing
    posture produces findings (we don't cry wolf about optional records like BIMI).

    Findings raised:
      * missing SPF (low: email spoofing surface),
      * SPF ``+all``/``?all`` (low: permissive),
      * missing DMARC (low),
      * DMARC ``p=none`` (info: monitoring-only, no enforcement),
      * missing CAA (info: any CA may issue certs for the domain).

    Returns ``(records, findings, emails)`` — ``emails`` are any ``iodef:mailto:`` contact
    addresses extracted from CAA records, for the harvest/breach chain.
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
        records.append(OsintRecord(kind="spf", value="not found", source=source))
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
        records.append(OsintRecord(kind="dmarc", value="not found", source=source))
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
            # A CAA `iodef` violation-reporting destination often exposes an
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
    # Emit a record for each ALWAYS — present with its value, or "not found" — so every checked
    # record type is visible in the posture table rather than silently omitted.
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
            # TLS-RPT (and MTA-STS) records carry rua/mailto reporting addresses — harvest any
            # so they feed the email → breach/leak chain.
            for m in re.findall(r"mailto:([^\s\"';,!]+@[^\s\"';,!]+)", hit, re.IGNORECASE):
                addr = m.strip().lower().strip(".")
                if "@" in addr:
                    caa_emails.append(Email(address=addr, source=f"{kind}-rua"))
        else:
            records.append(OsintRecord(kind=kind, value="not found", source=source))

    # --- CAA: also emit a record when absent, so CAA always appears in the table ---
    if not caa_values:
        records.append(OsintRecord(kind="caa", value="not found", source=source))

    # --- DKIM (selector probe) ---
    # DKIM keys live at <selector>._domainkey.<domain>; the selector isn't discoverable from
    # DNS, so we probe a set of common/provider-default selectors. A hit means DKIM is at least
    # configured for that selector. Reports which selectors were found, or "not found (probed N
    # common selectors)" — a not-found is normal and expected (the real selector may be custom).
    dkim_found: list[str] = []
    for sel in _DKIM_SELECTORS:
        rec = await resolve_txt(f"{sel}._domainkey.{domain}")
        hit = next((t for t in rec if "v=dkim1" in t.lower() or "k=rsa" in t.lower()
                    or "p=" in t.lower()), None)
        if hit:
            dkim_found.append(sel)
            records.append(OsintRecord(kind="dkim", value=f"{sel}: {hit[:120]}",
                                       detail=sel, source=source))
    if not dkim_found:
        records.append(OsintRecord(
            kind="dkim",
            value=f"not found (probed {len(_DKIM_SELECTORS)} common selectors)",
            source=source))

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
      * ODC ``federationprovider`` (``odc.officeapps.live.com``) — the current keyless
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

        # 3) ODC federationprovider -> tenant id + brand (current keyless method).
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
        #    Uses azmap.dev (a current keyless azure-tenant mapping source).
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

    Reliable confirmation: GET ``/.git/config``, and only report if
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


async def download_exposed_git(host: str) -> Finding | None:
    """Confirm an exposed ``/.git/`` is actually *downloadable* (not just that config is
    readable), by fetching a small, bounded set of internal git files — ``HEAD``, ``index``,
    ``logs/HEAD`` and ``info/refs`` — and checking they return real git data, not soft-404s.

    This does NOT reconstruct the repository or dump source: it fetches at most four small files
    to evidence that the objects are retrievable, upgrading the finding to CRITICAL/CONFIRMED
    (an attacker could clone the full history). Returns a Finding only when at least ``HEAD``
    plus one more artefact are confirmed retrievable; otherwise ``None``. Never raises."""
    probes = ["HEAD", "index", "logs/HEAD", "info/refs"]
    html_re = re.compile(r"<html|<body", re.IGNORECASE)
    async with httpx.AsyncClient(timeout=15, follow_redirects=True,
                                 headers={"user-agent": "Mozilla/5.0 (Kaalyx OSINT)"}) as client:
        for scheme in ("https", "http"):
            base = f"{scheme}://{host}/.git"
            retrieved: list[str] = []
            head_ok = False
            for name in probes:
                try:
                    resp = await client.get(f"{base}/{name}")
                except httpx.HTTPError as exc:
                    logger.debug("git download probe %s/%s: %s", base, name, exc)
                    continue
                if resp.status_code != 200:
                    continue
                body = resp.content[:512]
                text = body.decode("latin-1", "replace")
                if html_re.search(text):
                    continue  # soft-404 page
                # HEAD is a tiny text file starting "ref: refs/"; index/pack are binary blobs.
                if name == "HEAD":
                    if text.strip().startswith("ref:") or re.fullmatch(r"[0-9a-f]{40}\s*", text.strip()):
                        head_ok = True
                        retrieved.append(name)
                elif name == "index":
                    if body[:4] == b"DIRC":  # git index magic
                        retrieved.append(name)
                elif body:
                    retrieved.append(name)
            if head_ok and len(retrieved) >= 2:
                return Finding(
                    title="Downloadable .git repository",
                    category="exposed-git", severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED, target=f"{base}/", tool="exposed_git",
                    description=("The exposed /.git/ is fully retrievable — internal git objects "
                                 "download successfully, so the complete source history can be "
                                 "cloned. No reconstruction was performed by Kaalyx."),
                    evidence="retrievable git artefacts: " + ", ".join(retrieved),
                    reference=f"{base}/HEAD")
    return None


# Firebase Realtime Database exposure ------------------------------------------------------
# A Firebase RTDB is reachable over a plain REST endpoint at the database root + ``.json``.
# Two host families exist: the classic ``<id>.firebaseio.com`` and the newer regional
# ``<id>.<region>.firebasedatabase.app`` (and the ``-default-rtdb`` instance suffix). A DB
# that answers with data (or ``null``) instead of a permission-denied error is world-readable.
_FIREBASE_REGIONS = [
    "firebaseio.com",                       # classic (us-central1)
    "asia-southeast1.firebasedatabase.app",
    "europe-west1.firebasedatabase.app",
    "us-central1.firebasedatabase.app",
]
# Keys whose VALUES look sensitive — redacted in the preview so we never copy a third party's
# exposed secrets verbatim into our logs (distinct from the no-mask rule for OUR OWN findings).
_FIREBASE_SENSITIVE_KEY = re.compile(
    r"pass|pwd|secret|token|api[_-]?key|apikey|auth|credential|private|session|cookie|ssn|card",
    re.IGNORECASE,
)


def _firebase_candidates(target) -> list[str]:
    """Candidate Firebase project-id names, using the SAME variants as cloud-bucket enumeration:
    the bare base label, the full registrable domain, its dotted-to-hyphen form, and the
    hyphen-collapsed base. Also adds the ``<base>-default-rtdb`` default-instance name Firebase
    assigns new projects. Order-preserving, de-duplicated."""
    reg = target.registrable
    base = reg.split(".")[0]
    variants = [base, reg, reg.replace(".", "-")]
    if "-" in base:
        variants.append(base.replace("-", ""))
    variants.append(f"{base}-default-rtdb")  # Firebase's default RTDB instance name
    seen: set[str] = set()
    return [v for v in variants if v and not (v in seen or seen.add(v))]


def _firebase_preview(text: str, limit: int = 300) -> str:
    """A short, safe preview of an exposed DB's JSON: redact values under sensitive-looking keys
    and truncate, so we evidence the exposure without dumping (or copying secrets from) the DB.
    """
    import json as _json

    def _redact(obj):
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if _FIREBASE_SENSITIVE_KEY.search(str(k)):
                    out[k] = f"[redacted:{len(str(v))}]"
                else:
                    out[k] = _redact(v)
            return out
        if isinstance(obj, list):
            return [_redact(x) for x in obj[:5]]  # cap list previews too
        return obj

    try:
        data = _json.loads(text)
        preview = _json.dumps(_redact(data), separators=(",", ":"))
    except (ValueError, TypeError):
        preview = text  # not JSON we can parse — fall back to raw truncation
    preview = preview.strip()
    if len(preview) > limit:
        preview = preview[:limit] + f"… (+{len(preview) - limit} more chars, truncated)"
    return preview


async def check_firebase_exposure(candidates: list[str]) -> tuple[list[OsintRecord], list[Finding]]:
    """Check candidate Firebase project ids for an exposed Realtime Database.

    For each candidate × host-family, GET ``https://<id>.<host>/.json``. A permission-denied
    error means the DB is secured (no finding). Any other data-bearing response means the DB is
    WORLD-READABLE. For a readable DB we then probe writability with a NON-DESTRUCTIVE
    ``PATCH .json`` carrying an empty object ``{}`` — this makes Firebase evaluate the write
    rules while merging zero keys, so nothing is created, changed or deleted; a 200 means the DB
    is also world-WRITABLE. Severity: HIGH if writable, MEDIUM if read-only. A small, redacted,
    truncated JSON preview is captured as evidence (never the full DB).

    Keyless. Returns ``(records, findings)``; never raises (per-candidate errors are skipped).
    """
    records: list[OsintRecord] = []
    findings: list[Finding] = []
    seen_urls: set[str] = set()
    async with httpx.AsyncClient(timeout=12, follow_redirects=True,
                                 headers={"user-agent": "Mozilla/5.0 (Kaalyx OSINT)"}) as client:
        for cid in candidates:
            for host in _FIREBASE_REGIONS:
                base = f"https://{cid}.{host}"
                url = f"{base}/.json"
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                try:
                    resp = await client.get(url)
                except httpx.HTTPError as exc:
                    logger.debug("firebase probe failed for %s: %s", url, exc)
                    continue

                body = resp.text or ""
                low = body.lower()
                # Secured DBs answer 401/403 with {"error":"Permission denied"}; non-existent
                # projects answer 404 or a "not found"/deprecated error. Neither is exposure.
                if resp.status_code in (401, 403) or '"error"' in low and (
                    "permission denied" in low or "not found" in low or "deprecated" in low):
                    logger.debug("firebase %s: secured/absent (HTTP %s)", url, resp.status_code)
                    continue
                if resp.status_code != 200:
                    continue
                # 200 with an error body is still not real exposure.
                if '"error"' in low and "permission denied" in low:
                    continue

                # Exposed & readable. Empty DB legitimately returns the literal ``null``.
                preview = _firebase_preview(body)
                records.append(OsintRecord(kind="firebase_db", value=base,
                                           detail=f"exposed (readable): {preview}",
                                           source="firebase"))

                # Non-destructive writability probe: PATCH an empty object at root.
                writable = False
                try:
                    wresp = await client.patch(url, content=b"{}",
                                               headers={"content-type": "application/json"})
                    # A writable DB accepts the no-op merge (200). Secured write rules reject it.
                    writable = wresp.status_code == 200
                except httpx.HTTPError as exc:
                    logger.debug("firebase write-probe failed for %s: %s", url, exc)

                sev = Severity.HIGH if writable else Severity.MEDIUM
                access = "READ+WRITE" if writable else "read-only"
                findings.append(Finding(
                    title=f"Exposed Firebase Realtime Database ({access}): {cid}",
                    category="cloud", severity=sev, confidence=Confidence.FIRM,
                    target=base, tool="firebase",
                    description=(f"The Firebase Realtime Database at {url} is publicly "
                                 f"{'readable and WRITABLE' if writable else 'readable'} — it "
                                 "returned data instead of a permission-denied error"
                                 + (". A non-destructive empty-merge PATCH was accepted, so "
                                    "anyone can also modify the data." if writable else ".")),
                    evidence=f"GET {url} → HTTP 200\npreview: {preview}",
                    reference=url, raw=preview))
                # A project's RTDB lives on ONE host family; once found, don't re-report it
                # across the other regional domains for the same candidate id.
                break
    return records, findings


# Shodan InternetDB -------------------------------------------------------------------------
# The FREE, keyless companion to the paid /shodan/host lookup: https://internetdb.shodan.io/<ip>
# returns ports, hostnames, CPEs, tags and known CVE ids from Shodan's cache with no API key
# and no packets to the target. A 404 means Shodan has never seen the IP (not an error).
async def internetdb_lookup(ips: list[str]) -> tuple[list[OsintRecord], list[Finding]]:
    """Keyless passive host data + CVE tags per resolved IP via Shodan InternetDB.

    Returns ``(records, findings)``. Each IP Shodan knows yields an ``internetdb`` record
    (ports/hostnames/CPEs) and, when it lists ``vulns``, a ``cve`` finding (TENTATIVE — passive,
    unverified). Never raises; a per-IP failure/404 is skipped."""
    records: list[OsintRecord] = []
    findings: list[Finding] = []
    async with httpx.AsyncClient(timeout=12,
                                 headers={"user-agent": "Mozilla/5.0 (Kaalyx OSINT)"}) as client:
        for ip in ips:
            try:
                resp = await client.get(f"https://internetdb.shodan.io/{ip}")
            except httpx.HTTPError as exc:
                logger.debug("internetdb %s: %s", ip, exc)
                continue
            if resp.status_code == 404:
                continue  # Shodan has never indexed this IP
            if resp.status_code != 200:
                continue
            try:
                d = resp.json()
            except ValueError:
                continue
            ports = d.get("ports") or []
            hostnames = d.get("hostnames") or []
            cpes = d.get("cpes") or []
            vulns = sorted(d.get("vulns") or [])
            bits = [f"ports={','.join(str(p) for p in sorted(set(ports))) or 'none'}"]
            if hostnames:
                bits.append("hostnames=" + ",".join(hostnames))
            if cpes:
                bits.append(f"cpes={len(cpes)}")
            if vulns:
                bits.append(f"vulns={len(vulns)}")
            records.append(OsintRecord(kind="internetdb", value=ip,
                                       detail=" · ".join(bits), source="internetdb"))
            if vulns:
                sev = Severity.HIGH if len(vulns) >= 5 else Severity.MEDIUM
                findings.append(Finding(
                    title=f"InternetDB CVE tags on {ip} ({len(vulns)})",
                    category="cve", severity=sev, confidence=Confidence.TENTATIVE,
                    target=ip, tool="internetdb",
                    description=(f"Shodan InternetDB (free, passive) lists {len(vulns)} known-CVE "
                                 f"tag(s) for {ip}. Verify against the live service before acting."),
                    evidence=", ".join(vulns), reference=vulns[0], raw=", ".join(vulns)))
    return records, findings


# TLS certificate extraction ----------------------------------------------------------------
async def extract_tls_cert(domain: str) -> tuple[list[OsintRecord], list[str]]:
    """Fetch the target's live TLS leaf certificate and extract intelligence from it (keyless).

    Returns ``(records, san_hostnames)``. Records cover the subject CN, issuer, validity window
    and the Subject Alternative Names; the SAN hostnames on the target's registrable domain are
    also returned separately so the caller can feed them into subdomain discovery. Uses a blocking
    ``ssl`` handshake off the event loop. Never raises — a handshake failure yields empty."""
    records: list[OsintRecord] = []
    sans: list[str] = []

    def _fetch() -> dict | None:
        ctx = ssl.create_default_context()
        try:
            with ctx.wrap_socket(__import__("socket").socket(), server_hostname=domain) as s:
                s.settimeout(10)
                s.connect((domain, 443))
                return s.getpeercert()
        except Exception as exc:  # noqa: BLE001 — no cert / handshake failure is not an error
            logger.debug("TLS cert fetch failed for %s: %s", domain, exc)
            return None

    cert = await asyncio.to_thread(_fetch)
    if not cert:
        return records, sans

    def _name(seq) -> str:
        return ", ".join("=".join(x) for rdn in (seq or ()) for x in rdn)

    subject = _name(cert.get("subject"))
    issuer = _name(cert.get("issuer"))
    if subject:
        records.append(OsintRecord(kind="tls_cert", value=subject,
                                   detail="subject", source="tls_cert"))
    if issuer:
        records.append(OsintRecord(kind="tls_cert", value=issuer,
                                   detail="issuer", source="tls_cert"))
    if cert.get("notBefore") or cert.get("notAfter"):
        records.append(OsintRecord(
            kind="tls_cert", value=f"{cert.get('notBefore','?')} → {cert.get('notAfter','?')}",
            detail="validity", source="tls_cert"))
    reg = domain.split(".", 1)[-1] if domain.count(".") > 1 else domain
    for typ, val in cert.get("subjectAltName", ()):
        if typ.lower() == "dns":
            records.append(OsintRecord(kind="tls_cert", value=val, detail="san",
                                       source="tls_cert"))
            host = val.lstrip("*.").lower()
            if host.endswith(domain) or host.endswith(reg):
                sans.append(host)
    return records, sorted(set(sans))


# GitLab group / namespace discovery --------------------------------------------------------
async def discover_gitlab(company_slugs: list[str]) -> list[OsintRecord]:
    """Look up a public GitLab.com group or user matching the company (keyless public API).

    Returns ``gitlab`` records for each confirmed group/user namespace — a hint that public
    repositories (and their CI config) may exist. Never raises."""
    records: list[OsintRecord] = []
    seen: set[str] = set()
    async with httpx.AsyncClient(timeout=12, follow_redirects=True,
                                 headers={"user-agent": "Mozilla/5.0 (Kaalyx OSINT)"}) as client:
        for slug in company_slugs:
            for kind, path in (("group", f"https://gitlab.com/api/v4/groups/{urllib.parse.quote(slug)}"),
                               ("user", f"https://gitlab.com/api/v4/users?username={urllib.parse.quote(slug)}")):
                try:
                    resp = await client.get(path)
                except httpx.HTTPError as exc:
                    logger.debug("gitlab %s %s: %s", kind, slug, exc)
                    continue
                if resp.status_code != 200:
                    continue
                try:
                    data = resp.json()
                except ValueError:
                    continue
                items = data if isinstance(data, list) else [data]
                for it in items:
                    web = it.get("web_url") or f"https://gitlab.com/{slug}"
                    if web in seen:
                        continue
                    seen.add(web)
                    records.append(OsintRecord(
                        kind="gitlab", value=web,
                        detail=f"{kind}: {it.get('name') or it.get('username') or slug}",
                        source="gitlab"))
    return records


# Docker Hub org / user repositories --------------------------------------------------------
async def discover_dockerhub(company_slugs: list[str]) -> list[OsintRecord]:
    """List public Docker Hub repositories under a namespace matching the company (keyless).

    Image/repo names frequently leak internal service names. Returns ``dockerhub`` records for
    each public repo found. Never raises."""
    records: list[OsintRecord] = []
    async with httpx.AsyncClient(timeout=12,
                                 headers={"user-agent": "Mozilla/5.0 (Kaalyx OSINT)"}) as client:
        for slug in company_slugs:
            url = f"https://hub.docker.com/v2/repositories/{urllib.parse.quote(slug)}/"
            try:
                resp = await client.get(url, params={"page_size": 100})
            except httpx.HTTPError as exc:
                logger.debug("dockerhub %s: %s", slug, exc)
                continue
            if resp.status_code != 200:
                continue
            try:
                data = resp.json()
            except ValueError:
                continue
            for repo in data.get("results", []) or []:
                name = repo.get("name", "")
                full = f"{slug}/{name}"
                desc = (repo.get("description") or "").strip()[:80]
                records.append(OsintRecord(
                    kind="dockerhub", value=full,
                    detail=(f"pulls={repo.get('pull_count', 0)}"
                            + (f" · {desc}" if desc else "")),
                    source="dockerhub"))
    return records


# A brand label that is also a common English/tech word matches unrelated results on the
# name-seeded sources (mobile apps, affiliate certs). We don't drop these sources for such
# targets, but we require a STRICTER match (the brand as a distinct token in a seller/org name)
# so a generic label like "example"/"cloud"/"data" doesn't flood the output with noise.
_GENERIC_LABELS = {
    "example", "test", "demo", "cloud", "data", "app", "apps", "api", "dev", "web", "mail",
    "shop", "store", "pay", "info", "online", "digital", "tech", "group", "global", "world",
    "home", "my", "get", "go", "the", "smart", "money", "finance", "health", "learn", "play",
}


def _brand_token_match(brand: str, text: str) -> bool:
    """True if *brand* appears as a distinct word/token in *text* (case-insensitive), e.g. brand
    'acme' matches 'ACME, Inc.' or 'acme-labs' but not 'acmecorp-unrelated'. Used to keep only
    plausibly-owned results from name-seeded sources."""
    if not brand or not text:
        return False
    return re.search(rf"(?:^|[^a-z0-9]){re.escape(brand.lower())}(?:[^a-z0-9]|$)",
                     text.lower()) is not None


# Mobile app discovery (Apple App Store + Google Play) --------------------------------------
async def discover_mobile_apps(company_name: str) -> list[OsintRecord]:
    """Find the organisation's published mobile apps (keyless).

    Uses Apple's public iTunes Search API (keyless JSON) and a Google Play store query. Returns
    ``mobile_app`` records naming each app + its store URL — a pivot to bundle ids / privacy
    contacts / package names. Never raises."""
    records: list[OsintRecord] = []
    brand = company_name.strip().lower()
    # For a generic-word brand, a substring/track-name match is meaningless (every "example"
    # app matches), so require the brand as a distinct token in the SELLER/developer name —
    # apps a same-named developer actually published.
    generic = brand in _GENERIC_LABELS
    async with httpx.AsyncClient(timeout=12, follow_redirects=True,
                                 headers={"user-agent": "Mozilla/5.0 (Kaalyx OSINT)"}) as client:
        # Apple iTunes Search API — reliable keyless JSON.
        try:
            resp = await client.get("https://itunes.apple.com/search",
                                    params={"term": company_name, "entity": "software", "limit": 25})
            if resp.status_code == 200:
                for app in resp.json().get("results", []) or []:
                    seller = app.get("sellerName") or app.get("artistName") or ""
                    track = app.get("trackName") or ""
                    seller_hit = _brand_token_match(brand, seller)
                    # Generic brand: seller must match. Distinctive brand: seller OR track title.
                    if generic:
                        keep = seller_hit
                    else:
                        keep = seller_hit or _brand_token_match(brand, track)
                    if not keep:
                        continue
                    records.append(OsintRecord(
                        kind="mobile_app", value=track,
                        detail=f"iOS · {app.get('bundleId','')} · seller={seller} · "
                               f"{app.get('trackViewUrl','')}", source="mobile_app"))
        except (httpx.HTTPError, ValueError) as exc:
            logger.debug("itunes search failed: %s", exc)
        # Google Play — HTML search; extract package ids (id=<pkg>) referencing the company.
        # A package id is reverse-DNS (com.<vendor>.<app>); require the brand to be a distinct
        # segment of it (so com.acme.app matches, com.x.acmeexamples does not). Skip a generic
        # brand entirely — a substring like "example" hits countless unrelated packages.
        if not generic:
            try:
                resp = await client.get("https://play.google.com/store/search",
                                        params={"q": company_name, "c": "apps"})
                if resp.status_code == 200:
                    pkgs = sorted(set(re.findall(r"/store/apps/details\?id=([a-zA-Z0-9._]+)", resp.text)))
                    for pkg in pkgs[:25]:
                        if brand in pkg.lower().split("."):
                            records.append(OsintRecord(
                                kind="mobile_app", value=pkg, detail="Android · "
                                f"https://play.google.com/store/apps/details?id={pkg}",
                                source="mobile_app"))
            except httpx.HTTPError as exc:
                logger.debug("play search failed: %s", exc)
    return records


# Affiliate / related domains via crt.sh organisation certs ---------------------------------
async def discover_affiliate_domains(company_slugs: list[str], apex: str) -> list[OsintRecord]:
    """Find affiliate/related domains sharing the org's TLS certificates (keyless, crt.sh).

    Queries crt.sh for certificates whose subject/organisation matches the company, then reports
    registrable domains OTHER than the apex — a signal of sibling/affiliate properties. Returns
    ``affiliate_domain`` records. Never raises."""
    records: list[OsintRecord] = []
    seen: set[str] = set()
    async with httpx.AsyncClient(timeout=20, follow_redirects=True,
                                 headers={"user-agent": "Mozilla/5.0 (Kaalyx OSINT)"}) as client:
        for slug in company_slugs:
            # A generic-word slug (e.g. "example") matches thousands of unrelated domains on a
            # name search — too noisy to be a useful affiliate signal, so skip it entirely.
            if slug in _GENERIC_LABELS:
                logger.debug("affiliate: skipping generic slug %r", slug)
                continue
            try:
                resp = await client.get("https://crt.sh/",
                                        params={"q": f"%.{slug}%", "output": "json"})
            except httpx.HTTPError as exc:
                logger.debug("crt.sh %s: %s", slug, exc)
                continue
            if resp.status_code != 200:
                continue
            try:
                rows = resp.json()
            except ValueError:
                continue
            for row in rows:
                for name in str(row.get("name_value", "")).splitlines():
                    host = name.strip().lstrip("*.").lower()
                    if not host or "@" in host:
                        continue
                    labels = host.split(".")
                    if len(labels) < 2:
                        continue
                    reg = ".".join(labels[-2:])
                    # Report registrable domains other than the apex whose OWN base label is the
                    # brand as a distinct token — so "acme.io"/"acme-labs.com" qualify but
                    # "acmecorp-unrelated.com" (brand as a mere substring) does not.
                    base_label = reg.split(".")[0]
                    if reg == apex or reg in seen or not _brand_token_match(slug, base_label):
                        continue
                    seen.add(reg)
                    records.append(OsintRecord(kind="affiliate_domain", value=reg,
                                               detail=f"cert name shares brand '{slug}' (hint)",
                                               source="affiliate"))
    return records


async def harvest_emails(domain: str) -> list[Email]:
    """Keyless email harvesting from email-format.com and skymem.info.

    Queries email-format.com (decoding Cloudflare
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


# GitHub Actions workflow-log secret scanning -----------------------------------------------
# Secrets are routinely leaked by being echoed into CI output. GitHub retains run logs; with a
# token we can download recent runs' logs (a zip of text) and scan them for credential patterns.
_WORKFLOW_LOG_PATTERNS = {
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "github_pat": re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "generic_bearer": re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
}


async def scan_workflow_logs(
    org: str, token: str, max_repos: int = 10, max_runs: int = 5,
) -> tuple[list[OsintRecord], list[Finding]]:
    """Download recent GitHub Actions run logs for *org*'s repos and scan them for leaked
    secrets (needs a token). Returns ``(records, findings)``.

    For each of the org's most-recently-pushed repos, the most recent workflow runs' logs are
    fetched (a zip of plain-text logs) and matched against known credential patterns. A hit is a
    HIGH/FIRM ``secret`` finding — the FULL matched value is shown (per the no-mask rule).
    Bounded by *max_repos* / *max_runs* so a big org can't run away. Never raises."""
    import io
    import zipfile

    records: list[OsintRecord] = []
    findings: list[Finding] = []
    async with httpx.AsyncClient(timeout=30, follow_redirects=True,
                                 headers=_github_headers(token)) as client:
        repos = await _gh_get(client, f"/orgs/{urllib.parse.quote(org)}/repos",
                              {"sort": "pushed", "per_page": max_repos})
        if not isinstance(repos, list):
            # Might be a user account rather than an org.
            repos = await _gh_get(client, f"/users/{urllib.parse.quote(org)}/repos",
                                  {"sort": "pushed", "per_page": max_repos}) or []
        for repo in repos:
            full = repo.get("full_name")
            if not full:
                continue
            runs = await _gh_get(client, f"/repos/{full}/actions/runs", {"per_page": max_runs})
            for run in (runs or {}).get("workflow_runs", [])[:max_runs]:
                run_id = run.get("id")
                if not run_id:
                    continue
                try:
                    lr = await client.get(f"{_GH_API}/repos/{full}/actions/runs/{run_id}/logs")
                except httpx.HTTPError as exc:
                    logger.debug("workflow logs %s#%s: %s", full, run_id, exc)
                    continue
                if lr.status_code != 200:
                    continue
                records.append(OsintRecord(kind="workflow_log", value=f"{full}#{run_id}",
                                           detail="log downloaded", source="workflow_logs"))
                try:
                    zf = zipfile.ZipFile(io.BytesIO(lr.content))
                except zipfile.BadZipFile:
                    continue
                for member in zf.namelist():
                    try:
                        text = zf.read(member).decode("utf-8", "replace")
                    except KeyError:
                        continue
                    for label, pat in _WORKFLOW_LOG_PATTERNS.items():
                        for m in set(pat.findall(text)):
                            findings.append(Finding(
                                title=f"Secret leaked in CI log ({label})",
                                category="secret", severity=Severity.HIGH,
                                confidence=Confidence.FIRM, target=f"{full} run {run_id}",
                                tool="workflow_logs",
                                description=f"A {label} pattern was found in a GitHub Actions run "
                                            f"log for {full} ({member}).",
                                evidence=f"{label}: {m}",  # full value, per the no-mask rule
                                reference=run.get("html_url", ""), raw=m))
    return records, findings


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


# --- Additional keyless OSINT harvests: pgp, securitytxt, social ------------

# Public PGP keyservers expose a HKP search endpoint that returns UIDs (name <email>) for a
# domain. Keyless.
_PGP_KEYSERVERS = [
    "https://keys.openpgp.org/pks/lookup",
    "https://pgp.mit.edu/pks/lookup",
    "https://keyserver.ubuntu.com/pks/lookup",
]


async def harvest_pgp_emails(domain: str) -> list[Email]:
    """Harvest emails for *domain* from public PGP keyservers. Keyless.

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
    """Fetch and parse ``security.txt``. Keyless, two HTTP GETs.

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


# Social-profile patterns recognised in page links.
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


async def discover_social_profiles(domain: str) -> tuple[list[OsintRecord], list[str], bool]:
    """Find the org's social profiles from its homepage. Keyless.

    Fetches the apex over https (then http) and extracts social-media profile links from the
    HTML — one lightweight page fetch, NOT a crawl. Returns ``(records, github_handles, blocked)``
    where *blocked* is True when the homepage returned a bot-block page (403/429/…) so the
    caller can say "homepage blocked" instead of the misleading "no profiles found";
    the GitHub/GitLab handles are candidate org names that strengthen org discovery.
    """
    records: list[OsintRecord] = []
    handles: list[str] = []
    seen: set[str] = set()
    html = ""
    blocked = False
    # A realistic browser User-Agent + Accept headers — an obvious bot UA is more likely to be
    # challenged/blocked by a WAF (Cloudflare etc.). We also try the apex and www., http and
    # https, and parse the body EVEN on a 4xx/5xx block page (its markup may still leak the
    # footer social links); only a truly empty body is a dead end.
    browser_ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
    headers = {
        "user-agent": browser_ua,
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept-language": "en-US,en;q=0.9",
    }
    async with httpx.AsyncClient(timeout=15, follow_redirects=True, headers=headers) as client:
        for host in (domain, f"www.{domain}"):
            for scheme in ("https", "http"):
                try:
                    resp = await client.get(f"{scheme}://{host}/")
                except httpx.HTTPError as exc:
                    logger.debug("social homepage %s://%s failed: %s", scheme, host, exc)
                    continue
                if resp.text:
                    html = resp.text
                    # A 403/429/503 with a short body is almost certainly a bot-block page.
                    if resp.status_code in (401, 403, 405, 406, 429, 503):
                        blocked = True
                    # Stop as soon as we have a body that actually carries social links.
                    if any(s in html.lower() for s in ("facebook.com", "linkedin.com",
                                                       "twitter.com", "youtube.com",
                                                       "instagram.com", "github.com")):
                        blocked = False
                        break
            if html and not blocked:
                break
    if not html:
        return records, handles, blocked
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
    # If we found links, we weren't really blocked (some WAFs serve a partial page with links).
    if records:
        blocked = False
    return records, handles, blocked
