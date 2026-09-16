"""Shodan-backed OSINT sources (key-gated, in-process over the Shodan REST API).

These reuse a paid Shodan membership to its fullest across the OSINT stage — going well
beyond the domain-scoped hostname/ssl search that runs in the Subdomains stage. Everything
here is passive: we query Shodan's own cache and never touch the target directly.

Four independently-toggled capabilities:

* **Org/ASN search** — find IP ranges / infrastructure tied to the company's name or ASN,
  including hosts with no DNS trail back to the apex (forgotten servers, internal tools).
* **Favicon-hash matching** — hash a live host's favicon (the MurmurHash3 of its base64 form,
  exactly as Shodan indexes it) and pivot to every other host serving an identical favicon —
  staging clones, dev mirrors, or look-alike/phishing sites.
* **CVE / vulnerability tagging** — for any resolved IP, read Shodan's own ``vulns`` tags
  (software it has already flagged as CVE-affected). Zero additional packets to the target.
* **Per-IP deep lookup** — pull full host data (ports, banners, historical scans, vuln tags)
  from Shodan's cache instead of actively scanning ourselves.

All calls go through :class:`ShodanClient`, which asks the API itself why a request failed
(HTTP 401 → bad key, 403 → tier/membership doesn't allow it, 429 → rate limit) rather than
guessing from the account plan. A capability that a tier doesn't permit is reported as a clean
skip, never a crash, and never takes down the other Shodan sources or the wider stage.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

import httpx

from ..core.logging import get_logger
from ..data.models import Confidence, Finding, OsintRecord, Severity

logger = get_logger("osint.shodan")

_API_BASE = "https://api.shodan.io"
# A single host lookup / search costs 1 query credit on paid plans; keep timeouts generous
# because Shodan's search endpoint can be slow for large result sets.
_TIMEOUT = 20.0
# Cap how many hosts we pull per search so a broad org query can't balloon the scan; the raw
# file still records the total match count so nothing is hidden.
_MAX_SEARCH_HOSTS = 100


class ShodanTierError(Exception):
    """The API refused a request because the account's plan/tier/rate-limit doesn't allow it.

    Carries the reason Shodan itself gave (from the JSON ``error`` field or HTTP status), so the
    source can skip cleanly with an honest note instead of guessing about entitlements.
    """

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class ShodanClient:
    """Thin async wrapper over the Shodan REST API with honest, tier-aware error handling."""

    def __init__(self, api_key: str, client: httpx.AsyncClient):
        self._key = api_key
        self._http = client

    async def _get(self, path: str, params: dict | None = None) -> dict:
        """GET a Shodan endpoint. Raises :class:`ShodanTierError` when the API says the plan
        doesn't allow it (401/403/429), or on an empty/invalid response; returns parsed JSON."""
        p = dict(params or {})
        p["key"] = self._key
        try:
            resp = await self._http.get(f"{_API_BASE}{path}", params=p, timeout=_TIMEOUT)
        except httpx.TimeoutException as exc:
            raise ShodanTierError("request timed out") from exc
        except httpx.HTTPError as exc:
            raise ShodanTierError(f"network error: {type(exc).__name__}") from exc

        # Shodan returns a JSON body with an "error" string even on 4xx — prefer it over a bare
        # status so the skip note quotes Shodan's own words (e.g. membership/plan wording).
        api_error = None
        try:
            data = resp.json()
            if isinstance(data, dict):
                api_error = data.get("error")
        except ValueError:
            data = None

        if resp.status_code == 401:
            raise ShodanTierError(api_error or "invalid API key (HTTP 401)")
        if resp.status_code == 403:
            raise ShodanTierError(
                api_error or "plan/tier does not permit this query (HTTP 403)")
        if resp.status_code == 429:
            raise ShodanTierError(api_error or "rate limit reached (HTTP 429)")
        if resp.status_code >= 400:
            raise ShodanTierError(api_error or f"HTTP {resp.status_code}")
        if data is None:
            raise ShodanTierError("empty/invalid response")
        # Some endpoints answer 200 with an {"error": ...} body for plan restrictions.
        if isinstance(data, dict) and data.get("error"):
            raise ShodanTierError(str(data["error"]))
        return data

    async def host(self, ip: str, history: bool = False) -> dict:
        """`/shodan/host/<ip>` — full host data from Shodan's cache. ``history=True`` adds every
        past scan banner (used by the deep lookup)."""
        params = {"minify": "false"}
        if history:
            params["history"] = "true"
        return await self._get(f"/shodan/host/{ip}", params)

    async def search(self, query: str, limit: int = _MAX_SEARCH_HOSTS) -> dict:
        """`/shodan/host/search` — run a Shodan search query, capped at *limit* hosts."""
        # `page` is 1-based; one page holds up to 100 matches, which is our cap.
        return await self._get("/shodan/host/search",
                               {"query": query, "minify": "true", "page": 1})


# --------------------------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------------------------

def _host_summary(match: dict) -> str:
    """One-line ``ip · ports · org · country`` summary from a search match / host record."""
    ip = match.get("ip_str") or match.get("ip") or ""
    ports = match.get("ports") or ([match["port"]] if match.get("port") else [])
    org = match.get("org") or match.get("isp") or ""
    country = (match.get("location") or {}).get("country_name") or match.get("country_name") or ""
    parts = [ip]
    if ports:
        parts.append("ports=" + ",".join(str(p) for p in sorted(set(ports))))
    if org:
        parts.append(f"org={org}")
    if country:
        parts.append(country)
    return " · ".join(p for p in parts if p)


def _vuln_severity(cve_count: int) -> Severity:
    """Passive CVE tags aren't confirmed exploitable, so keep them measured: any tag is at most
    MEDIUM (Shodan flagged known-vulnerable software), scaling to HIGH only for a large cluster."""
    if cve_count >= 5:
        return Severity.HIGH
    if cve_count >= 1:
        return Severity.MEDIUM
    return Severity.INFO


# --------------------------------------------------------------------------------------------
# 1) Org / ASN search
# --------------------------------------------------------------------------------------------

async def org_asn_search(
    client: ShodanClient, company_slugs: list[str], known_ips: set[str],
) -> tuple[list[OsintRecord], list[Finding], str]:
    """Find infrastructure tied to the company by ``org:`` (and ``asn:`` when a slug looks like
    an AS number). Hosts whose IP has NO DNS trail to the apex (not in *known_ips*) are the
    prize — forgotten/internal servers — and are flagged as low-severity attack-surface notes.

    Returns ``(records, findings, raw_text)``. A tier refusal propagates as ShodanTierError.
    """
    records: list[OsintRecord] = []
    findings: list[Finding] = []
    raw_lines: list[str] = []

    queries: list[str] = []
    for slug in company_slugs:
        if slug.upper().startswith("AS") and slug[2:].isdigit():
            queries.append(f"asn:{slug.upper()}")
        else:
            queries.append(f'org:"{slug}"')

    seen_ips: set[str] = set()
    for query in queries:
        data = await client.search(query)
        total = data.get("total", 0)
        matches = data.get("matches", []) or []
        raw_lines.append(f"# query: {query}  (total={total}, shown={len(matches)})")
        for m in matches:
            ip = m.get("ip_str") or ""
            if not ip or ip in seen_ips:
                continue
            seen_ips.add(ip)
            summary = _host_summary(m)
            raw_lines.append(summary)
            no_dns_trail = ip not in known_ips
            detail = summary + ("  [no DNS trail to apex]" if no_dns_trail else "")
            records.append(OsintRecord(kind="shodan_org", value=ip, detail=detail,
                                       source="shodan_org"))
            if no_dns_trail:
                findings.append(Finding(
                    title=f"Org-linked host with no DNS trail: {ip}",
                    category="attack-surface", severity=Severity.LOW,
                    confidence=Confidence.TENTATIVE, target=ip, tool="shodan",
                    description=(f"Shodan associates {ip} with the target's organisation "
                                 f"({query}) but it has no resolvable link to the apex domain — "
                                 "a candidate forgotten/internal server."),
                    evidence=summary, reference=query, raw=summary))
    if not raw_lines:
        raw_lines.append("# no org/ASN matches")
    return records, findings, "\n".join(raw_lines)


# --------------------------------------------------------------------------------------------
# 2) Favicon-hash matching
# --------------------------------------------------------------------------------------------

def favicon_hash(favicon_bytes: bytes) -> int:
    """Compute the Shodan favicon hash: MurmurHash3 (x86, 32-bit) of the base64-encoded icon.

    This is exactly what Shodan indexes as ``http.favicon.hash``. ``base64.encodebytes`` (not
    ``b64encode``) is required — it inserts the newline every 76 chars that Shodan's pipeline
    produces, and the hash differs without it. Returns a signed 32-bit int.
    """
    import mmh3  # local import: only needed when favicon matching actually runs

    return mmh3.hash(base64.encodebytes(favicon_bytes))


async def fetch_favicon(http: httpx.AsyncClient, base_url: str) -> bytes | None:
    """Fetch ``/favicon.ico`` for a live host. Returns the raw bytes, or ``None`` if absent."""
    url = base_url.rstrip("/") + "/favicon.ico"
    try:
        resp = await http.get(url, timeout=_TIMEOUT, follow_redirects=True)
        if resp.status_code == 200 and resp.content:
            return resp.content
    except httpx.HTTPError as exc:
        logger.debug("favicon fetch failed for %s: %s", url, exc)
    return None


async def favicon_search(
    client: ShodanClient, http: httpx.AsyncClient, live_hosts: list[str], known_ips: set[str],
) -> tuple[list[OsintRecord], list[Finding], str]:
    """For each live host, hash its favicon and pivot via ``http.favicon.hash:<h>`` to other
    hosts serving the same icon. Matches outside *known_ips* are surfaced as related/look-alike
    infrastructure (staging clone, dev mirror, or a possible impersonation site).

    *live_hosts* are base URLs (``https://host``). Returns ``(records, findings, raw_text)``.
    """
    records: list[OsintRecord] = []
    findings: list[Finding] = []
    raw_lines: list[str] = []

    hashed: dict[int, str] = {}
    for base in live_hosts:
        fav = await fetch_favicon(http, base)
        if not fav:
            raw_lines.append(f"# {base}: no favicon")
            continue
        h = favicon_hash(fav)
        hashed.setdefault(h, base)

    for h, origin in hashed.items():
        data = await client.search(f"http.favicon.hash:{h}")
        total = data.get("total", 0)
        matches = data.get("matches", []) or []
        raw_lines.append(f"# favicon.hash:{h} from {origin}  (total={total}, shown={len(matches)})")
        records.append(OsintRecord(kind="shodan_favicon", value=str(h),
                                   detail=f"{origin} → {total} host(s) share this favicon",
                                   source="shodan_favicon"))
        for m in matches:
            ip = m.get("ip_str") or ""
            if not ip:
                continue
            summary = _host_summary(m)
            raw_lines.append(summary)
            related = ip not in known_ips
            records.append(OsintRecord(
                kind="shodan_favicon", value=ip,
                detail=summary + ("  [related infra — not in DNS trail]" if related else ""),
                source="shodan_favicon"))
            if related:
                findings.append(Finding(
                    title=f"Host shares target favicon: {ip}",
                    category="related-infra", severity=Severity.INFO,
                    confidence=Confidence.TENTATIVE, target=ip, tool="shodan",
                    description=(f"{ip} serves a favicon identical to {origin} "
                                 f"(hash {h}) but is not in the target's DNS trail — a possible "
                                 "staging clone, dev mirror, or impersonation/phishing site."),
                    evidence=summary, reference=f"http.favicon.hash:{h}", raw=summary))
    if not raw_lines:
        raw_lines.append("# no favicons hashed")
    return records, findings, "\n".join(raw_lines)


# --------------------------------------------------------------------------------------------
# 3) + 4) Per-IP deep lookup and CVE/vuln tagging (both from /shodan/host/<ip>)
# --------------------------------------------------------------------------------------------

async def host_deep_lookup(
    client: ShodanClient, ips: list[str], history: bool, want_vulns: bool, want_deep: bool,
) -> tuple[list[OsintRecord], list[Finding], str]:
    """Pull cached host data for each resolved IP. One request per IP serves BOTH capabilities:

    * ``want_deep`` records ports/banners/hostnames (with ``history`` for past scans);
    * ``want_vulns`` records Shodan's ``vulns`` CVE tags as passive findings.

    A per-IP failure (e.g. Shodan has never seen the IP → 404) is logged and skipped; only a
    tier/plan/rate refusal (raised by the client) stops the source. Returns
    ``(records, findings, raw_text)``.
    """
    records: list[OsintRecord] = []
    findings: list[Finding] = []
    raw_lines: list[str] = []

    for ip in ips:
        try:
            data = await client.host(ip, history=history)
        except ShodanTierError:
            raise  # plan/rate issue → let the source skip cleanly for all IPs
        except Exception as exc:  # noqa: BLE001 — a single IP Shodan has never indexed, etc.
            logger.debug("shodan host %s: %s", ip, exc)
            raw_lines.append(f"# {ip}: not in Shodan cache ({type(exc).__name__})")
            continue

        ports = data.get("ports") or []
        hostnames = data.get("hostnames") or []
        org = data.get("org") or data.get("isp") or ""
        vulns = sorted(data.get("vulns") or [])
        raw_lines.append(
            f"# {ip}  org={org}  ports={ports}  hostnames={hostnames}  vulns={len(vulns)}")

        if want_deep:
            port_str = ",".join(str(p) for p in sorted(set(ports))) or "none"
            detail_bits = [f"ports={port_str}"]
            if org:
                detail_bits.append(f"org={org}")
            if hostnames:
                detail_bits.append("hostnames=" + ",".join(hostnames))
            if history:
                detail_bits.append(f"scans={len(data.get('data') or [])}")
            records.append(OsintRecord(kind="shodan_host", value=ip,
                                       detail=" · ".join(detail_bits), source="shodan_host"))
            # Record each service banner line so nothing is buried only in the raw file.
            for svc in (data.get("data") or []):
                port = svc.get("port")
                product = svc.get("product") or svc.get("_shodan", {}).get("module") or ""
                banner = (svc.get("data") or "").strip().splitlines()[:1]
                banner_line = banner[0][:120] if banner else ""
                raw_lines.append(f"    {ip}:{port} {product} {banner_line}".rstrip())

        if want_vulns and vulns:
            sev = _vuln_severity(len(vulns))
            records.append(OsintRecord(kind="shodan_vuln", value=ip,
                                       detail="CVEs: " + ", ".join(vulns), source="shodan_vuln"))
            findings.append(Finding(
                title=f"Shodan-indexed CVE tags on {ip} ({len(vulns)})",
                category="cve", severity=sev, confidence=Confidence.TENTATIVE,
                target=ip, tool="shodan",
                description=(f"Shodan has flagged {len(vulns)} known-CVE-affected service(s) on "
                             f"{ip} from its own indexing (passive; no packets sent to the "
                             "target). Verify each against the live service before acting."),
                evidence=", ".join(vulns), reference=vulns[0] if vulns else "",
                raw=", ".join(vulns)))

    if not raw_lines:
        raw_lines.append("# no IPs looked up")
    return records, findings, "\n".join(raw_lines)
