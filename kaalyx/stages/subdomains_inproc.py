"""In-process helpers for the Subdomains stage (Part 2).

These are the passive sources Kaalyx implements itself as direct HTTP calls rather than shelling
out to a CLI tool, plus the amass wrapper (amass has no native timeout, so it is capped with the
external ``timeout`` command and its partial output is kept).

* :func:`fetch_crtsh` — Certificate Transparency log subdomains via crt.sh's JSON API (keyless).
* :func:`fetch_jsmon` — subdomains.jsmon.sh direct API (needs ``JSMON_API_KEY``; free tier is
  3 queries/day).
* :func:`in_scope` — keep only hostnames within the target's registrable domain.

Every network failure degrades gracefully to "fewer/no results" — a source never raises out of
here (the stage's fan-out must never be torn down by one source).
"""

from __future__ import annotations

import json

import httpx

from ..core.logging import get_logger
from ..data.models import Subdomain

logger = get_logger("subdomains_inproc")

_UA = {"user-agent": "Mozilla/5.0 (Kaalyx Subdomains)"}


def in_scope(host: str, registrable: str) -> bool:
    """True when *host* is the registrable domain itself or a subdomain of it.

    Guards against a CT log / API returning unrelated hostnames (crt.sh identity matches can pull
    in look-alikes); we keep only names that actually belong under the target's domain."""
    h = (host or "").strip().lower().rstrip(".")
    reg = (registrable or "").strip().lower().rstrip(".")
    if not h or not reg or "." not in h:
        return False
    return h == reg or h.endswith("." + reg)


def _clean_hostnames(raw_names, registrable: str) -> list[str]:
    """Normalise a batch of candidate names → sorted unique in-scope hostnames.

    Handles the wildcard form ``*.example.com`` (kept as the bare parent) and newline-packed
    single fields (crt.sh's ``name_value`` can carry several names separated by newlines)."""
    out: set[str] = set()
    for name in raw_names:
        for part in str(name).split("\n"):
            h = part.strip().lower().lstrip("*.").rstrip(".")
            if in_scope(h, registrable):
                out.add(h)
    return sorted(out)


async def fetch_crtsh(registrable: str, timeout: float = 40.0) -> tuple[list[Subdomain], str]:
    """Query crt.sh's Certificate Transparency JSON API for subdomains of *registrable*.

    Keyless. Returns ``(subdomains, raw_text)`` — *raw_text* is the verbatim JSON body for the
    raw file. crt.sh can be slow/flaky, so a timeout or non-200 just yields no results (never
    raises). Each certificate's ``name_value`` may hold several newline-separated names and
    wildcard entries; all are normalised and scoped to the target domain."""
    url = "https://crt.sh/"
    params = {"q": f"%.{registrable}", "output": "json"}
    raw = ""
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers=_UA) as client:
            resp = await client.get(url, params=params)
            raw = resp.text or ""
            if resp.status_code != 200 or not raw.strip():
                return [], raw or f"# crt.sh returned HTTP {resp.status_code}"
            try:
                data = resp.json()
            except (ValueError, json.JSONDecodeError):
                return [], raw
    except httpx.HTTPError as exc:
        logger.debug("crt.sh failed for %s: %s", registrable, exc)
        return [], f"# crt.sh request failed: {type(exc).__name__}"

    names = [row.get("name_value", "") for row in data if isinstance(row, dict)]
    hosts = _clean_hostnames(names, registrable)
    subs = [Subdomain(hostname=h, source="crt.sh") for h in hosts]
    return subs, raw


async def fetch_jsmon(
    registrable: str, api_key: str, timeout: float = 40.0
) -> tuple[list[Subdomain], str, str]:
    """Query subdomains.jsmon.sh's API for subdomains of *registrable* (needs an API key).

    Returns ``(subdomains, raw_text, skip_note)``. When no key is set, returns an empty list and
    a skip note so the source reports a clean, actionable skip. NOTE: the jsmon free tier allows
    only 3 queries/day — running this on many targets will exhaust it quickly.

    The response shape is read defensively (a list of names, or a dict wrapping a list under a
    ``subdomains``/``results``/``data`` key), mirroring how the OSINT parsers tolerate shape
    variance across tool/API versions."""
    if not api_key:
        return [], "# skipped: JSMON_API_KEY not set", "skipped: JSMON_API_KEY not set"

    url = "https://subdomains.jsmon.sh/api/v1/subdomains"
    raw = ""
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers=_UA) as client:
            resp = await client.get(
                url, params={"domain": registrable},
                headers={**_UA, "X-Jsmon-Key": api_key, "Authorization": f"Bearer {api_key}"},
            )
            raw = resp.text or ""
            if resp.status_code == 401 or resp.status_code == 403:
                return [], raw, "skipped: JSMON_API_KEY rejected (HTTP %d)" % resp.status_code
            if resp.status_code == 429:
                return [], raw, "skipped: jsmon rate/quota exceeded (free tier: 3/day)"
            if resp.status_code != 200 or not raw.strip():
                return [], raw or f"# jsmon HTTP {resp.status_code}", ""
            try:
                data = resp.json()
            except (ValueError, json.JSONDecodeError):
                return [], raw, ""
    except httpx.HTTPError as exc:
        logger.debug("jsmon failed for %s: %s", registrable, exc)
        return [], f"# jsmon request failed: {type(exc).__name__}", ""

    names: list = []
    if isinstance(data, list):
        names = data
    elif isinstance(data, dict):
        for key in ("subdomains", "results", "data", "domains"):
            if isinstance(data.get(key), list):
                names = data[key]
                break
    # entries may be bare strings or dicts carrying a hostname field
    flat: list[str] = []
    for item in names:
        if isinstance(item, str):
            flat.append(item)
        elif isinstance(item, dict):
            flat.append(str(item.get("subdomain") or item.get("host") or item.get("name") or ""))
    hosts = _clean_hostnames(flat, registrable)
    subs = [Subdomain(hostname=h, source="jsmon") for h in hosts]
    return subs, raw, ""
