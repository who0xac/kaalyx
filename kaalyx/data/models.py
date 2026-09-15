"""Normalised record models shared across stages, storage, and the web layer.

These dataclasses are the *lingua franca* of Kaalyx: parsers turn heterogeneous tool
output into these records, the repository persists them, and the dashboard renders them.
Keeping them tool-agnostic is what lets "every category gets 2+ independent tools"
 collapse into a single deduplicated view.

Enums use ``str`` mixins so they serialise cleanly to SQLite/JSON and compare to plain
strings coming back out of the database.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    """Finding severity. Ordering matters for alert thresholds and dashboard sorting."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        """Higher = more severe. Used for threshold comparisons and sorting."""
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
            Severity.UNKNOWN: 0,
        }[self]

    @classmethod
    def coerce(cls, value: str | None) -> "Severity":
        """Best-effort parse of an arbitrary severity string from a tool."""
        if not value:
            return cls.UNKNOWN
        try:
            return cls(value.strip().lower())
        except ValueError:
            return cls.UNKNOWN


class Confidence(str, Enum):
    """How much we trust a finding, independent of its severity."""

    CONFIRMED = "confirmed"   # tool actively validated (e.g. interactsh callback)
    FIRM = "firm"             # strong signal, e.g. dalfox reflected+executed
    TENTATIVE = "tentative"   # pattern/template match, unverified
    UNKNOWN = "unknown"


def _now() -> str:
    """UTC ISO-8601 timestamp, used as the default for all ``discovered_at`` fields."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Subdomain:
    """A discovered subdomain."""

    hostname: str
    source: str                       # tool/source that found it (subfinder, crt.sh, ...)
    resolved: bool = False
    ip_addresses: list[str] = field(default_factory=list)
    interesting: bool = False         # matched an interesting-keyword heuristic
    interesting_reason: str | None = None
    discovered_at: str = field(default_factory=_now)


@dataclass
class Host:
    """A network host (IP) and its exposed surface."""

    ip: str
    hostname: str | None = None
    open_ports: list[int] = field(default_factory=list)
    is_cdn: bool = False
    cdn_name: str | None = None
    waf: str | None = None
    geo: str | None = None            # country / ASN summary from ipinfo/smap
    technologies: list[str] = field(default_factory=list)
    source: str = ""
    discovered_at: str = field(default_factory=_now)


@dataclass
class WebURL:
    """A URL discovered during web analysis (gau/katana/gospider/etc.)."""

    url: str
    source: str
    status_code: int | None = None
    gf_patterns: list[str] = field(default_factory=list)  # matched gf patterns
    screenshot_path: str | None = None
    discovered_at: str = field(default_factory=_now)


@dataclass
class Finding:
    """A vulnerability or noteworthy result — the unit that drives alerts & the dashboard.

    ``dedup_key`` lets the repository collapse the same issue reported by multiple tools
    (the "2+ tools per category" design) into one row while still recording each tool in
    ``tools``.
    """

    title: str
    category: str                     # xss, sqli, ssrf, takeover, secret, cve, ...
    severity: Severity = Severity.UNKNOWN
    confidence: Confidence = Confidence.UNKNOWN
    target: str = ""                  # affected URL / host / subdomain
    tool: str = ""                    # tool that produced this observation
    description: str = ""
    evidence: str = ""                # matched payload, request/response snippet, etc.
    reference: str = ""               # template id, CVE, doc link
    raw: str = ""                     # original raw line/JSON for traceability
    discovered_at: str = field(default_factory=_now)

    @property
    def dedup_key(self) -> str:
        """Stable identity for a logical finding, independent of which tool saw it."""
        return f"{self.category}|{self.target}|{self.title}".lower()


@dataclass
class Email:
    """A discovered email address (from harvesting) with optional breach data.

    A typed email-address record plus h8mail breach
    chaining: an email harvested by one source can later be enriched with breach counts by
    a breach-lookup source keyed on the same address.
    """

    address: str
    source: str
    breached: bool = False
    breach_count: int = 0
    breach_detail: str = ""     # comma-joined breach names / notes
    discovered_at: str = field(default_factory=_now)


@dataclass
class Employee:
    """A person associated with the target org (from theHarvester LinkedIn/Twitter data)."""

    name: str
    source: str                 # linkedin, twitter, ...
    role: str = ""
    discovered_at: str = field(default_factory=_now)


@dataclass
class OsintRecord:
    """A generic OSINT datum (WHOIS field, DNS record, email, secret, misconfig, ...).

    OSINT is heterogeneous, so this is intentionally loose: ``kind`` names the sub-type
    and ``value``/``detail`` carry the content. Anything security-relevant is *also*
    emitted as a :class:`Finding` so it shows up in the findings view and can alert.
    """

    kind: str                         # whois, dns, email, breach, secret, spf, dmarc, ...
    value: str
    detail: str = ""
    source: str = ""
    discovered_at: str = field(default_factory=_now)
