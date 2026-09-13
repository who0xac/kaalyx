"""Scan-target parsing and apex-vs-subdomain classification.

A key Kaalyx behaviour: if the user supplies a single *subdomain*
(e.g. ``app.example.com``) rather than an *apex* domain (``example.com``), the pipeline
skips subdomain enumeration entirely and goes straight to the host/URL/vuln stages.

Distinguishing an apex from a subdomain reliably requires knowing the public suffix (so
that ``example.co.uk`` is recognised as an apex, not a subdomain of ``co.uk``). We use a
bundled snapshot of the most common public suffixes and multi-label TLDs. This is a
heuristic — good enough to route the pipeline — and the user can always force the
classification with a CLI flag if an unusual suffix is misjudged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from .exceptions import TargetError

# A pragmatic subset of the Public Suffix List: single-label TLDs are handled generically
# (any final label), while these multi-label suffixes need explicit listing so that a
# name like "example.co.uk" is treated as a 3-label apex rather than a subdomain.
_MULTI_LABEL_SUFFIXES: frozenset[str] = frozenset(
    {
        "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
        "sch.uk", "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
        "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
        "co.za", "org.za", "net.za", "gov.za", "ac.za",
        "com.br", "net.br", "org.br", "gov.br",
        "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "gov.in", "ac.in",
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
        "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
        "com.sg", "edu.sg", "gov.sg", "net.sg", "org.sg",
        "com.mx", "com.ar", "com.tr", "com.ua", "com.pl", "com.tw", "com.hk",
        "co.kr", "or.kr", "go.kr",
        "com.ng", "com.gh", "com.ke",
    }
)

# Hostname label validation (RFC 1123, no leading/trailing hyphen, 1-63 chars).
_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


class TargetType(str, Enum):
    """How the pipeline should treat the target."""

    APEX = "apex"            # e.g. example.com / example.co.uk -> run full pipeline
    SUBDOMAIN = "subdomain"  # e.g. app.example.com -> skip subdomain enumeration


@dataclass(frozen=True)
class Target:
    """A parsed, classified scan target.

    Attributes:
        raw: The exact string the user supplied.
        domain: Normalised hostname (lower-cased, scheme/path/port stripped).
        registrable: The registrable ("apex") domain, e.g. ``example.co.uk``.
        target_type: :class:`TargetType`.
    """

    raw: str
    domain: str
    registrable: str
    target_type: TargetType

    @property
    def is_apex(self) -> bool:
        return self.target_type is TargetType.APEX

    @property
    def is_subdomain(self) -> bool:
        return self.target_type is TargetType.SUBDOMAIN

    @property
    def slug(self) -> str:
        """Filesystem-safe identifier used for results/<slug>/ directories."""
        return self.domain.replace(":", "_")


def _normalise(raw: str) -> str:
    """Strip scheme, path, port, userinfo, and surrounding noise; lower-case."""
    value = raw.strip().lower()
    if not value:
        raise TargetError("Empty target.")
    # Drop scheme.
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value)
    # Drop any path/query/fragment.
    value = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    # Drop userinfo.
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    # Drop port.
    value = value.split(":", 1)[0]
    # Drop a trailing dot (FQDN root).
    value = value.rstrip(".")
    if not value:
        raise TargetError(f"Could not extract a hostname from '{raw}'.")
    return value


def registrable_domain(hostname: str) -> str:
    """Return the registrable domain for a hostname using the bundled suffix snapshot."""
    labels = hostname.split(".")
    # Check the longest known multi-label suffixes first.
    for suffix in _MULTI_LABEL_SUFFIXES:
        suffix_labels = suffix.split(".")
        if labels[-len(suffix_labels):] == suffix_labels:
            take = len(suffix_labels) + 1
            return ".".join(labels[-take:]) if len(labels) >= take else hostname
    # Generic single-label TLD: registrable = last two labels.
    return ".".join(labels[-2:]) if len(labels) >= 2 else hostname


def parse_target(raw: str, *, force_type: TargetType | None = None) -> Target:
    """Parse and classify a user-supplied target.

    Args:
        raw: Whatever the user passed (URL, host, host:port, etc.).
        force_type: Override auto-classification (e.g. from a ``--as-subdomain`` flag).

    Raises:
        TargetError: If the value cannot be parsed into a valid hostname.
    """
    domain = _normalise(raw)

    labels = domain.split(".")
    if len(labels) < 2:
        raise TargetError(
            f"'{raw}' does not look like a domain (needs at least one dot)."
        )
    for label in labels:
        if not _LABEL_RE.match(label):
            raise TargetError(f"Invalid hostname label '{label}' in '{raw}'.")

    registrable = registrable_domain(domain)

    if force_type is not None:
        target_type = force_type
    elif domain == registrable:
        target_type = TargetType.APEX
    else:
        target_type = TargetType.SUBDOMAIN

    return Target(
        raw=raw,
        domain=domain,
        registrable=registrable,
        target_type=target_type,
    )
