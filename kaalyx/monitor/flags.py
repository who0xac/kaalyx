"""Rule-based flagging & enrichment.

Two deterministic enrichments used across stages:

* :func:`flag_interesting` — marks a subdomain as "interesting" when its labels match a
  configurable keyword list (dev-, staging-, admin-, internal-, …). These are the hosts a
  human wants to look at first, so we surface them prominently and can alert on them.
* severity/confidence helpers live in :mod:`kaalyx.data.models`; this module focuses on
  the naming/keyword heuristics so the keyword policy stays in one place.

The matching is intentionally conservative: it matches a keyword as a *label component*
(bounded by dots or hyphens), so ``dev.example.com`` and ``api-dev.example.com`` match on
``dev`` but ``developers.example.com`` does not falsely match on ``dev`` unless ``dev`` is
its own hyphen/dot-delimited token. This keeps the flag meaningful rather than noisy.
"""

from __future__ import annotations

import re

from ..data.models import Subdomain


def _tokenize(hostname: str) -> set[str]:
    """Split a hostname into label tokens delimited by dots and hyphens."""
    return {tok for tok in re.split(r"[.\-]", hostname.lower()) if tok}


def match_keywords(hostname: str, keywords: list[str]) -> list[str]:
    """Return the configured keywords that appear as a token in *hostname*."""
    tokens = _tokenize(hostname)
    return [kw for kw in keywords if kw.lower() in tokens]


def flag_interesting(sub: Subdomain, keywords: list[str]) -> Subdomain:
    """Set ``interesting``/``interesting_reason`` on *sub* if its name matches a keyword.

    Mutates and returns the same object for convenience in comprehensions.
    """
    hits = match_keywords(sub.hostname, keywords)
    if hits:
        sub.interesting = True
        reason = f"naming pattern: {', '.join(sorted(hits))}"
        # Preserve any existing reason (e.g. unusual tech stack set elsewhere).
        sub.interesting_reason = (
            reason if not sub.interesting_reason else f"{sub.interesting_reason}; {reason}"
        )
    return sub


def flag_all(subs: list[Subdomain], keywords: list[str]) -> list[Subdomain]:
    """Apply :func:`flag_interesting` to every subdomain in *subs*."""
    for sub in subs:
        flag_interesting(sub, keywords)
    return subs
