"""Shared GitHub-org discovery — used by every stage with a GitHub-scanning source.

Identifying the TARGET's GitHub org is a cross-stage concern: OSINT's secret scanners and the
Subdomains stage's ``github_subdomains`` source all need it, and none of them may ever scan the
token owner's own account or an unrelated org. This module owns that logic in ONE place so both
stages behave identically and the discovery runs at most once per pipeline.

The result is stashed in ``ctx.shared``:

* ``github_org``            — the chosen org login (or ``None`` when none is confident);
* ``github_org_reason``     — a human explanation of the choice / why none was chosen;
* ``github_org_candidates`` — the ranked candidate list (for notes/logging).

DATA-INTEGRITY GATE: only a HIGH-confidence candidate is ever selected. A medium/low match — a
name-only collision, or an owner that merely *mentions* the domain in code (e.g. yt-dlp shipping a
``lecturio.py`` extractor for lecturio.com) — is NOT the target's org and must never be scanned;
consumers skip cleanly instead. This is the guard against a silent wrong-org scan.
"""

from __future__ import annotations

from ..core.logging import get_logger
from . import osint_inproc

logger = get_logger("github_org")

#: Marker key in ctx.shared recording that discovery has already run this pipeline (so a second
#: stage doesn't repeat the API calls). Distinct from ``github_org``, which may legitimately be
#: ``None`` (no confident org) — we must not re-run just because the answer was "none".
_DONE_KEY = "github_org_discovered"


async def ensure_github_org(ctx) -> str | None:
    """Ensure the target's GitHub org is discovered and stashed in ``ctx.shared``; return it.

    Idempotent and cross-stage: if discovery already ran this pipeline (e.g. OSINT ran before the
    Subdomains stage in an ``--all`` run), this returns the cached ``github_org`` without repeating
    the API calls. Otherwise it runs discovery once, stashes the result, and marks it done. Never
    raises — a discovery failure resolves to "no org" so the caller's source skips cleanly rather
    than scanning the wrong account.
    """
    if ctx.get_shared(_DONE_KEY):
        return ctx.get_shared("github_org")

    target = ctx.target
    token = ctx.secrets.next_github_token()
    try:
        candidates = await osint_inproc.discover_github_org(target, token)
    except Exception as exc:  # never let discovery break a stage
        logger.warning("GitHub org discovery failed: %s", exc)
        candidates = []

    ctx.set_shared("github_org_candidates", candidates)
    best = next((c for c in candidates if c.confidence == "high"), None)
    if best is not None:
        ctx.set_shared("github_org", best.login)
        ctx.set_shared("github_org_reason", f"{best.confidence}: {best.reason}")
        others = [c for c in candidates if c is not best]
        logger.info(
            "GitHub org for %s: %s (%s — %s)%s",
            target.registrable, best.login, best.kind, best.confidence,
            f"; NOT scanning weaker candidates: {', '.join(c.login for c in others[:5])}"
            if others else "",
        )
    else:
        ctx.set_shared("github_org", None)
        weak = ", ".join(f"{c.login}({c.confidence})" for c in candidates[:5])
        reason = (f"no HIGH-confidence GitHub org for {target.registrable}"
                  + (f"; ignored weak matches: {weak}" if weak else ""))
        ctx.set_shared("github_org_reason", reason)
        logger.info(
            "No confident GitHub org for %s — GitHub-scanning sources will SKIP "
            "(refusing to scan a weak/unrelated match%s).", target.registrable,
            f"; ignored: {weak}" if weak else "",
        )

    ctx.set_shared(_DONE_KEY, True)
    return ctx.get_shared("github_org")
