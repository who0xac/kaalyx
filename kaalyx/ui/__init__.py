"""Presentation layer for Kaalyx's terminal UI.

Kaalyx's console output is meant to be genuinely good to look at during a scan — not just
functional. This package holds the reusable ``rich`` building blocks (colour palette,
severity styling, banners) and per-stage UI helpers (live progress, result tables, summary
panels). Keeping this separate from the stages means a stage stays focused on recon logic
and simply hands data to a UI object for rendering.
"""

from __future__ import annotations

from ..data.models import Severity

# --- Shared colour vocabulary -----------------------------------------------------------
# One place for the colours so severity/state read the same everywhere on screen.

SEVERITY_STYLE: dict[str, str] = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim white",
    "unknown": "dim",
}

STATE_STYLE = {
    "ok": "bold green",
    "found": "bold green",
    "running": "bold cyan",
    "skipped": "yellow",
    "failed": "bold red",
    "warn": "yellow",
}

# Accent colours used across banners/panels for a consistent "brand" look.
ACCENT = "bright_cyan"
ACCENT_DIM = "cyan"
MUTED = "grey50"


def severity_style(severity: str | Severity) -> str:
    """Return the rich style string for a severity value."""
    key = severity.value if isinstance(severity, Severity) else str(severity).lower()
    return SEVERITY_STYLE.get(key, SEVERITY_STYLE["unknown"])


# --- Stage-header palette + format (FINAL, PERMANENT; identical across ALL 6 stage headers) --
# The header is locked to this exact shape for every stage — only the stage NAME, the subtitle,
# and the info rows' values differ. Do NOT change the format or the palette per stage.
#
#   [◆] KAALYX::OSINT
#       initializing passive recon engine...
#
#       TARGET  ›  polycab.com
#       SOURCES ›  32 registered
#       MODE    ›  passive · zero packets to target
#
STAGE_TITLE = "bold orange1"   # "[◆] KAALYX::<STAGE>" — bold orange (locked warm palette)
STAGE_SUBTITLE = MUTED         # the "initializing…" line — dim gray
STAGE_LABEL = MUTED            # the TARGET/SOURCES/MODE labels — dim gray
STAGE_SEP = MUTED              # the "›" separator — muted
STAGE_DOMAIN = "bold white"    # the target domain value — bold white
STAGE_COUNT = "bold yellow"    # the count value — bold yellow
STAGE_MODE = "white"           # the MODE value

_STAGE_LABEL_W = 8             # pad labels to a common width — wide enough that even the
                               # longest ("SOURCES") keeps a space before the "›" separator


def _stage_info_row(label: str, value, value_style: str):
    """One aligned 'LABEL  ›  value' info row for a stage header."""
    from rich.text import Text
    row = Text("    ")                                   # 4-space indent under the header
    row.append(f"{label:<{_STAGE_LABEL_W}}", style=STAGE_LABEL)
    row.append("›  ", style=STAGE_SEP)
    if isinstance(value, Text):
        row.append_text(value)
    else:
        row.append(str(value), style=value_style)
    return row


def stage_header(stage: str, subtitle: str, info: list[tuple[str, object, str]] | None = None):
    """Build the shared, PERMANENT per-stage header used by all 6 pipeline stages.

    Renders exactly::

        [◆] KAALYX::<STAGE>
            <subtitle>

            LABEL   ›  value
            ...

    * *stage* — the uppercase stage name (``"OSINT"``, ``"SUBDOMAINS"``, …); the title is always
      ``[◆] KAALYX::<STAGE>`` in bold orange (the locked warm palette).
    * *subtitle* — the dim-gray line under the title (e.g. "initializing passive recon engine...").
    * *info* — ordered ``(label, value, value_style)`` rows (TARGET/SOURCES/MODE/…); label dim,
      "›" muted, value in the given style. Only the stage name, subtitle and these values change
      between stages — the format and palette never do.
    """
    from rich.console import Group
    from rich.text import Text

    parts = [
        Text.assemble(("[◆] ", STAGE_TITLE), (f"KAALYX::{stage}", STAGE_TITLE)),
        Text.assemble(("    ", ""), (subtitle, STAGE_SUBTITLE)),
    ]
    if info:
        parts.append(Text(""))
        for label, value, style in info:
            parts.append(_stage_info_row(label, value, style))
    return Group(*parts)


def severity_tag(severity: str | Severity) -> str:
    """Return a coloured, bracketed severity tag for inline use, e.g. ``[HIGH]``."""
    key = severity.value if isinstance(severity, Severity) else str(severity).lower()
    return f"[{severity_style(key)}]{key.upper()}[/]"


# --- Main application banner ------------------------------------------------------------

_BANNER_ART = r""" _  __           _
| |/ /__ _  __ _| |_   ___  __
| ' // _` |/ _` | | | | \ \/ /
| . \ (_| | (_| | | |_| |>  <
|_|\_\__,_|\__,_|_|\__, /_/\_\
                    |___/"""

_BANNER_DIVIDER = "─" * 51
_BANNER_AUTHOR = "who0xac"


def main_banner():
    """Build the Kaalyx startup banner as a rich renderable.

    Styling: the ASCII art is RED; on the version/tagline line the version is bold YELLOW,
    the ``|`` separator dim, and the tagline bold GREEN; the divider dim; the author muted.
    """
    from rich.console import Group
    from rich.text import Text

    from .. import __version__

    # Show the installed commit next to the version so a STALE install is immediately visible —
    # e.g. an old pipx build that predates a source/fix (the "MOBILE_APPS missing / key not read
    # even though update was run" class of confusion). Best-effort; never breaks the banner.
    sha = None
    try:
        from ..core.updater import installed_commit
        sha = installed_commit(timeout=2.0)
    except Exception:
        sha = None

    version_bits = [
        ("    ", ""),
        (f"v{__version__}", "bold yellow"),
    ]
    if sha:
        version_bits += [(" (", MUTED), (sha, "yellow"), (")", MUTED)]
    version_bits += [
        ("  |  ", MUTED),
        ("Automated Recon & Vulnerability Engine", "bold green"),
    ]
    version_line = Text.assemble(*version_bits)

    return Group(
        Text(_BANNER_ART, style="bold red"),
        Text(""),
        Text(f"    {_BANNER_DIVIDER}", style=MUTED),
        version_line,
        Text(f"    Author: {_BANNER_AUTHOR}", style=MUTED),
        Text(""),
    )


def print_main_banner() -> None:
    """Print the Kaalyx startup banner to the shared console."""
    from ..core.logging import get_console

    get_console().print(main_banner())


# --- Dot progress bar (used by `kaalyx update`) -----------------------------------------

# Number of dots in the bar. 20 gives clean 5%-per-dot resolution.
_DOT_BAR_WIDTH = 20
_DOT_FILLED = "●"
_DOT_EMPTY = "○"


def dot_progress():
    """Build a :class:`rich.progress.Progress` with a dot-style bar: ``●●●●○○○○  62%``.

    rich's built-in :class:`BarColumn` draws a block bar and can't be given custom fill
    glyphs, so we render the bar as a small custom column: filled dots in the accent colour,
    empty dots muted, followed by the percentage. Use it as::

        with dot_progress() as progress:
            task = progress.add_task("Updating Kaalyx", total=100)
            progress.update(task, completed=62)
    """
    from rich.progress import Progress, ProgressColumn, TextColumn
    from rich.text import Text

    from ..core.logging import get_console

    class _DotBarColumn(ProgressColumn):
        def render(self, task) -> Text:
            fraction = 0.0 if not task.total else max(0.0, min(1.0, task.completed / task.total))
            filled = round(fraction * _DOT_BAR_WIDTH)
            bar = Text()
            bar.append(_DOT_FILLED * filled, style=ACCENT)
            bar.append(_DOT_EMPTY * (_DOT_BAR_WIDTH - filled), style=MUTED)
            return bar

    return Progress(
        TextColumn("[bold white]{task.description}[/]"),
        _DotBarColumn(),
        TextColumn(f"[{ACCENT_DIM}]{{task.percentage:>3.0f}}%[/]"),
        console=get_console(),
        transient=False,  # keep the completed bar visible; the final status prints below it
    )
