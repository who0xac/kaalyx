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

    Styling: bold accent on the ASCII art, a dim divider, the version/tagline in the
    secondary accent colour, and a muted author line.
    """
    from rich.console import Group
    from rich.text import Text

    from .. import __version__

    return Group(
        Text(_BANNER_ART, style=f"bold {ACCENT}"),
        Text(""),
        Text(f"    {_BANNER_DIVIDER}", style=MUTED),
        Text(f"    v{__version__}  |  Automated Recon & Vulnerability Engine", style=ACCENT_DIM),
        Text(f"    Author: {_BANNER_AUTHOR}", style=MUTED),
        Text(""),
    )


def print_main_banner() -> None:
    """Print the Kaalyx startup banner to the shared console."""
    from ..core.logging import get_console

    get_console().print(main_banner())
