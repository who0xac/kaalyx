"""Rich terminal UI for the OSINT stage.

Provides:

* :func:`print_banner` — the OSINT module ASCII banner (figlet-slant "OSINT").
* :class:`OsintProgress` — a live, in-place panel showing every OSINT source and its state
  (queued → running (spinner) → done/skipped/failed) as they run concurrently. Driven by
  the ``progress`` hook from :func:`kaalyx.stages.sources.run_sources`.
* result-table renderers (emails, employees, SPF/DMARC posture, cloud/bucket exposures,
  findings) — aligned tables instead of dumped text.
* :func:`summary_panel` — a bordered summary box printed when the stage finishes.

All rendering goes through the shared console (:func:`kaalyx.core.logging.get_console`) so
it interleaves cleanly with logging.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from rich.box import HEAVY, ROUNDED
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..core.logging import get_console
from . import ACCENT, ACCENT_DIM, MUTED, severity_style

# The OSINT phase header: a fixed double-line box drawn by hand so it renders identically
# on every terminal, regardless of font metrics.
_HEADER_LINES = [
    "╔══════════════════════════════════════════════════════════╗",
    "║  OSINT · Passive Footprinting & Intelligence Gathering    ║",
    "╚══════════════════════════════════════════════════════════╝",
]


def print_banner(domain: str, source_count: int) -> None:
    """Print the OSINT phase header: main banner, a blank line, the double-line box, then a
    target/source-count line."""
    from . import print_main_banner

    console = get_console()

    # Main banner + one blank line precede the phase header (the confirmed sequence).
    print_main_banner()
    console.print()

    header = Text("\n".join(_HEADER_LINES), style=f"bold {ACCENT}")
    subtitle = Text.assemble(
        ("target ", MUTED),
        (domain, "bold white"),
        ("   ", ""),
        (f"{source_count} sources", ACCENT_DIM),
    )
    console.print(header)
    console.print(subtitle)
    console.print()


# --- Live progress ----------------------------------------------------------------------

_SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


@dataclass
class _SourceState:
    label: str
    state: str = "queued"   # queued | running | done | skipped | failed
    items: int = 0
    note: str = ""
    started: float = 0.0
    finished: float = 0.0


class OsintProgress:
    """A live, in-place status board for concurrently-running OSINT sources.

    Usage::

        progress = OsintProgress({name: human_label, ...})
        with progress.live():
            results = await run_sources(sources, progress.hook)

    The status board re-renders as sources start and finish, so the user sees every
    sub-check's state at a glance rather than a silent wait.
    """

    def __init__(self, labels: dict[str, str]) -> None:
        self._console = get_console()
        self._states: dict[str, _SourceState] = {
            name: _SourceState(label=label) for name, label in labels.items()
        }
        self._live = None
        self._start = time.monotonic()

    def hook(self, event: str, name: str, result) -> None:
        """The progress hook passed to ``run_sources``."""
        st = self._states.get(name)
        if st is None:
            return
        if event == "start":
            st.state = "running"
            st.started = time.monotonic()
        elif event == "finish":
            st.finished = time.monotonic()
            st.items = getattr(result, "total", 0)
            st.note = getattr(result, "note", "") or ""
            if result is None or not getattr(result, "ok", False):
                st.state = "failed"
            elif getattr(result, "skipped", False) or (
                st.items == 0 and st.note.lower().startswith("skipped")
            ):
                st.state = "skipped"
            else:
                st.state = "done"
        self._refresh()

    def _render(self):
        table = Table.grid(padding=(0, 1))
        table.add_column(width=2)          # icon
        table.add_column(width=22)         # label
        table.add_column(width=10)         # state
        table.add_column(justify="right", width=6)  # items
        table.add_column(ratio=1, style=MUTED)       # note

        frame = _SPINNER_FRAMES[int((time.monotonic() * 12)) % len(_SPINNER_FRAMES)]
        for st in self._states.values():
            if st.state == "running":
                icon, state_txt = Text(frame, style=ACCENT), Text("running", style="cyan")
            elif st.state == "done":
                icon, state_txt = Text("✔", style="green"), Text("done", style="green")
            elif st.state == "skipped":
                icon, state_txt = Text("○", style="yellow"), Text("skipped", style="yellow")
            elif st.state == "failed":
                icon, state_txt = Text("✘", style="red"), Text("failed", style="bold red")
            else:
                icon, state_txt = Text("·", style=MUTED), Text("queued", style=MUTED)
            items = str(st.items) if st.state == "done" and st.items else ""
            note = st.note if st.state in ("skipped", "failed") else ""
            table.add_row(icon, Text(st.label, style="white"), state_txt, items, note)

        done = sum(1 for s in self._states.values() if s.state != "queued" and s.state != "running")
        elapsed = time.monotonic() - self._start
        header = Text.assemble(
            ("running OSINT sources  ", "bold white"),
            (f"{done}/{len(self._states)}", ACCENT),
            (f"   {elapsed:0.1f}s", MUTED),
        )
        return Panel(table, title=header, title_align="left",
                     border_style=ACCENT_DIM, box=ROUNDED, padding=(0, 1))

    def _refresh(self) -> None:
        if self._live is not None:
            self._live.refresh()

    def live(self):
        """Context manager yielding an auto-refreshing ``rich.Live`` for this board.

        ``get_renderable=self._render`` makes Live recompute the board on every one of its
        ``refresh_per_second`` ticks (not only on start/finish events), so the spinner frame
        — derived from the clock in ``_render`` — animates continuously even while a slow
        source (e.g. theHarvester) blocks between events.
        """
        from rich.live import Live

        self._live = Live(
            get_renderable=self._render,
            console=self._console,
            refresh_per_second=12,
            auto_refresh=True,
            transient=False,
        )
        return self._live


# --- Result tables ----------------------------------------------------------------------


def emails_table(rows: list) -> Table | None:
    """Aligned table of discovered emails (+ breach data if present)."""
    if not rows:
        return None
    table = Table(title="Emails", box=ROUNDED, border_style=ACCENT_DIM,
                  title_style=f"bold {ACCENT}", header_style="bold white", expand=False)
    table.add_column("Address", style="white")
    table.add_column("Source", style=MUTED)
    table.add_column("Breached", justify="center")
    for r in rows:
        breached = r["breached"] if isinstance(r, dict) or hasattr(r, "keys") else r.breached
        addr = r["address"]
        source = r["source"]
        count = r["breach_count"]
        breach_cell = (
            Text(f"⚠ {count}", style="bold red") if breached else Text("—", style=MUTED)
        )
        table.add_row(addr, source, breach_cell)
    return table


def employees_table(rows: list) -> Table | None:
    if not rows:
        return None
    table = Table(title="People / Employees", box=ROUNDED, border_style=ACCENT_DIM,
                  title_style=f"bold {ACCENT}", header_style="bold white")
    table.add_column("Name", style="white")
    table.add_column("Role", style=MUTED)
    table.add_column("Source", style=MUTED)
    for r in rows:
        table.add_row(r["name"], r["role"] or "—", r["source"])
    return table


def mail_hygiene_table(records: list) -> Table | None:
    """Show SPF/DMARC/DNS-security posture + spoofability verdict as a compact table."""
    kinds = ("spf", "dmarc", "caa", "bimi", "mta_sts", "tls_rpt", "dkim", "spoofable")
    interesting = [r for r in records if r["kind"] in kinds]
    if not interesting:
        return None
    table = Table(title="Email / DNS Security Posture", box=ROUNDED,
                  border_style=ACCENT_DIM, title_style=f"bold {ACCENT}",
                  header_style="bold white")
    table.add_column("Record", style="cyan")
    table.add_column("Value", style="white", overflow="fold")
    # Put the spoofable verdict last (it's the summary of the rest).
    interesting.sort(key=lambda r: r["kind"] == "spoofable")
    for r in interesting:
        label = r["kind"].upper().replace("_", "-")
        if r["kind"] == "spoofable":
            spoofable = str(r["value"]).lower() == "yes"
            verdict = Text(
                f"YES — {r['detail']}" if spoofable else f"no — {r['detail']}",
                style="bold red" if spoofable else "green",
            )
            table.add_row(Text("SPOOFABLE", style="bold"), verdict)
        else:
            table.add_row(label, r["value"])
    return table


def findings_table(rows: list, limit: int = 25) -> Table | None:
    """Coloured table of findings, most-severe first."""
    if not rows:
        return None
    order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}
    ordered = sorted(rows, key=lambda r: order.get(r["severity"], 0), reverse=True)[:limit]
    table = Table(title="Findings", box=ROUNDED, border_style=ACCENT_DIM,
                  title_style=f"bold {ACCENT}", header_style="bold white")
    table.add_column("Sev", width=9)
    table.add_column("Category", style="magenta")
    table.add_column("Title", style="white", overflow="fold")
    table.add_column("Target", style=MUTED, overflow="fold")
    for r in ordered:
        sev = r["severity"]
        table.add_row(
            Text(sev.upper(), style=severity_style(sev)),
            r["category"], r["title"], r["target"],
        )
    return table


# --- Summary panel ----------------------------------------------------------------------


def summary_panel(
    domain: str,
    counts: dict[str, int],
    sev_counts: dict[str, int],
    source_states: list[tuple[str, str, int, str]],
    duration_s: float,
) -> Panel:
    """Build the bordered end-of-phase summary panel.

    Args:
        domain: target.
        counts: item totals ({emails, employees, osint, findings, subdomains}).
        sev_counts: findings by severity.
        source_states: list of (name, state, items, note) for the per-source roll-up.
        duration_s: how long the stage took.
    """
    # Left: headline numbers.
    numbers = Table.grid(padding=(0, 2))
    numbers.add_column(justify="right", style=f"bold {ACCENT}")
    numbers.add_column(style="white")
    for label, key in (
        ("Subdomains", "subdomains"), ("Emails", "emails"), ("People", "employees"),
        ("OSINT records", "osint"), ("Findings", "findings"),
    ):
        numbers.add_row(str(counts.get(key, 0)), label)

    # Severity breakdown line (only non-zero severities).
    sev_line = Text()
    for sev in ("critical", "high", "medium", "low", "info"):
        n = sev_counts.get(sev, 0)
        if n:
            if sev_line.plain:
                sev_line.append("  ", MUTED)
            sev_line.append(f"{n} {sev}", style=severity_style(sev))
    if not sev_line.plain:
        sev_line = Text("no findings", style=MUTED)

    # Source roll-up: counts of done/skipped/failed.
    done = sum(1 for _, s, _, _ in source_states if s == "done")
    skipped = sum(1 for _, s, _, _ in source_states if s == "skipped")
    failed = sum(1 for _, s, _, _ in source_states if s == "failed")
    rollup = Text.assemble(
        (f"{done} ok", "green"), ("   ", ""),
        (f"{skipped} skipped", "yellow"), ("   ", ""),
        (f"{failed} failed", "red" if failed else MUTED),
    )
    failed_names = [n for n, s, _, _ in source_states if s == "failed"]

    body_parts = [
        numbers,
        Text(""),
        Text("findings:", style="bold white"),
        sev_line,
        Text(""),
        Text("sources:", style="bold white"),
        rollup,
    ]
    if failed_names:
        body_parts.append(Text(f"failed: {', '.join(failed_names)}", style="red"))
    body = Group(*body_parts)

    title = Text.assemble(
        ("✔ OSINT complete", "bold green"), ("   ", ""),
        (domain, f"bold {ACCENT}"), ("   ", ""), (f"{duration_s:0.1f}s", MUTED),
    )
    return Panel(body, title=title, title_align="left", border_style="green",
                 box=HEAVY, padding=(1, 2))
