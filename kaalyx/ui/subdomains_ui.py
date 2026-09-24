"""Rich terminal UI for the Subdomains stage (Part 2).

Implements the FINAL, locked two-stage board:

    [◆] KAALYX::SUBDOMAINS  header (+ full ASCII banner only when standalone)

    ── STAGE 1 · PASSIVE DISCOVERY ──────────────────────────
        [icon] SOURCE .......... N found · Ns        (running rows animate the ·•●•· pulse)
        PASSIVE RESULTS  (├─ raw / ├─ dupes removed / └─ unique subdomains)

    ── STAGE 2 · ACTIVE ENUMERATION ─────────────────────────
        [icon] STEP ............ N ... · Ns
        ACTIVE RESULTS   (├─ candidates / ├─ resolved / ├─ dupes removed / └─ new)

    ── FINAL RESULTS ────────────────────────────────────────
        PASSIVE UNIQUE / ACTIVE NEW / TOTAL UNIQUE

    [◆] KAALYX::SUBDOMAINS COMPLETE

The board is rendered in NORMAL scrollback (no alt-screen) so native mouse-wheel scroll works at
all times, exactly like OSINT's final locked design. Each stage animates as a small live block
while it runs, then stays as static scrollback text. The pulse/spinner mechanism is imported
verbatim from :mod:`kaalyx.ui.osint_ui` so the animation is identical across stages.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from rich.console import Group
from rich.text import Text

from ..core.logging import get_console
from . import ACCENT, MUTED, stage_header
# Reuse OSINT's exact animation + quiet-terminal machinery so the board looks/behaves identically.
from .osint_ui import _QuietTerminal, _pulse_leader, _spinner_frame, format_duration

_SECTION_W = 56          # width of the "── TITLE ──────" section rules


def _section_rule(title: str) -> "Text":
    """A ``── TITLE ─────────`` section divider (no boxes), per the spec."""
    prefix = f"── {title} "
    dashes = "─" * max(3, _SECTION_W - len(prefix))
    return Text(prefix + dashes, style=ACCENT)


def _mmss(seconds: float) -> str:
    """S.Ss under a minute, MM:SS at/above, H:MM:SS past an hour — same format as OSINT."""
    return format_duration(seconds)


@dataclass
class _RowState:
    """One source/step row's live state."""
    label: str
    # queued | running | done | skipped | failed
    state: str = "queued"
    found: int = 0                 # running/updated count (found candidates/resolved/etc.)
    unit: str = "found"            # noun shown after the count (found/candidates/resolved/enriched)
    note: str = ""
    started: float = 0.0
    finished: float = 0.0
    slow: bool = False             # amass: show the "[!] may take longer" note
    live_tick: bool = False        # tool streams incremental output → tick the count live


@dataclass
class _Breakdown:
    """The tree-branch numeric summary printed under a stage (├─ / └─ rows)."""
    title: str
    rows: list[tuple[str, int]] = field(default_factory=list)


class SubdomainsProgress:
    """Live two-stage board state + renderer for the Subdomains stage.

    The stage drives it by registering the passive rows, running them under a live block, filling
    the passive breakdown, then the active rows/breakdown, then the final totals — each rendered
    with :meth:`stage_block`. Row animation and counts update in place via :meth:`hook` /
    :meth:`set_found`, identical to OSINT's board hook."""

    _NAME_W = 30
    _LEADER_W = 16

    def __init__(self, target: str, n_passive: int, n_active: int) -> None:
        self._console = get_console()
        self._target = target
        self._n_passive = n_passive
        self._n_active = n_active
        self._rows: dict[str, _RowState] = {}
        self._live = None
        self._start = time.monotonic()

    # -- registration + state updates --------------------------------------------------

    def register(self, name: str, label: str, unit: str = "found",
                 slow: bool = False, live_tick: bool = False) -> None:
        self._rows[name] = _RowState(label=label, unit=unit, slow=slow, live_tick=live_tick)

    def hook(self, event: str, name: str, result) -> None:
        """run_sources-compatible hook: mark a row running/done and record its count/note."""
        st = self._rows.get(name)
        if st is None:
            return
        if event == "start":
            st.state = "running"
            st.started = time.monotonic()
        elif event == "finish":
            st.finished = time.monotonic()
            if result is None or not getattr(result, "ok", False):
                st.state = "failed"
                st.note = getattr(result, "error", "") or getattr(result, "note", "") or "failed"
            elif getattr(result, "skipped", False):
                st.state = "skipped"
                st.note = getattr(result, "note", "") or "skipped"
            else:
                st.state = "done"
                st.found = getattr(result, "total", 0) or len(getattr(result, "subdomains", []) or [])
                st.note = getattr(result, "note", "") or ""
        self._refresh()

    def set_found(self, name: str, count: int) -> None:
        """Live-tick a streaming source's found count (e.g. amass). No-op for absent rows."""
        st = self._rows.get(name)
        if st is not None and st.live_tick:
            st.found = count
            self._refresh()

    def set_done(self, name: str, count: int, note: str = "") -> None:
        """Mark a sequentially-run step done with its final count (active steps)."""
        st = self._rows.get(name)
        if st is None:
            return
        if st.started == 0.0:
            st.started = self._start
        st.state, st.found, st.note = "done", count, note
        st.finished = time.monotonic()
        self._refresh()

    def start(self, name: str) -> None:
        st = self._rows.get(name)
        if st is not None:
            st.state, st.started = "running", time.monotonic()
            self._refresh()

    # -- rendering ---------------------------------------------------------------------

    def _row(self, name: str, now: float, sweep: float) -> "Text":
        """One row: ``[icon] NAME ....leader.... N unit · time``. Running rows animate the pulse."""
        st = self._rows[name]
        state = st.state
        if state == "running":
            icon, name_style = Text(_spinner_frame(now), style="bold cyan"), "bold white"
            tail = Text(f"{st.found} {st.unit} · running", style="cyan") if st.live_tick \
                else Text("running", style="cyan")
            show_time = st.live_tick
        elif state == "done":
            icon, name_style = Text("✔", style="bold green"), "white"
            tail = Text(f"{st.found} {st.unit}", style="green")
            show_time = True
        elif state == "skipped":
            icon, name_style = Text("○", style="grey50"), "grey50"
            tail = Text(_clean_note(st.note) or "skipped", style="yellow")
            show_time = False
        elif state == "failed":
            icon, name_style = Text("✘", style="bold red"), "red"
            tail = Text("failed", style="bold red")
            show_time = False
        else:  # queued
            icon, name_style = Text(" ", style=MUTED), MUTED
            tail = Text("queued", style=MUTED)
            show_time = False

        line = Text("    ")
        line.append("[", style=MUTED)
        line.append_text(icon)
        line.append("] ", style=MUTED)
        line.append(f"{st.label:<{self._NAME_W}}", style=name_style)
        line.append(" ")
        if state == "running":
            line.append_text(_pulse_leader(self._LEADER_W, sweep))
        else:
            line.append("." * self._LEADER_W, style=MUTED)
        line.append(" ")
        line.append_text(tail)
        if show_time and st.started > 0:
            end = st.finished if st.finished > 0 else now
            line.append(" · ", style=MUTED)
            line.append(_mmss(max(0.0, end - st.started)),
                        style="white" if state == "done" else "cyan")
        try:
            width = self._console.size.width
        except Exception:
            width = 80
        line.truncate(max(20, width - 1), overflow="ellipsis")
        return line

    def _breakdown(self, bd: "_Breakdown") -> list:
        """Render a tree-branch numeric summary (├─ label › value / └─ last › value)."""
        parts: list = [Text(""), Text(f"    {bd.title}", style=f"bold {ACCENT}")]
        lbl_w = max((len(l) for l, _ in bd.rows), default=0)
        for i, (label, value) in enumerate(bd.rows):
            conn = "    └─ " if i == len(bd.rows) - 1 else "    ├─ "
            parts.append(Text.assemble(
                (conn, MUTED), (f"{label:<{lbl_w}}", "white"),
                (" › ", MUTED), (f"{value:,}", "green")))
        return parts

    def stage_block(self, title: str, names: list[str], breakdown: "_Breakdown | None" = None,
                    lead_note: str = "") -> "Group":
        """Renderable for one stage: section rule + its rows (+ optional slow note + breakdown)."""
        now = time.monotonic()
        sweep = (now * 0.9) % 1.0
        parts: list = [Text(""), _section_rule(title)]
        parts.append(Text(""))
        for n in names:
            parts.append(self._row(n, now, sweep))
        # A "[!] AMASS may take longer" note if any listed row is a slow one still running.
        slow_running = [self._rows[n] for n in names
                        if n in self._rows and self._rows[n].slow and self._rows[n].state == "running"]
        if slow_running:
            parts.append(Text(""))
            parts.append(Text("    [!] AMASS may take longer than other passive sources.",
                              style="yellow"))
        if breakdown is not None:
            parts.extend(self._breakdown(breakdown))
        if lead_note:
            parts.append(Text(""))
            parts.append(Text(f"    [!] {lead_note}", style="yellow"))
        return Group(*parts)

    def final_block(self, passive_unique: int, active_new: int) -> "Group":
        """The ── FINAL RESULTS ── block: passive unique + active new = total unique."""
        total = passive_unique + active_new
        parts: list = [Text(""), _section_rule("FINAL RESULTS"), Text("")]
        def row(label: str, value: int, style: str = "green"):
            return Text.assemble(("    ", ""), (f"{label:<20}", "cyan"),
                                 (" › ", MUTED), (f"{value:,}", style))
        parts.append(row("PASSIVE UNIQUE", passive_unique))
        parts.append(row("ACTIVE NEW", active_new))
        parts.append(Text("    " + "─" * 33, style=MUTED))
        parts.append(row("TOTAL UNIQUE", total, "bold green"))
        return Group(*parts)

    # -- live block plumbing (mirrors OSINT's _CategoryDisplay) -------------------------

    def live_stage(self, title: str, names: list[str]):
        """Context manager: animate one stage's rows in a small live block, then leave it as
        static scrollback text (screen=False, transient=False) — identical model to OSINT."""
        return _StageDisplay(self, title, names)

    def _refresh(self) -> None:
        if self._live is not None:
            try:
                self._live.refresh()
            except Exception:
                pass

    # -- headers -----------------------------------------------------------------------

    def print_header(self, show_banner: bool) -> None:
        """Print the full ASCII banner (only when standalone) then the KAALYX::SUBDOMAINS header."""
        if show_banner:
            from . import print_main_banner
            print_main_banner()
            self._console.print()
        self._console.print(stage_header(
            "SUBDOMAINS",
            "initializing subdomain discovery engine...",
            info=[
                ("TARGET", self._target, "bold white"),
                ("SOURCES", f"{self._n_passive} passive · {self._n_active} active", "bold yellow"),
                ("MODE", "passive → active", "white"),
            ],
        ))

    def print_static(self, renderable) -> None:
        """Print a completed block straight to scrollback (used for sections not under a live block)."""
        self._console.print(renderable)

    def print_complete(self, folder: str) -> None:
        """The [◆] KAALYX::SUBDOMAINS COMPLETE panel."""
        elapsed = time.monotonic() - self._start
        self._console.print()
        self._console.print(Text.assemble(
            ("[◆] ", "bold orange1"), ("KAALYX::SUBDOMAINS COMPLETE", "bold orange1")))
        self._console.print(Text.assemble(
            ("    TARGET › ", MUTED), (self._target, "white"),
            (f" · {_mmss(elapsed)}", MUTED)))
        self._console.print()
        self._console.print(Text("    Results saved to:", style=f"bold {ACCENT}"))
        self._console.print(Text(f"    {folder}", style="white"))


def _clean_note(note: str) -> str:
    """Strip a leading 'skipped:' from a skip note for a tidy row."""
    import re
    return re.sub(r"^\s*skipped[:\-]?\s*", "", note or "", flags=re.I).strip()


class _StageDisplay:
    """Live block for ONE stage's rows in normal scrollback (screen=False), with a dedicated
    refresh thread so the pulse animates while the async work runs — the exact model OSINT uses
    for a category block. On exit the finished rows are left in place as static scrollback text."""

    def __init__(self, progress: "SubdomainsProgress", title: str, names: list[str]) -> None:
        self._p = progress
        self._title = title
        self._names = names
        self._live = None
        self._quiet = _QuietTerminal()
        self._stop = None
        self._thread = None

    def _renderable(self):
        return self._p.stage_block(self._title, self._names)

    def _animate(self) -> None:
        while not self._stop.wait(1.0 / 12):
            try:
                self._live.refresh()
            except Exception:
                pass

    def __enter__(self):
        from rich.live import Live
        import threading
        self._quiet.__enter__()
        self._live = Live(
            get_renderable=self._renderable, console=self._p._console,
            screen=False, refresh_per_second=12, auto_refresh=True, transient=False,
            redirect_stdout=True, redirect_stderr=True,
        )
        self._p._live = self._live
        try:
            self._live.__enter__()
            self._stop = threading.Event()
            self._thread = threading.Thread(target=self._animate, daemon=True)
            self._thread.start()
        except Exception:
            self._live = None
            self._p._live = None
            self._quiet.__exit__(None, None, None)
        return self

    def __exit__(self, *exc):
        if self._stop is not None:
            self._stop.set()
        if self._thread is not None:
            try:
                self._thread.join(timeout=0.5)
            except Exception:
                pass
        try:
            if self._live is not None:
                try:
                    self._live.refresh()
                except Exception:
                    pass
                self._live.__exit__(*exc)
        finally:
            self._p._live = None
            self._quiet.__exit__(*exc)
        return False
