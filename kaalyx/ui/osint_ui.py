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

import sys
import time
from dataclasses import dataclass

from rich.box import HEAVY, ROUNDED
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..core.logging import get_console


class _QuietTerminal:
    """Context manager that disables tty ECHO + canonical input for its body, then drains any
    buffered keystrokes on exit — so keys pressed while a rich.Live board is up are neither
    echoed onto the screen (which would make the board reprint) nor left queued for the shell.

    A no-op when stdin isn't a real tty (pipes, CI) or on platforms without ``termios``
    (Windows) — the ``with`` block still runs, just without terminal tweaks.
    """

    def __init__(self) -> None:
        self._fd = None
        self._saved = None

    def __enter__(self):
        try:
            import termios
            if not sys.stdin.isatty():
                return self
            self._fd = sys.stdin.fileno()
            self._saved = termios.tcgetattr(self._fd)
            new = termios.tcgetattr(self._fd)
            # lflags: drop ECHO (don't print typed chars) and ICANON (don't line-buffer).
            new[3] = new[3] & ~(termios.ECHO | termios.ICANON)
            termios.tcsetattr(self._fd, termios.TCSANOW, new)
        except Exception:
            # Any failure (no termios, not a tty, restricted env) => just run without tweaks.
            self._fd = None
        return self

    def __exit__(self, *exc):
        if self._fd is None or self._saved is None:
            return False
        try:
            import termios
            # Discard anything typed during the board, then restore the original tty mode.
            termios.tcflush(self._fd, termios.TCIFLUSH)
            termios.tcsetattr(self._fd, termios.TCSANOW, self._saved)
        except Exception:
            pass
        return False


class _FdCapture:
    """Capture EVERYTHING written to the real stdout/stderr file descriptors (1 and 2) for the
    duration, so no write from ANY source can corrupt an in-place ``rich.Live`` board.

    This is the general, root-cause defence against the "board prints itself twice" bug. rich's
    own ``redirect_stdout``/``redirect_stderr`` only wrap the Python-level ``sys.stdout`` /
    ``sys.stderr`` objects — they do NOT catch writes that reach the terminal by other routes:
    a C extension writing to fd 1, a subprocess that inherited the fd, an ``os.write(2, …)``, a
    late ``ResourceWarning``/asyncio "unclosed"/"Task exception" message emitted at the C level,
    or anything a third-party library prints straight to the descriptor. Any such byte lands on
    the terminal between Live's cursor-up and its redraw, so Live miscounts the previous frame's
    height and paints a fresh board below the old one.

    We redirect fds 1 and 2 to an OS pipe and drain it on a daemon thread, forwarding captured
    bytes to the rotating FILE log (never the terminal) so nothing is lost but nothing reaches
    the screen except Live's frames. rich's Live keeps its OWN saved handle to the real terminal
    (``console.file``), so the board itself still renders. A no-op when stdout isn't a real
    terminal (pipes/CI/redirected output) or on platforms without ``os.dup2`` semantics we can
    rely on (Windows) — there the existing Python-level redirects remain the defence.
    """

    def __init__(self) -> None:
        self._active = False
        self._saved_fds: dict[int, int] = {}
        self._pipe_r = None
        self._pipe_w = None
        self._thread = None
        #: A writable text stream on the REAL terminal (a dup of fd 1 taken before redirection),
        #: for the Live board to render through while fds 1/2 point at the capture pipe. ``None``
        #: when capture is inactive (caller then keeps using the normal console file).
        self.terminal_stream = None

    def __enter__(self):
        # Only meaningful on a POSIX tty; Windows lacks the fd-dup semantics we depend on.
        try:
            if sys.platform == "win32" or not sys.stdout.isatty():
                return self
            import os
            # Take a dup of the real terminal (fd 1) FIRST and wrap it as a text stream — the
            # board renders through this so it still reaches the screen after we redirect fd 1.
            real_term_fd = os.dup(1)
            self.terminal_stream = os.fdopen(real_term_fd, "w", encoding="utf-8", closefd=True)
            self._pipe_r, self._pipe_w = os.pipe()
            for fd in (1, 2):
                try:
                    self._saved_fds[fd] = os.dup(fd)     # remember the real terminal fd
                    os.dup2(self._pipe_w, fd)            # point 1/2 at the pipe's write end
                except OSError:
                    self._saved_fds.pop(fd, None)
            if not self._saved_fds:
                self.terminal_stream = None
                self._teardown_pipe()
                return self
            import threading
            self._thread = threading.Thread(target=self._drain, daemon=True)
            self._thread.start()
            self._active = True
        except Exception:
            self._restore_fds()
            self._teardown_pipe()
            self.terminal_stream = None
        return self

    def _drain(self) -> None:
        """Read captured bytes off the pipe and log them to the file logger, off the screen."""
        import os
        from ..core.logging import get_logger
        log = get_logger("captured")
        buf = b""
        while True:
            try:
                chunk = os.read(self._pipe_r, 4096)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, _, buf = buf.partition(b"\n")
                text = line.decode("utf-8", "replace").rstrip()
                if text:
                    log.debug("stray terminal write during board: %s", text)

    def _restore_fds(self) -> None:
        import os
        for fd, saved in self._saved_fds.items():
            try:
                os.dup2(saved, fd)   # restore the real terminal onto 1/2
                os.close(saved)
            except OSError:
                pass
        self._saved_fds.clear()

    def _teardown_pipe(self) -> None:
        import os
        for p in (self._pipe_w, self._pipe_r):
            if p is not None:
                try:
                    os.close(p)
                except OSError:
                    pass
        self._pipe_w = self._pipe_r = None

    def __exit__(self, *exc):
        if not self._active:
            self._restore_fds()
            self._teardown_pipe()
            return False
        import os
        # Restore the real fds FIRST so later output goes to the terminal again, then close the
        # write end so the drain thread sees EOF and exits, then clean up.
        self._restore_fds()
        try:
            if self._pipe_w is not None:
                os.close(self._pipe_w)
                self._pipe_w = None
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        try:
            if self._pipe_r is not None:
                os.close(self._pipe_r)
                self._pipe_r = None
        except OSError:
            pass
        self._active = False
        return False


class _LiveWithQuietTerminal:
    """Wrap a ``rich.Live`` context manager so entering/exiting it also (a) enters/exits a
    :class:`_QuietTerminal` for keypress-robustness and (b) installs a terminal-resize handler
    that keeps the board a single in-place frame.

    Resize is the second duplicate-frame trigger: rich overwrites the previous frame by moving
    the cursor UP by the previously-rendered line count; a resize between refreshes changes how
    many physical lines that frame occupies, so the cursor-up misses and the next frame draws
    below the old one. On SIGWINCH we clear the LiveRender's cached shape and force a refresh,
    so the next frame is drawn cleanly at the current size instead of over a miscounted one."""

    def __init__(self, live) -> None:
        self._live = live
        self._quiet = _QuietTerminal()
        self._fdcap = _FdCapture()
        self._prev_winch = None
        self._orig_console_file = None

    def _on_resize(self, *_):
        try:
            # Drop the stale "previous frame height" so rich doesn't cursor-up over a frame
            # whose real line count just changed, then repaint at the new size.
            self._live._live_render._shape = None  # type: ignore[attr-defined]
            self._live.refresh()
        except Exception:
            pass

    def __enter__(self):
        self._quiet.__enter__()
        # Capture the real stdout/stderr fds so NOTHING but the board reaches the terminal, then
        # point the Live console at the preserved real-terminal stream so the board still renders.
        self._fdcap.__enter__()
        if self._fdcap.terminal_stream is not None:
            try:
                self._orig_console_file = self._live.console.file
                self._live.console.file = self._fdcap.terminal_stream
            except Exception:
                self._orig_console_file = None
        try:
            result = self._live.__enter__()
        except Exception:
            if self._orig_console_file is not None:
                self._live.console.file = self._orig_console_file
                self._orig_console_file = None
            self._fdcap.__exit__(None, None, None)
            self._quiet.__exit__(None, None, None)
            raise
        try:
            import signal
            if hasattr(signal, "SIGWINCH"):
                self._prev_winch = signal.getsignal(signal.SIGWINCH)
                signal.signal(signal.SIGWINCH, self._on_resize)
        except Exception:
            self._prev_winch = None
        return result

    def __exit__(self, *exc):
        try:
            if self._prev_winch is not None:
                import signal
                try:
                    signal.signal(signal.SIGWINCH, self._prev_winch)
                except Exception:
                    pass
            return self._live.__exit__(*exc)
        finally:
            # Restore the console file, then release the fd capture (terminal back to normal),
            # then the tty mode. Order matters: Live must be torn down before we drop capture.
            if self._orig_console_file is not None:
                try:
                    self._live.console.file = self._orig_console_file
                except Exception:
                    pass
                self._orig_console_file = None
            self._fdcap.__exit__(*exc)
            self._quiet.__exit__(*exc)
from . import ACCENT, ACCENT_DIM, MUTED, severity_style


def format_duration(seconds: float) -> str:
    """Human duration: plain seconds below 60s (``4.2s``), MM:SS at/above 60s (``2:16``).

    Used everywhere elapsed time is shown — per-source rows, the board header, and the final
    summary panel — so the format is consistent. At/above an hour it rolls to H:MM:SS.
    """
    secs = max(0.0, seconds)
    if secs < 60:
        return f"{secs:0.1f}s"
    total = int(round(secs))
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}:{m:02d}:{s:02d}"
    return f"{m}:{s:02d}"

def print_banner(domain: str, source_count: int) -> None:
    """Print the OSINT stage header in the PERMANENT ``[◆] KAALYX::<STAGE>`` format, preceded by
    the main banner. Only the stage name/subtitle and the TARGET/SOURCES/MODE values differ
    between stages — the format and palette are locked (see :func:`ui.stage_header`)."""
    from . import (print_main_banner, stage_header,
                   STAGE_DOMAIN, STAGE_COUNT, STAGE_MODE)

    console = get_console()

    # Main banner + one blank line precede the stage header (the confirmed sequence).
    print_main_banner()
    console.print()

    console.print(stage_header(
        "OSINT",
        "initializing passive recon engine...",
        info=[
            ("TARGET", domain, STAGE_DOMAIN),
            ("SOURCES", f"{source_count} registered", STAGE_COUNT),
            ("MODE", "passive · queries third-party data, no packets to the target",
             STAGE_MODE),
        ],
    ))
    console.print()


# --- Live progress ----------------------------------------------------------------------

_SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def _classify_skip(note: str) -> str:
    """Split a generic skip into an actionable sub-state from its note text:

      * ``not_installed`` — the tool isn't on PATH ("skipped: <tool> not on PATH/runnable").
        More urgent: the user can install it.
      * ``no_key`` — a required key/token is missing ("skipped: <KEY> not set").
      * ``skipped`` — a deliberate no-input skip (no emails to check, no org identified, etc.).
    """
    low = note.lower()
    if "not on path" in low or "not runnable" in low or "not installed" in low:
        return "not_installed"
    if "not set" in low or "_token" in low or "_key" in low or "github_token" in low:
        return "no_key"
    return "skipped"


def _skip_note(note: str) -> str:
    """Clean the raw skip note for the board — drop a leading 'skipped:' prefix and, for a
    no-key skip, phrase it as '<KEY> not set in config.env'."""
    import re
    n = re.sub(r"^\s*skipped[:\-]?\s*", "", note or "", flags=re.I).strip()
    m = re.search(r"([A-Z][A-Z0-9_]{3,})\s+not set", n)
    if m:
        return f"{m.group(1)} not set in config.env"
    return n


# Source name -> the hacker-terminal display name (UPPERCASE_SNAKE with optional [context]).
# Keyed by the internal source name; falls back to upper-casing the name if absent.
_DISPLAY_NAMES: dict[str, str] = {
    "whois": "WHOIS",
    "dns": "DNS_RECORDS[dnsx]",
    "ip_info": "IP_INTEL[geo/asn]",
    "mail_dns": "MAIL_DNS_SEC",
    "m365": "M365_TENANT",
    "email_harvest": "EMAIL_HARVEST",
    "social": "SOCIAL_PROFILES",
    "github_subdomains": "GITHUB_SUBDOMAINS",
    "trufflehog": "TRUFFLEHOG[org]",
    "cloud_enum": "CLOUD_ENUM",
    "s3scanner": "S3_SCANNER",
    "badsecrets": "BADSECRETS",
    "retirejs": "RETIRE_JS",
    "theharvester": "THEHARVESTER",
    "third_party_misconfig": "3RDPARTY_MISCONFIG",
    "api_leaks": "API_LEAKS[postman/swagger]",
    "exposed_git": "EXPOSED_GIT",
    "firebase": "FIREBASE_RTDB[exposure]",
    "github_actions": "GITHUB_ACTIONS[gato]",
    "google_dorks": "GOOGLE_DORKS",
    "breach_lookup": "BREACH_LOOKUP[h8mail]",
    "leak_search": "LEAKSEARCH",
    "shodan_org": "SHODAN_ORG[asn]",
    "shodan_favicon": "SHODAN_FAVICON[pivot]",
    "shodan_vulns": "SHODAN_CVE[tags]",
    "shodan_host": "SHODAN_HOST[deep]",
    "internetdb": "INTERNETDB[free]",
    "tls_cert": "TLS_CERT[san/issuer]",
    "gitlab": "GITLAB[groups]",
    "dockerhub": "DOCKERHUB[repos]",
    "mobile_apps": "MOBILE_APPS[ios/android]",
    "affiliate_domains": "AFFILIATE_DOMAINS[crt.sh]",
    "dnstwist": "DNSTWIST[typosquat]",
    "workflow_logs": "WORKFLOW_LOGS[ci-secrets]",
}


def _display_name(source_name: str, fallback_label: str = "") -> str:
    return _DISPLAY_NAMES.get(source_name) or source_name.upper() or fallback_label


@dataclass
class _SourceState:
    label: str
    # queued | running | done | skipped | no_key | not_installed | failed
    state: str = "queued"
    items: int = 0
    note: str = ""
    started: float = 0.0
    finished: float = 0.0
    # Optional live progress "done/total" for a running source (e.g. LEAKSEARCH 23/47).
    prog_done: int = 0
    prog_total: int = 0


class OsintProgress:
    """A live, in-place status board for concurrently-running OSINT sources.

    Usage::

        progress = OsintProgress({name: human_label, ...})
        with progress.live():
            results = await run_sources(sources, progress.hook)

    The status board re-renders as sources start and finish, so the user sees every
    sub-check's state at a glance rather than a silent wait.
    """

    def __init__(self, labels: dict[str, str], target: str = "") -> None:
        self._console = get_console()
        self._target = target
        self._states: dict[str, _SourceState] = {
            name: _SourceState(label=label) for name, label in labels.items()
        }
        self._live = None
        self._start = time.monotonic()

    def set_progress(self, name: str, done: int, total: int) -> None:
        """Update a running source's live done/total counter (e.g. LEAKSEARCH 23/47). Redraws
        the SAME row in place — never prints a new line."""
        st = self._states.get(name)
        if st is None:
            return
        st.prog_done, st.prog_total = done, total
        self._refresh()

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
                # Split the generic "skipped" into distinct, actionable sub-states.
                st.state = _classify_skip(st.note)
            else:
                st.state = "done"
        self._refresh()


    # Column geometry for the source rows (aligned; leaders fill the middle).
    _NAME_W = 30      # width reserved for "NAME[context]" before the dotted leader
    _RESULT_W = 9     # right-aligned result field ("00 hits" / "RUNNING" / "23/47")
    _BAR_W = 46       # progress-bar inner width

    def _mmss(self, secs: float) -> str:
        """Time for the bar/running rows: 'S.Ss' under a minute, zero-padded 'MM:SS' at/above
        (e.g. 5.2s, 02:25), and 'H:MM:SS' past an hour."""
        secs = max(0.0, secs)
        if secs < 60:
            return f"{secs:0.1f}s"
        total = int(round(secs))
        h, rem = divmod(total, 3600)
        m, s = divmod(rem, 60)
        return f"{h}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"

    def _progress_bar(self, done: int, total: int) -> "Text":
        """[=====>....] filled with '=', a '>' arrowhead at the leading edge, '.' unfilled."""
        total = max(total, 1)
        filled = int(round(self._BAR_W * done / total))
        filled = min(filled, self._BAR_W)
        if filled <= 0:
            inner = "." * self._BAR_W
        elif filled >= self._BAR_W:
            inner = "=" * self._BAR_W
        else:
            inner = ("=" * (filled - 1)) + ">" + ("." * (self._BAR_W - filled))
        return Text.assemble(("[", ACCENT_DIM), (inner, ACCENT), ("]", ACCENT_DIM))

    def _row(self, st: "_SourceState", name: str, now: float, frame: str,
             pos: int = 0, total: int = 0) -> "Text":
        """One source row: '[N/T] [icon] NAME ......... RESULT :: TIME' (name = display name).

        *pos*/*total* prepend a right-aligned '[N/TOTAL]' position tag so the operator sees both
        which source this is and where it sits in the overall run."""
        # --- status icon + name/result/time by state ---
        note = ""
        show_time = True
        if st.state == "running":
            icon = Text("~", style="bold cyan")
            name_style = "bold white"
            # LEAKSEARCH-style live counter, else "RUNNING".
            if st.prog_total > 0:
                result = Text(f"{st.prog_done}/{st.prog_total}", style="cyan")
            else:
                result = Text("RUNNING", style="cyan")
        elif st.state == "done":
            icon = Text("✓", style="bold green")
            name_style = "white"
            result = Text(f"{min(st.items, 99):02d} hits", style="green")
        elif st.state == "not_installed":
            icon = Text("✘", style="bold orange1")
            name_style = "orange1"
            result = Text("not installed", style="bold orange1")
            note = "run: kaalyx tools --install"
            show_time = False
        elif st.state == "no_key":
            icon = Text(" ", style=MUTED)
            name_style = "yellow"
            result = Text("no key", style="yellow")
            note = _skip_note(st.note)
            show_time = False
        elif st.state == "skipped":
            icon = Text(" ", style=MUTED)
            name_style = MUTED
            result = Text("skipped", style=MUTED)
            note = _skip_note(st.note)
            show_time = False
        elif st.state == "failed":
            icon = Text("✘", style="bold red")
            name_style = "red"
            result = Text("FAILED", style="bold red")
            note = st.note
            show_time = False
        else:  # queued
            icon = Text(" ", style=MUTED)
            name_style = MUTED
            result = Text("queued", style=MUTED)
            show_time = False

        # Dotted leader: name, then dots to fill, then result. Compute visible widths.
        name_txt = Text(name, style=name_style)
        # dots between name and result (leave a space each side)
        result_len = len(result.plain)
        pad = max(1, self._NAME_W + self._RESULT_W - len(name) - result_len)
        line = Text("    ")                         # 4-space indent
        if total:
            # Right-align N within the width of TOTAL so the [N/T] column stays aligned.
            w = len(str(total))
            line.append(f"[{pos:>{w}}/{total}] ", style=MUTED)
        line.append("[", style=MUTED)
        line.append_text(icon)
        line.append("] ", style=MUTED)
        line.append_text(name_txt)
        line.append(" " + "." * pad + " ", style=MUTED)
        line.append_text(result)
        if show_time:
            end = st.finished if st.finished > 0 else now
            t = self._mmss(max(0.0, end - st.started)) if st.started > 0 else ""
            line.append(" :: ", style=MUTED)
            line.append(f"{t:>5}", style="white" if st.state == "done" else "cyan")
        elif note:
            # Keep the row on ONE line — trim an over-long note so the board never wraps.
            n = note if len(note) <= 40 else note[:39] + "…"
            line.append("  ", style=MUTED)
            line.append(n, style=MUTED)
        return line

    def _render(self):
        now = time.monotonic()
        frame = _SPINNER_FRAMES[int((now * 12)) % len(_SPINNER_FRAMES)]
        total = len(self._states)
        done = sum(1 for s in self._states.values()
                   if s.state not in ("queued", "running"))

        lines = []
        # NO stage header here — the single stage header ([◆] KAALYX::OSINT + TARGET/SOURCES/MODE)
        # is printed once by print_banner() BEFORE the board. The live board renders only the
        # progress bar + per-source rows beneath it, so the header never appears twice.
        # 1) Progress bar + N/total :: elapsed
        elapsed = time.monotonic() - self._start
        bar = self._progress_bar(done, total)
        bar_line = Text("    ")
        bar_line.append_text(bar)
        bar_line.append(f" {done}/{total} ", style="white")
        bar_line.append(":: ", style=MUTED)
        bar_line.append(self._mmss(elapsed), style="white")
        lines.append(bar_line)
        lines.append(Text(""))
        # 3) One row per source, in insertion (pipeline) order — ALWAYS every source, including
        #    queued ones (shown as "queued"). Rows are never hidden or collapsed behind a summary;
        #    if the board is taller than the terminal, the Live uses vertical_overflow="visible"
        #    (see live()) so the content scrolls through normal terminal history instead of being
        #    clipped with an ellipsis.
        for i, (name, st) in enumerate(self._states.items(), start=1):
            lines.append(self._row(st, _display_name(name, st.label), now, frame,
                                    pos=i, total=total))
        return Group(*lines)

    def _refresh(self) -> None:
        if self._live is not None:
            self._live.refresh()

    def live(self):
        """Context manager yielding an auto-refreshing ``rich.Live`` board that stays a SINGLE
        in-place frame regardless of terminal interaction (keypresses, resize).

        ``get_renderable=self._render`` makes Live recompute the board on every one of its
        ``refresh_per_second`` ticks (not only on start/finish events), so the spinner frame
        — derived from the clock in ``_render`` — animates continuously even while a slow
        source blocks between events.

        Robustness against duplicate frames (the board re-printing itself):
          * ``redirect_stdout/stderr`` capture any stray program write during the fan-out.
          * A terminal-mode guard (:class:`_QuietTerminal`) disables tty ECHO + canonical mode
            for the duration, so stray KEYPRESSES aren't echoed onto the screen — an echoed
            char is console output Live didn't emit, which makes a non-transient Live
            checkpoint the current frame and start a fresh one below (the "board printed N
            times" bug). Draining is best-effort and a no-op off a real tty / on Windows.
          * RESIZE: rich 13.x re-reads the console size every refresh and redraws in place; the
            terminal guard removes the only remaining trigger (echoed input), so a resize alone
            just reflows the same single frame.
        """
        from rich.live import Live

        live = Live(
            get_renderable=self._render,
            console=self._console,
            refresh_per_second=12,
            auto_refresh=True,
            transient=False,
            redirect_stdout=True,
            redirect_stderr=True,
            # Show EVERY source row always; when the board is taller than the terminal, let it
            # scroll through normal terminal history rather than clipping the tail with an
            # ellipsis (rich's default "ellipsis"). Never hide/collapse rows.
            vertical_overflow="visible",
        )
        self._live = live
        return _LiveWithQuietTerminal(live)


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


# Fixed display order for the email/DNS posture table — every type ALWAYS shown (found or not).
_MAIL_ROW_ORDER = ("spf", "dmarc", "dkim", "caa", "mta_sts", "tls_rpt", "bimi")


def _dmarc_interpretation(dmarc_value: str) -> str:
    """One-line plain-English takeaway for a DMARC record's PRIMARY policy (the ``p=`` tag).

    Keys strictly on the ``p=`` value (not any occurrence of 'reject'/'quarantine' — a
    ``sp=reject`` subdomain policy must not be mistaken for the main policy).
    """
    import re as _re
    low = (dmarc_value or "").lower()
    if "not found" in low or not low.startswith("v=dmarc1"):
        return "no DMARC — spoofing NOT blocked; recipients have no policy to enforce"
    m = _re.search(r"(?:^|;)\s*p\s*=\s*(none|quarantine|reject)", low)
    p = m.group(1) if m else ""
    if p == "reject":
        return "DMARC p=reject — strict enforcement, spoofing actively blocked"
    if p == "quarantine":
        return "DMARC p=quarantine — spoofed mail sent to spam, not outright rejected"
    if p == "none":
        return "DMARC p=none — monitoring only, spoofing NOT blocked"
    return "DMARC present — policy unclear from the record"


def mail_hygiene_table(records: list) -> Table | None:
    """Show the full email/DNS security posture: SPF, DMARC, DKIM, CAA, MTA-STS, TLS-RPT, BIMI
    (every type ALWAYS present — its value, or an explicit dim "not found"), then the SPOOFABLE
    verdict with a one-line plain-English interpretation."""
    by_kind: dict[str, list] = {}
    for r in records:
        by_kind.setdefault(r["kind"], []).append(r)
    if not any(k in by_kind for k in _MAIL_ROW_ORDER) and "spoofable" not in by_kind:
        return None

    table = Table(title="Email / DNS Security Posture", box=ROUNDED,
                  border_style=ACCENT_DIM, title_style=f"bold {ACCENT}",
                  header_style="bold white")
    table.add_column("Record", style="cyan", no_wrap=True)
    table.add_column("Value", style="white", overflow="fold")

    for kind in _MAIL_ROW_ORDER:
        label = kind.upper().replace("_", "-")
        rows = by_kind.get(kind)
        if not rows:
            # Type wasn't emitted at all — still show it so the table is complete.
            table.add_row(label, Text("not found", style=MUTED))
            continue
        for r in rows:
            val = str(r["value"])
            if val.lower().startswith("not found"):
                table.add_row(label, Text(val, style=MUTED))
            else:
                table.add_row(label, val)

    # SPOOFABLE verdict + plain-English interpretation of the DMARC enforcement.
    spoof = (by_kind.get("spoofable") or [None])[0]
    if spoof is not None:
        spoofable = str(spoof["value"]).lower() == "yes"
        dmarc_val = (by_kind.get("dmarc") or [{"value": "not found"}])[0]["value"]
        verdict = Text(
            f"YES — {spoof['detail']}" if spoofable else f"no — {spoof['detail']}",
            style="bold red" if spoofable else "green",
        )
        table.add_row(Text("SPOOFABLE", style="bold"), verdict)
        table.add_row("", Text(_dmarc_interpretation(dmarc_val),
                               style="red" if spoofable else "green"))
    return table


_WHOIS_SECTION_TITLES = {
    "registrar": "Registrar",
    "registrant": "Registrant",
    "dates": "Dates",
    "nameservers": "Nameservers",
    "status": "Status",
}


def whois_table(records: list):
    """Show WHOIS data as a clean, grouped list (the whois source) instead of a raw dump.

    Records carry ``detail = "<category>|<label>"`` (from parse_whois). We group them under
    clear section headings — Registrar, Registrant, Dates, Nameservers, Status — in a fixed
    order, each field on its own aligned 'Label : value' row. Returns a Group renderable, or
    ``None`` when there are no whois records."""
    rows = [r for r in records if r["kind"] == "whois"]
    if not rows:
        return None

    # Bucket rows by category, preserving encounter order within each.
    buckets: dict[str, list[tuple[str, str]]] = {}
    for r in rows:
        detail = r["detail"] or "other|"
        category, _, label = detail.partition("|")
        buckets.setdefault(category, []).append((label or "", r["value"]))

    order = ["registrar", "registrant", "dates", "nameservers", "status"]
    ordered = [c for c in order if c in buckets] + [c for c in buckets if c not in order]

    lines: list = [Text.assemble(("[◆] ", "bold orange1"), ("WHOIS", "bold orange1"),
                                 (" :: registration & ownership", MUTED)), Text("")]
    for ci, category in enumerate(ordered):
        title = _WHOIS_SECTION_TITLES.get(category, category.title())
        lines.append(Text(f"  {title}", style=f"bold {ACCENT}"))
        fields = buckets[category]
        lbl_w = max((len(l) for l, _ in fields), default=0)
        for label, value in fields:
            lines.append(Text.assemble(("    ", ""),
                                       (f"{label:<{lbl_w}}", "cyan"),
                                       ("  ", ""), (value, "white")))
        if ci != len(ordered) - 1:
            lines.append(Text(""))
    return Group(*lines)


def social_table(records: list) -> Table | None:
    """Show discovered social-media profiles (the social source) as a table, so the data is
    visible during the scan instead of only saved to social.txt."""
    rows = [r for r in records if r["kind"] == "social"]
    if not rows:
        return None
    table = Table(title="Social Profiles", box=ROUNDED, border_style=ACCENT_DIM,
                  title_style=f"bold {ACCENT}", header_style="bold white")
    table.add_column("Platform", style="cyan", no_wrap=True)
    table.add_column("Handle / Profile", style="white", overflow="fold")
    for r in rows:
        # value is "<platform>: <handle>"; detail is the platform. Split for clean columns.
        val = r["value"]
        platform = (r["detail"] or (val.split(":", 1)[0] if ":" in val else "")).strip()
        handle = val.split(":", 1)[1].strip() if ":" in val else val
        table.add_row(platform, handle)
    return table


def _parse_ip_detail(detail: str) -> dict:
    """Parse the ``key=value|..`` detail string emitted by ip_info back into a dict. Recognises
    the total-failure form ``failed=1|tried=src:reason,src:reason``."""
    out: dict = {}
    for part in (detail or "").split("|"):
        if "=" not in part:
            continue
        k, _, v = part.partition("=")
        out[k.strip()] = v.strip()
    if out.get("failed") == "1":
        trail = out.get("tried", "")
        pairs = []
        for item in trail.split(","):
            if ":" in item:
                src, _, reason = item.partition(":")
                pairs.append((src.strip(), reason.strip()))
            elif item.strip():
                pairs.append((item.strip(), "failed"))
        out["_tried"] = pairs
    return out


# Dotted-leader helper so every field label lines up like the OSINT board rows.
def _leader(label: str, width: int = 12) -> str:
    dots = "." * max(4, width - len(label) + 4)
    return f"{label} {dots}"


def host_intel_table(records: list):
    """Tree-style IP intelligence view (the ip_info source): resolved-IP geolocation / ASN /
    ISP-org / reverse-IP, shown by default rather than buried in the raw files.

    Renders in the project's hacker/cybersec idiom — an ``[◆] IP_INTEL :: geo/asn lookup``
    header, each IP as a branch with ``├─``/``└─`` connectors for COUNTRY/ASN/ORG/ISP/REVERSE.
    A field the lookup couldn't fill (even after all fallbacks) shows ``[unavailable]`` rather
    than being dropped. When every geo source failed for an IP, a clear failure block lists
    which sources were tried and why each failed (timeout / rate-limited / …)."""
    rows = [r for r in records if r["kind"] == "ip_info"]
    if not rows:
        return None

    lines: list = []
    lines.append(Text.assemble(("[◆] ", "bold orange1"), ("IP_INTEL", "bold orange1"),
                                (" :: ", MUTED), ("geo/asn lookup", "orange1")))
    lines.append(Text(""))

    UNAVAIL = Text("[unavailable]", style="yellow")

    for r in rows:
        ip = r["value"]
        info = _parse_ip_detail(r["detail"])
        # TARGET_IP header row for this address.
        lines.append(Text.assemble(("    ", ""),
                                    (_leader("TARGET_IP", 12), "bold white"),
                                    (" ", ""), (ip, "bold cyan")))

        if info.get("failed") == "1":
            # Total failure: every source exhausted. List each source tried and why.
            tried = info.get("_tried", [])
            lines.append(Text.assemble(("    └─ ", "red"),
                                       ("GEO LOOKUP FAILED — all sources exhausted", "bold red")))
            for i, (src, reason) in enumerate(tried):
                conn = "       └─ " if i == len(tried) - 1 else "       ├─ "
                lines.append(Text.assemble((conn, MUTED), (f"{src} ", "white"),
                                           (f"→ {reason}", "yellow")))
            lines.append(Text(""))
            continue

        # Success (possibly partial). Build the field branches; missing → [unavailable].
        country = info.get("country", "")
        cc = info.get("cc", "")
        country_disp = (f"{country} ({cc})" if country and cc else (country or cc))
        asn = info.get("asn", "")
        org = info.get("org", "")
        isp = info.get("isp", "")
        reverse = info.get("reverse", "")
        via = info.get("via", "")

        branches = [
            ("COUNTRY", country_disp, "white"),
            ("ASN", asn, "green"),
            ("ORG", org, "white"),
            ("ISP", isp, "white"),
        ]
        if reverse:
            branches.append(("REVERSE", reverse, "cyan"))

        for i, (label, val, style) in enumerate(branches):
            conn = "    └─ " if i == len(branches) - 1 else "    ├─ "
            val_txt = Text(val, style=style) if val else UNAVAIL
            lines.append(Text.assemble((conn, ACCENT_DIM),
                                       (_leader(label, 10), "bold white"),
                                       (" ", ""), *_as_assemble(val_txt)))
        if via:
            lines.append(Text.assemble(("       via ", MUTED), (via, MUTED)))
        lines.append(Text(""))

    # Drop the trailing blank line for a tight block.
    while lines and isinstance(lines[-1], Text) and str(lines[-1]) == "":
        lines.pop()
    return Group(*lines)


def _as_assemble(txt: Text):
    """Yield a single (text, style) tuple from a Text so it can be spread into Text.assemble."""
    return [(txt.plain, txt.style or "")]


# Category → human section title, in the order we present them.
_CATEGORY_TITLES = [
    ("secret", "Secrets & Credentials"),
    ("credential-leak", "Leaked Credentials"),
    ("api-leak", "API Leaks"),
    ("cloud", "Cloud Resources"),
    ("ci-cd", "CI/CD (GitHub Actions)"),
    ("third-party-misconfig", "Third-party Misconfigurations"),
    ("email-security", "Email / DNS Security"),
    ("tenant-mapping", "Tenant Mapping"),
    ("attack-surface", "Attack Surface (Shodan org/ASN)"),
    ("related-infra", "Related Infrastructure (favicon pivot)"),
    ("cve", "Known CVE Tags (passive)"),
    ("exposed-git", "Exposed / Downloadable .git"),
    ("typosquatting", "Typosquatting / Look-alike Domains"),
]
_SEV_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}


def _is_complex(row) -> bool:
    """A finding needs the spacious CARD format (not a table row) when its detail is large or
    multi-line — e.g. a hardcoded Postman credential with request/header/value/URL. A short,
    single-line detail (TruffleHog's ``repo | file:line | masked``) fits a compact table."""
    ev = _row_get(row, "evidence")
    return "\n" in ev or len(ev) > 100


def _finding_card(row):
    """Render one complex finding as a bordered card with every detail line visible."""
    sev = _row_get(row, "severity", "unknown")
    title = _row_get(row, "title")
    body = Table.grid(padding=(0, 1))
    body.add_column(style="cyan", no_wrap=True)     # label
    body.add_column(style="white", overflow="fold")  # value (wraps, never truncates)
    body.add_row(Text(sev.upper(), style=severity_style(sev)), _verified_cell(row))
    tgt = _row_get(row, "target")
    if tgt:
        body.add_row("Target", Text(tgt))
    # evidence is newline-separated lines. Some are structured "Label: value" (from the Postman
    # parser); others are free text that legitimately contains a colon (a URL like
    # ``https://host/.json``, ``preview: {...}`` with JSON). Only split on the first colon when
    # the part before it looks like a short label — no spaces, no slashes, and reasonably short —
    # so a colon inside a URL/value never gets mistaken for a label separator.
    ev = _row_get(row, "evidence")
    if "\n" in ev:
        for line in ev.split("\n"):
            head = line.partition(":")[0]
            is_label = (":" in line and head.strip()
                        and " " not in head.strip() and "/" not in head
                        and len(head.strip()) <= 16)
            # Wrap value cells in Text() so a value containing rich-markup brackets — a full
            # secret value, or a "[redacted:N]" marker — renders literally, never as markup.
            if is_label:
                lbl, _, val = line.partition(":")
                body.add_row(lbl.strip(), Text(val.strip()))
            elif line.strip():
                body.add_row("", Text(line.strip()))
    else:
        body.add_row("Detail", Text(ev or _row_get(row, "description")))
    return Panel(body, title=Text(title, style="bold white"), title_align="left",
                 border_style=severity_style(sev), box=ROUNDED, padding=(0, 1))


def _simple_findings_table(rows: list, section_title: str) -> Table:
    """Compact table for simple findings (short single-line detail), full width, folding."""
    table = Table(title=section_title, box=ROUNDED, border_style=ACCENT_DIM,
                  title_style=f"bold {ACCENT}", header_style="bold white", expand=True)
    table.add_column("Sev", width=9, no_wrap=True)
    table.add_column("Verified", width=10, justify="center", no_wrap=True)
    table.add_column("Title", style="white", overflow="fold", ratio=2, min_width=18)
    table.add_column("Detail", style=MUTED, overflow="fold", ratio=3, min_width=22)
    for r in rows:
        sev = _row_get(r, "severity", "unknown")
        detail = _row_get(r, "evidence") or _row_get(r, "target") or ""
        table.add_row(
            Text(sev.upper(), style=severity_style(sev)),
            _verified_cell(r), _row_get(r, "title"), Text(detail, style=MUTED),
        )
    return table


def render_findings(rows: list, limit: int = 40) -> list:
    """Findings rendered Option-3 style: GROUPED BY CATEGORY, each group using the format that
    fits its detail — a compact table for simple findings, spacious cards for complex ones.

    Returns a list of renderables (section header + table/cards per category) so no detail is
    ever truncated to keep a uniform table tidy. Empty list when there are no findings.
    """
    if not rows:
        return []
    rows = sorted(rows, key=lambda r: _SEV_ORDER.get(_row_get(r, "severity", "unknown"), 0),
                  reverse=True)[:limit]
    # Bucket by category, preserving the presentation order; unknown categories go last.
    buckets: dict[str, list] = {}
    for r in rows:
        buckets.setdefault(_row_get(r, "category", "other") or "other", []).append(r)

    ordered_cats = [c for c, _ in _CATEGORY_TITLES if c in buckets]
    ordered_cats += [c for c in buckets if c not in ordered_cats]
    title_map = dict(_CATEGORY_TITLES)

    out: list = [Text("Findings", style=f"bold {ACCENT}")]
    for cat in ordered_cats:
        group = buckets[cat]
        section = title_map.get(cat, cat.replace("-", " ").title())
        complex_rows = [r for r in group if _is_complex(r)]
        simple_rows = [r for r in group if not _is_complex(r)]
        if simple_rows:
            out.append(_simple_findings_table(simple_rows, section))
        for r in complex_rows:
            out.append(_finding_card(r))
    return out


def findings_table(rows: list, limit: int = 25):
    """Back-compat shim: return a Group of the grouped-findings renderables (or ``None``)."""
    parts = render_findings(rows, limit=limit)
    return Group(*parts) if parts else None


def _row_get(row, key: str, default: str = "") -> str:
    """Read a column from a sqlite3.Row or dict-like finding row, tolerating missing keys."""
    try:
        val = row[key]
    except (KeyError, IndexError, TypeError):
        return default
    return val if val is not None else default


def _verified_cell(row) -> "Text":
    """Verified indicator for a finding, from its confidence.

    For tools that actively validate a credential (TruffleHog live-tests each secret against
    its service, badsecrets/h8mail-recovered creds), ``confidence == confirmed`` means the
    finding was VERIFIED — the secret actually authenticates / the value was recovered. Lower
    confidence means unverified (pattern match only, not live-tested). Making this an explicit
    column lets the user separate the ~real from the noise at a glance rather than trusting the
    row blindly.
    """
    try:
        conf = row["confidence"]
    except (KeyError, IndexError, TypeError):
        conf = "unknown"
    conf = (conf or "unknown").lower()
    if conf == "confirmed":
        return Text("✔ verified", style="bold green")
    if conf == "firm":
        return Text("~ firm", style="yellow")
    if conf in ("tentative", "unknown"):
        return Text("unverified", style=MUTED)
    return Text(conf, style=MUTED)


# --- Summary panel ----------------------------------------------------------------------


def summary_panel(
    domain: str,
    counts: dict[str, int],
    sev_counts: dict[str, int],
    source_states: list[tuple[str, str, int, str]],
    duration_s: float,
    verified_counts: dict[str, int] | None = None,
) -> Panel:
    """Build the bordered end-of-stage summary panel.

    Args:
        domain: target.
        counts: item totals ({emails, employees, osint, findings, subdomains}).
        sev_counts: findings by severity.
        source_states: list of (name, state, items, note) for the per-source roll-up.
        duration_s: how long the stage took.
        verified_counts: optional {verified, unverified} finding split (TruffleHog etc.).
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
    ]
    # Verified/unverified split — makes a big credential scan's real hits legible at a glance.
    if verified_counts and (verified_counts.get("verified") or verified_counts.get("unverified")):
        v, u = verified_counts.get("verified", 0), verified_counts.get("unverified", 0)
        body_parts.append(Text.assemble(
            (f"{v} verified", "bold green" if v else MUTED), ("  ", ""),
            (f"{u} unverified", "yellow" if u else MUTED),
        ))
    body_parts += [
        Text(""),
        Text("sources:", style="bold white"),
        rollup,
    ]
    if failed_names:
        body_parts.append(Text(f"failed: {', '.join(failed_names)}", style="red"))
    body = Group(*body_parts)

    title = Text.assemble(
        ("✔ OSINT complete", "bold green"), ("   ", ""),
        (domain, f"bold {ACCENT}"), ("   ", ""), (format_duration(duration_s), MUTED),
    )
    return Panel(body, title=title, title_align="left", border_style="green",
                 box=HEAVY, padding=(1, 2))
