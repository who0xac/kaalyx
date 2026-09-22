"""Rich terminal UI for the OSINT stage.

Provides:

* :func:`print_banner` — the OSINT module ASCII banner (figlet-slant "OSINT").
* :class:`OsintProgress` — during the scan, a single live status line (progress bar +
  elapsed + an animated cyan braille spinner naming the running source(s)). Per-source rows
  are NOT printed while the scan runs; they appear once at the end in the grouped board. This
  keeps the tall board out of the height-limited Live frame. Driven by the ``progress`` hook
  from :func:`kaalyx.stages.sources.run_sources`.
* :func:`grouped_source_board` — the final end-of-scan board: every source grouped under a
  category header, with a PLAIN status icon (✔ green / ✘ red / ⚠ yellow-flagged / ○ dim) before
  the name, no bracketed markers and no [N/T] prefix.
* result renderers (whois, emails, employees, SPF/DMARC posture, social, host/IP intel,
  findings) — borderless board idiom, dotted leaders, UPPERCASE headers, no boxes.

All rendering goes through the shared console (:func:`kaalyx.core.logging.get_console`) so
it interleaves cleanly with logging.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass

from rich.console import Group
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
    "gitgraber": "GITGRABER[secrets]",
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
        self._total = len(self._states)
        self._finished = 0          # how many sources have completed (drives [N/total])

    def set_progress(self, name: str, done: int, total: int) -> None:
        """Update a running source's live done/total counter (e.g. LEAKSEARCH 23/47). Only the
        single live status line reflects it — no per-source row is reprinted."""
        st = self._states.get(name)
        if st is None:
            return
        st.prog_done, st.prog_total = done, total
        self._refresh()

    def hook(self, event: str, name: str, result) -> None:
        """The progress hook passed to ``run_sources``.

        DESIGN: every source's row is printed EXACTLY ONCE, as a static line, the moment it
        finishes (in completion order) — plain console output that scrolls through terminal
        history and is never redrawn. The ONLY thing the live board updates in place is a single
        status line (see ``_status_line``), which always fits on screen. This is what makes the
        board free of both the 'reprints every tick' and 'rows disappear' bugs: nothing tall is
        ever held as a live frame."""
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
            # Track completion for the live progress line. Per-source rows are NOT printed during
            # the scan any more — the full category-grouped board is printed once at the end (see
            # grouped_source_board). During the scan the only live output is the single status
            # line, which keeps the tall board out of the height-limited Live frame.
            self._finished += 1
        self._refresh()

    def _print_static_row(self, name: str, st: "_SourceState", pos: int) -> None:
        """Emit ONE completed-source line to the console (static; scrolls into history). Printed
        via the live board's console so it interleaves correctly above the live status line."""
        row = self._row(st, _display_name(name, st.label), time.monotonic(),
                        _SPINNER_FRAMES[0], pos=pos, total=self._total)
        if self._live is not None:
            # console.print through the Live renders the static line ABOVE the live status line,
            # then repaints only the (single-line) status — no full-board redraw.
            self._live.console.print(row)
        else:
            self._console.print(row)


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
            icon = Text("○", style="yellow")          # skipped (missing key) — distinct from queued
            name_style = "yellow"
            result = Text("no key", style="yellow")
            note = _skip_note(st.note)
            show_time = False
        elif st.state == "skipped":
            icon = Text("○", style="yellow")          # ran the check, nothing to do — NOT queued
            name_style = MUTED
            result = Text("skipped", style="yellow")
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

    def _status_line(self):
        """The ONE line the live board updates in place: progress bar + [done/total] + which
        sources are currently running + elapsed. Always a single line, so it always fits on
        screen and Live updates it in place without ever repainting a multi-row frame.

        (The completed sources' rows are printed once as static lines by ``_print_static_row``;
        they scroll through history and are not part of this live renderable.)"""
        now = time.monotonic()
        frame = _SPINNER_FRAMES[int((now * 12)) % len(_SPINNER_FRAMES)]
        done = self._finished
        total = self._total
        running = [self._states[n] for n in self._states
                   if self._states[n].state == "running"]
        elapsed = now - self._start

        line = Text("    ")
        line.append_text(self._progress_bar(done, total))
        line.append(f" {done}/{total} ", style="white")
        line.append(":: ", style=MUTED)
        line.append(self._mmss(elapsed), style="white")
        if running:
            # Name the active source(s); the spinner frame animates so a long-running one shows life.
            names = ", ".join(_display_name(n, self._states[n].label)
                              for n in self._states if self._states[n].state == "running")
            line.append(f"  {frame} ", style="bold cyan")
            line.append(names, style="cyan")
        elif done >= total:
            line.append("  done", style="bold green")
        # CRITICAL: hard-truncate to the terminal width so the status line is ALWAYS exactly one
        # physical line. If it wrapped to 2 lines, rich.Live's cursor-up count (based on 1 line)
        # would be wrong and it would leave the previous frame behind — the "status line prints
        # multiple times with different timestamps" bug. One line = one in-place update, always.
        try:
            width = self._console.size.width
        except Exception:
            width = 80
        line.truncate(max(10, width - 1), overflow="ellipsis")
        return line

    def _refresh(self) -> None:
        if self._live is not None:
            self._live.refresh()

    def live(self):
        """Context manager yielding a ``rich.Live`` that manages ONLY the single status line
        (``get_renderable=self._status_line``). Because that renderable is always one line, it
        always fits on screen and Live updates it in place — it can never overflow the terminal,
        so it can never fall into the 'repaint the whole frame every tick' failure mode. Every
        source's full row is printed separately as a static line by ``_print_static_row`` and
        scrolls through terminal history like any normal output.

        redirect_stdout/stderr + the _LiveWithQuietTerminal guard remain, but they now only have
        to protect a one-line frame, which is trivially robust."""
        from rich.live import Live

        live = Live(
            get_renderable=self._status_line,
            console=self._console,
            refresh_per_second=8,
            auto_refresh=True,
            transient=False,
            redirect_stdout=True,
            redirect_stderr=True,
        )
        self._live = live
        return _LiveWithQuietTerminal(live)


# --- Result tables ----------------------------------------------------------------------


def _NA() -> "Text":
    """The 'no data for this FIELD' marker: 'N/A' in red. Distinct from a source's 0 hit-count
    (which stays GREEN — a clean zero-result is a valid successful outcome, not a failure). Red
    N/A means 'this particular field/record has no value', not 'the source failed'."""
    return Text("N/A", style="red")


def _section_header(name: str, subtitle: str = ""):
    """A borderless '[◆] NAME :: subtitle' section header in the locked board idiom."""
    return Text.assemble(("[◆] ", "bold orange1"), (name, "bold orange1"),
                         ((f" :: {subtitle}" if subtitle else ""), MUTED))


# Category grouping for the end-of-scan board. Every source belongs to exactly one category;
# the board prints these groups in this order, each under an UPPERCASE header. New sources must
# be added to a category here (a source not listed falls into "OTHER" so it's never dropped).
_SOURCE_CATEGORIES: list[tuple[str, list[str]]] = [
    ("INFRASTRUCTURE & DNS",
     ["whois", "dns", "ip_info", "mail_dns", "tls_cert", "internetdb"]),
    ("CODE & SECRETS",
     ["github_subdomains", "gitgraber", "trufflehog", "github_actions", "workflow_logs",
      "badsecrets", "retirejs"]),
    ("CLOUD & STORAGE",
     ["cloud_enum", "s3scanner", "firebase"]),
    ("IDENTITY & TENANT",
     ["m365", "gitlab", "dockerhub"]),
    ("PEOPLE & EMAIL",
     ["email_harvest", "theharvester", "social", "breach_lookup", "leak_search"]),
    ("APPS & PRESENCE",
     ["mobile_apps", "affiliate_domains", "dnstwist"]),
    ("API & THIRD-PARTY",
     ["api_leaks", "third_party_misconfig", "exposed_git"]),
    ("ATTACK SURFACE (SHODAN)",
     ["shodan_org", "shodan_favicon", "shodan_vulns", "shodan_host"]),
    ("RECON AIDS",
     ["google_dorks"]),
]


def _plain_status_icon(r) -> "Text":
    """The plain (un-bracketed) status icon for a source's final row, colored per the locked
    scheme: ✔ green (ran ok), ✘ red (failed), ○ dim (skipped / not installed / no key). The ⚠
    flagged marker is applied by the caller (it depends on cross-source flag state), not here."""
    if not r.ok:
        return Text("✘", style="bold red")
    if r.skipped:
        return Text("○", style="grey50")
    return Text("✔", style="bold green")


def grouped_source_board(results: list, flagged_sources: set[str] | None = None):
    """The final, locked end-of-scan board: every source grouped under a category header, with a
    PLAIN status icon (✔/✘/○, or ⚠ for a flagged row) directly before the source name — no
    bracketed markers and no per-row [N/T] prefix. A ⚠ (yellow) overrides the normal icon for any
    source in *flagged_sources* (e.g. an org-mismatch / data-integrity concern) so the flag is
    visible right on its row. Sources not in any category fall into a trailing OTHER group so none
    is ever dropped. Returns a single Group (printed statically once, after the scan)."""
    if not results:
        return None
    flagged_sources = flagged_sources or set()
    by_name = {r.name: r for r in results}
    placed: set[str] = set()

    lines: list = [_section_header("SOURCE RESULTS", f"{len(results)} sources"), Text("")]

    def _emit_row(r) -> None:
        name = _display_name(r.name, r.name)
        flagged = r.name in flagged_sources
        icon = Text("⚠", style="bold yellow") if flagged else _plain_status_icon(r)
        # Name style: dim for skipped, red for failed, yellow when flagged, else white.
        if flagged:
            name_style = "yellow"
        elif not r.ok:
            name_style = "red"
        elif r.skipped:
            name_style = "grey50"
        else:
            name_style = "white"
        line = Text("    ")
        line.append_text(icon)
        line.append(" ")
        line.append(f"{name:<28}", style=name_style)
        pad = max(1, 30 - len(name))
        line.append(" " + "." * pad + " ", style=MUTED)
        # Result cell: green hit COUNT (0 stays green — a valid clean result), yellow skip state,
        # red failed.
        if not r.ok:
            line.append("failed", style="bold red")
        elif r.skipped:
            line.append(_skip_result_text(r.note))
        else:
            line.append(f"{r.total} hits", style="green")
        note = (r.note or "").strip()
        if note:
            n = note if len(note) <= 34 else note[:33] + "…"
            line.append(f"  {n}", style=MUTED)
        lines.append(line)

    for title, names in _SOURCE_CATEGORIES:
        rows = [by_name[n] for n in names if n in by_name]
        if not rows:
            continue
        lines.append(Text(f"  {title}", style=f"bold {ACCENT}"))
        for r in rows:
            _emit_row(r)
            placed.add(r.name)
        lines.append(Text(""))

    # Any source not assigned to a category — never drop it.
    leftover = [r for r in results if r.name not in placed]
    if leftover:
        lines.append(Text("  OTHER", style=f"bold {ACCENT}"))
        for r in leftover:
            _emit_row(r)
        lines.append(Text(""))

    # Drop the trailing blank so the board ends cleanly.
    while lines and isinstance(lines[-1], Text) and not lines[-1].plain:
        lines.pop()
    return Group(*lines)


def source_results_table(results: list):
    """Every source's OUTCOME, in the locked board idiom — ALL sources, not just the ones that
    found something. Each source shows a status marker + its result: a green hit COUNT (0 stays
    green — a clean zero is a valid outcome), a red ``N/A`` for a source that produced no data,
    ``skipped``/``no key`` in yellow, or ``failed`` in red. A persistent post-scan roster so the
    full set of sources is always visible after a scan, mirroring the live board.

    Superseded on the terminal by :func:`grouped_source_board` (category-grouped, plain icons);
    kept for any caller that still wants the flat ungrouped roster."""
    if not results:
        return None
    lines = [_section_header("SOURCE RESULTS", f"{len(results)} sources"), Text("")]
    for r in results:
        name = _display_name(r.name, r.name)
        line = Text("    ")
        # Status marker (matches the live board): ✓ ok / ○ skipped / ✘ failed.
        if not r.ok:
            line.append("[✘] ", style="bold red")
        elif r.skipped:
            line.append("[○] ", style="yellow")
        else:
            line.append("[✓] ", style="bold green")
        line.append(f"{name:<28}", style="white" if r.ok and not r.skipped else "grey50")
        pad = max(1, 30 - len(name))
        line.append(" " + "." * pad + " ", style=MUTED)
        # Result cell: a completed source ALWAYS shows a real hit COUNT in green — including
        # "0 hits" for a legitimate clean result (locked rule: green 0 = valid outcome). N/A is
        # NEVER used for a source's overall count; it is only for a missing FIELD inside a
        # source's own detailed block.
        if not r.ok:
            line.append("failed", style="bold red")
        elif r.skipped:
            line.append(_skip_result_text(r.note))
        else:
            line.append(f"{r.total} hits", style="green")
        # A short trailing note for context (skip reason etc.), trimmed to stay on one line.
        note = (r.note or "").strip()
        if note:
            n = note if len(note) <= 34 else note[:33] + "…"
            line.append(f"  {n}", style=MUTED)
        lines.append(line)
    return Group(*lines)


# One-line description per source for its detailed [◆] block header.
_SOURCE_DESC = {
    "whois": "registration & ownership", "dns": "DNS records",
    "ip_info": "geo/asn lookup", "mail_dns": "anti-spoofing & DNS records",
    "m365": "Microsoft 365 / Entra tenant", "email_harvest": "harvested addresses",
    "social": "social-media profiles", "breach_lookup": "email breach enrichment",
    "leak_search": "leaked credentials", "github_subdomains": "subdomains from GitHub code",
    "gitgraber": "service-specific secret patterns", "trufflehog": "org secret scan",
    "cloud_enum": "public cloud buckets/blobs", "s3scanner": "S3 buckets",
    "badsecrets": "known secrets / crypto misconfig", "retirejs": "vulnerable JS libraries",
    "theharvester": "emails / hosts / people", "third_party_misconfig": "3rd-party SaaS misconfig",
    "api_leaks": "Postman / Swagger API leaks", "exposed_git": "exposed / downloadable .git",
    "firebase": "Firebase Realtime DB exposure", "github_actions": "GitHub Actions audit",
    "google_dorks": "ready-to-run dork URLs", "shodan_org": "org/ASN infrastructure",
    "shodan_favicon": "favicon-hash pivots", "shodan_vulns": "passive CVE tags",
    "shodan_host": "per-IP deep lookup", "internetdb": "free per-IP ports/CVEs",
    "tls_cert": "certificate SANs/issuer/validity", "gitlab": "GitLab namespaces",
    "dockerhub": "Docker Hub repositories", "mobile_apps": "iOS / Android apps",
    "affiliate_domains": "related domains (crt.sh)", "dnstwist": "typosquat / look-alike domains",
    "workflow_logs": "CI-log secret scan",
}


def _generic_source_block(r) -> "Group":
    """A detailed [◆] block for ONE source, built from its SourceResult. Shows the source's
    records / findings / subdomains / URLs as labelled lines; when the source didn't run
    (skipped / no key / not installed / failed) or found nothing, it still renders the block
    stating that — so the operator sees WHAT was checked even on an empty result. Per-field
    misses render red N/A; the block never shows N/A for an overall count."""
    name = _display_name(r.name, r.name)
    desc = _SOURCE_DESC.get(r.name, "")
    lines: list = [_section_header(name, desc), Text("")]

    # Didn't run cleanly → say why, then stop (nothing to detail).
    if not r.ok:
        lines.append(Text.assemble(("    status  ", "cyan"),
                                   (f"FAILED — {r.error or r.note or 'unknown error'}", "bold red")))
        return Group(*lines)
    if r.skipped:
        state = _classify_skip(r.note or "")
        style = "bold orange1" if state == "not_installed" else "yellow"
        lines.append(Text.assemble(("    status  ", "cyan"),
                                   (_skip_note(r.note) or "skipped", style)))
        return Group(*lines)

    body = False
    # Findings (structured) — severity-tagged one-liners.
    for f in r.findings:
        body = True
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        lines.append(Text.assemble(("    ", ""), (f"[{sev.upper()}] ", severity_style(sev)),
                                    (f.title, "white")))
        if f.description:
            lines.append(Text.assemble(("        ", ""), (f.description[:150], MUTED)))
    # OSINT records — value + detail.
    for o in r.osint:
        body = True
        val = o["value"] if not hasattr(o, "value") else o.value
        det = o["detail"] if not hasattr(o, "detail") else o.detail
        line = Text("    ")
        line.append(str(val), style="white")
        if det:
            line.append("  ", style=MUTED); line.append(str(det)[:110], style=MUTED)
        lines.append(line)
    # Subdomains discovered by this source.
    if r.subdomains:
        body = True
        lines.append(Text.assemble(("    subdomains  ", "cyan"),
                                    (", ".join(s.hostname for s in r.subdomains[:20]), "white")))
    # URLs / endpoints discovered by this source.
    if r.urls:
        body = True
        for u in r.urls[:20]:
            lines.append(Text.assemble(("    url  ", "cyan"), (u.url, "white")))

    if not body:
        # Ran clean, found nothing — show it explicitly (green context, not a failure), plus the
        # source's own note so the operator sees what was checked.
        lines.append(Text.assemble(("    result  ", "cyan"), ("0 — none found", "green")))
        if r.note:
            lines.append(Text.assemble(("    note    ", "cyan"), (r.note[:110], MUTED)))
    return Group(*lines)


def source_detail_blocks(results: list, osint_rows: list, email_rows: list, emp_rows: list) -> list:
    """A detailed [◆] block for EVERY source, in pipeline order. The four sources with bespoke
    layouts (whois / ip_info / mail_dns / social) delegate to their rich renderers; every other
    source gets the generic block. Sources that found nothing still render a block saying so, so
    the full set of 35 is always visible. Returns a list of renderables to print in order."""
    specialized = {
        "whois": lambda: whois_table(osint_rows),
        "ip_info": lambda: host_intel_table(osint_rows),
        "mail_dns": lambda: mail_hygiene_table(osint_rows),
        "social": lambda: social_table(osint_rows),
        "email_harvest": lambda: emails_table(email_rows),
        "theharvester": lambda: employees_table(emp_rows),
    }
    out: list = []
    for r in results:
        block = None
        if r.name in specialized and r.ok and not r.skipped:
            block = specialized[r.name]()   # bespoke renderer (may be None if it had no rows)
        if block is None:
            block = _generic_source_block(r)
        out.append(block)
    return out


def _skip_result_text(note: str) -> "Text":
    """Result cell for a skipped source: 'no key' (yellow) or 'skipped' (yellow) from its note."""
    state = _classify_skip(note or "")
    if state == "no_key":
        return Text("no key", style="yellow")
    if state == "not_installed":
        return Text("not installed", style="bold orange1")
    return Text("skipped", style="yellow")


def emails_table(rows: list):
    """Discovered emails (+ breach data) as borderless board-idiom lines. ``None`` when empty."""
    if not rows:
        return None
    lines = [_section_header("EMAILS", f"{len(rows)} address(es)"), Text("")]
    for r in rows:
        breached = r["breached"] if isinstance(r, dict) or hasattr(r, "keys") else r.breached
        addr, source, count = r["address"], r["source"], r["breach_count"]
        line = Text("    ")
        line.append(addr, style="white")
        pad = max(1, 40 - len(addr))
        line.append(" " + "." * pad + " ", style=MUTED)
        if breached:
            line.append(f"⚠ breached ×{count}", style="bold red")
        else:
            line.append("clean", style="green")
        line.append(f"  ({source})", style=MUTED)
        lines.append(line)
    return Group(*lines)


def employees_table(rows: list):
    """Discovered people/employees as borderless board-idiom lines. ``None`` when empty."""
    if not rows:
        return None
    lines = [_section_header("PEOPLE / EMPLOYEES", f"{len(rows)}"), Text("")]
    for r in rows:
        name = r["name"]
        line = Text("    ")
        line.append(name, style="white")
        pad = max(1, 34 - len(name))
        line.append(" " + "." * pad + " ", style=MUTED)
        role = r["role"]
        line.append_text(Text(role, style="cyan") if role else _NA())
        line.append(f"  ({r['source']})", style=MUTED)
        lines.append(line)
    return Group(*lines)


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


def mail_hygiene_table(records: list):
    """Email/DNS security posture as borderless board-idiom lines: SPF, DMARC, DKIM, CAA,
    MTA-STS, TLS-RPT, BIMI — every type ALWAYS shown, with its value or a red ``N/A`` when that
    record is absent (a missing record is a per-field 'no data', hence N/A) — then the SPOOFABLE
    verdict + one-line plain-English DMARC interpretation. ``None`` when nothing was assessed."""
    by_kind: dict[str, list] = {}
    for r in records:
        by_kind.setdefault(r["kind"], []).append(r)
    if not any(k in by_kind for k in _MAIL_ROW_ORDER) and "spoofable" not in by_kind:
        return None

    lines = [_section_header("EMAIL / DNS SECURITY", "anti-spoofing & DNS records"), Text("")]

    def _row(label: str, value, style: str = "white"):
        line = Text("    ")
        line.append(f"{label:<9}", style="cyan")
        line.append("  ", style=MUTED)
        if isinstance(value, Text):
            line.append_text(value)
        else:
            line.append(str(value), style=style)
        return line

    for kind in _MAIL_ROW_ORDER:
        label = kind.upper().replace("_", "-")
        rows = by_kind.get(kind)
        if not rows:
            lines.append(_row(label, _NA()))          # type absent → red N/A (per-field no data)
            continue
        for r in rows:
            val = str(r["value"])
            if val.lower().startswith("not found"):
                lines.append(_row(label, _NA()))      # explicit "not found" → red N/A too
            else:
                lines.append(_row(label, val))

    spoof = (by_kind.get("spoofable") or [None])[0]
    if spoof is not None:
        lines.append(Text(""))
        spoofable = str(spoof["value"]).lower() == "yes"
        dmarc_val = (by_kind.get("dmarc") or [{"value": "not found"}])[0]["value"]
        verdict = Text(f"YES — {spoof['detail']}" if spoofable else f"no — {spoof['detail']}",
                       style="bold red" if spoofable else "green")
        lines.append(_row("SPOOFABLE", verdict))
        lines.append(_row("", Text(_dmarc_interpretation(dmarc_val),
                                    style="red" if spoofable else "green")))
    return Group(*lines)


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


def social_table(records: list):
    """Discovered social-media profiles as borderless board-idiom lines. ``None`` when empty."""
    rows = [r for r in records if r["kind"] == "social"]
    if not rows:
        return None
    lines = [_section_header("SOCIAL PROFILES", f"{len(rows)}"), Text("")]
    for r in rows:
        val = r["value"]
        platform = (r["detail"] or (val.split(":", 1)[0] if ":" in val else "")).strip()
        handle = val.split(":", 1)[1].strip() if ":" in val else val
        line = Text("    ")
        line.append(f"{platform.upper():<12}", style="cyan")
        line.append("  ", style=MUTED)
        line.append_text(Text(handle, style="white") if handle else _NA())
        lines.append(line)
    return Group(*lines)


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


# Severity → the leading bracket marker, matching the source board's [icon] idiom. Colour comes
# from severity_style; the glyph signals urgency at a glance.
_SEV_MARKER = {
    "critical": "‼", "high": "!", "medium": "!", "low": "·", "info": "i", "unknown": "·",
}


def _finding_lines(row) -> list:
    """Render ONE finding as borderless lines in the source-board idiom:

        [!] HIGH  ✔ verified  <title> ....... <short detail>
              <label>  <value>          (extra evidence lines, indented, only when present)

    A short single-line detail sits on the header line after a dotted leader; a long or
    multi-line evidence body is spread over indented continuation lines (no box, nothing
    truncated). Full secret values render literally (no masking, no markup eaten)."""
    sev = _row_get(row, "severity", "unknown").lower()
    marker = _SEV_MARKER.get(sev, "·")
    sev_style = severity_style(sev)
    title = _row_get(row, "title")
    tgt = _row_get(row, "target")
    ev = _row_get(row, "evidence")

    header = Text("    ")
    header.append(f"[{marker}] ", style=sev_style)
    header.append(f"{sev.upper():<8} ", style=sev_style)
    header.append_text(_verified_cell(row))
    header.append("  ", style=MUTED)
    header.append(title, style="white")

    lines = [header]
    # Short, single-line evidence → one dotted-leader continuation under the title.
    short = ev and "\n" not in ev and len(ev) <= 100
    if short:
        lines.append(Text.assemble(("          ", ""), (ev, MUTED)))
    else:
        if tgt:
            lines.append(Text.assemble(("          target  ", "cyan"), (tgt, "white")))
        if "\n" in ev:
            # Structured "Label: value" lines (Postman creds) vs free text w/ a colon (URLs/JSON).
            for line in ev.split("\n"):
                head = line.partition(":")[0]
                is_label = (":" in line and head.strip()
                            and " " not in head.strip() and "/" not in head
                            and len(head.strip()) <= 16)
                if is_label:
                    lbl, _, val = line.partition(":")
                    lines.append(Text.assemble(("          ", ""),
                                               (f"{lbl.strip()}  ", "cyan"),
                                               *_as_assemble(Text(val.strip()))))
                elif line.strip():
                    lines.append(Text.assemble(("          ", ""),
                                               *_as_assemble(Text(line.strip(), style=MUTED))))
        elif ev:
            lines.append(Text.assemble(("          ", ""), *_as_assemble(Text(ev, style=MUTED))))
        elif not tgt:
            lines.append(Text.assemble(("          ", ""),
                                       (_row_get(row, "description"), MUTED)))
    return lines


def render_findings(rows: list, limit: int = 60) -> list:
    """Findings in the locked hacky/cybersec board idiom — NO borders, NO boxed tables. Grouped
    by category under UPPERCASE headings, each finding a ``[marker] SEV verified title`` line
    with indented evidence beneath. Matches the source-board visual language so findings read as
    a continuation of it. Empty list when there are no findings."""
    if not rows:
        return []
    rows = sorted(rows, key=lambda r: _SEV_ORDER.get(_row_get(r, "severity", "unknown"), 0),
                  reverse=True)[:limit]
    buckets: dict[str, list] = {}
    for r in rows:
        buckets.setdefault(_row_get(r, "category", "other") or "other", []).append(r)

    ordered_cats = [c for c, _ in _CATEGORY_TITLES if c in buckets]
    ordered_cats += [c for c in buckets if c not in ordered_cats]
    title_map = dict(_CATEGORY_TITLES)

    out: list = [Text.assemble(("[◆] ", "bold orange1"), ("FINDINGS", "bold orange1"),
                               (f" :: {len(rows)} across {len(buckets)} categories", MUTED)),
                 Text("")]
    for cat in ordered_cats:
        section = title_map.get(cat, cat.replace("-", " ").title())
        out.append(Text(f"  {section.upper()}", style=f"bold {ACCENT}"))
        for r in buckets[cat]:
            out.extend(_finding_lines(r))
        out.append(Text(""))
    return [Group(*out)]


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
) -> Group:
    """Build the bordered end-of-stage summary panel.

    Args:
        domain: target.
        counts: item totals ({emails, employees, osint, findings, subdomains}).
        sev_counts: findings by severity.
        source_states: list of (name, state, items, note) for the per-source roll-up.
        duration_s: how long the stage took.
        verified_counts: optional {verified, unverified} finding split (TruffleHog etc.).
    """
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

    # Borderless closing block in the locked board idiom — no box, consistent with the findings
    # and source-board style. Counts stay GREEN even at 0 (a clean zero-result is a valid,
    # successful outcome, not a failure — distinct from a red per-field N/A).
    header = Text.assemble(
        ("[◆] ", "bold orange1"), ("KAALYX::OSINT COMPLETE", "bold orange1"),
        (f" :: {domain} · {format_duration(duration_s)}", MUTED),
    )
    body_parts = [header, Text("")]
    for label, key in (("SUBDOMAINS", "subdomains"), ("EMAILS", "emails"),
                       ("PEOPLE", "employees"), ("OSINT RECORDS", "osint"),
                       ("FINDINGS", "findings")):
        n = counts.get(key, 0)
        row = Text("    ")
        row.append(f"{label:<15}", style="cyan")
        row.append("  ", style=MUTED)
        row.append(f"{n}", style="green")     # 0 stays green: valid clean result, not a failure
        body_parts.append(row)
    body_parts += [Text(""), Text("    FINDINGS BY SEVERITY", style=f"bold {ACCENT}"),
                   Text.assemble(("      ", ""), *_as_assemble(sev_line))]
    if verified_counts and (verified_counts.get("verified") or verified_counts.get("unverified")):
        v, u = verified_counts.get("verified", 0), verified_counts.get("unverified", 0)
        body_parts.append(Text.assemble(
            ("      ", ""), (f"{v} verified", "bold green" if v else MUTED), ("  ", ""),
            (f"{u} unverified", "yellow" if u else MUTED)))
    body_parts += [Text(""), Text("    SOURCES", style=f"bold {ACCENT}"),
                   Text.assemble(("      ", ""), *_as_assemble(rollup))]
    if failed_names:
        body_parts.append(Text(f"      failed: {', '.join(failed_names)}", style="red"))
    return Group(*body_parts)


def flagged_callout(flagged: list[str]):
    """A short, high-signal callout for the genuinely noteworthy items (an org mismatch, verified
    secrets, an exposed .git, …) — the only detail the compact terminal shows beyond per-source
    counts. Each entry is a one-line string already summarizing the concern. Returns ``None`` when
    there is nothing to flag (so the caller prints nothing)."""
    if not flagged:
        return None
    lines = [_section_header("FLAGGED FOR REVIEW", f"{len(flagged)} item(s)"), Text("")]
    for item in flagged:
        lines.append(Text.assemble(("    ! ", "bold yellow"), (item, "white")))
    return Group(*lines)


def completion_message(domain: str, folder: str, duration_s: float,
                       n_sources: int, n_findings: int, n_flagged: int):
    """The compact end-of-stage completion block. Shows ONLY the folder where all OSINT output
    (the full report, raw files, everything) was saved — not any individual filename — plus a
    one-line tally. Deliberately terse: the full detail lives in the report file, not the
    terminal."""
    header = Text.assemble(
        ("[◆] ", "bold orange1"), ("KAALYX::OSINT COMPLETE", "bold orange1"),
        (f" :: {domain} · {format_duration(duration_s)}", MUTED),
    )
    tally = Text.assemble(
        ("    ", ""), (f"{n_sources} sources", "green"), (" · ", MUTED),
        (f"{n_findings} findings", "green"), (" · ", MUTED),
        (f"{n_flagged} flagged for review", "yellow" if n_flagged else MUTED),
    )
    return Group(
        header, Text(""),
        Text("    Results saved to:", style=f"bold {ACCENT}"),
        Text(f"    {folder}", style="white"),
        Text(""), tally,
    )
