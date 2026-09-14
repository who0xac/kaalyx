"""Centralised logging for Kaalyx, built on :mod:`rich`.

Two sinks are configured:

* a :class:`rich.logging.RichHandler` for pretty, colourised console output, and
* a plain rotating file handler under ``<results_dir>/<domain>/kaalyx.log`` (attached
  lazily once a scan's output directory is known) so every run keeps a full text log.

A single shared :class:`rich.console.Console` instance is exposed via :func:`get_console`
so progress bars, tables, and log output all render through the same terminal handle.
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# A shared theme so severity/status colours are consistent across the whole app.
_THEME = Theme(
    {
        "logging.level.debug": "dim cyan",
        "logging.level.info": "green",
        "logging.level.warning": "yellow",
        "logging.level.error": "bold red",
        "logging.level.critical": "bold white on red",
        "kaalyx.stage": "bold cyan",
        "kaalyx.tool": "magenta",
        "kaalyx.finding.critical": "bold white on red",
        "kaalyx.finding.high": "bold red",
        "kaalyx.finding.medium": "yellow",
        "kaalyx.finding.low": "cyan",
        "kaalyx.finding.info": "dim",
    }
)

_console: Console | None = None
_LOGGER_NAME = "kaalyx"
_console_level: int = logging.INFO  # remembered so we can restore after a Live board
# Console handler temporarily detached while a rich.Live board owns the screen (see
# set_console_logging); held here so it can be re-attached, not lost.
_detached_console_handler: logging.Handler | None = None


def _ensure_utf8_streams() -> None:
    """Force stdout/stderr to UTF-8 so rich's Unicode (box-drawing, spinners, dashes)
    renders on Windows terminals, whose default cp1252 codepage otherwise raises
    ``UnicodeEncodeError`` on characters like ``○`` or ``─``. Safe/no-op elsewhere.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):  # pragma: no cover - stream may not support it
                pass


def get_console() -> Console:
    """Return the process-wide shared :class:`rich.console.Console` (UTF-8 output)."""
    global _console
    if _console is None:
        _ensure_utf8_streams()
        _console = Console(theme=_THEME)
    return _console


def setup_logging(level: int = logging.INFO, *, quiet: bool = False) -> logging.Logger:
    """Configure and return the root Kaalyx logger.

    Idempotent: calling it again reconfigures the level but does not stack handlers.

    Args:
        level: Console logging level.
        quiet: If ``True``, suppress the console handler entirely (file logging, once
            attached, is unaffected). Useful when the web server owns the terminal.
    """
    global _console_level
    _console_level = level
    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(logging.DEBUG)  # handlers filter; logger passes everything through.

    # Remove only the console handler we may have added before, leave file handlers.
    for handler in list(logger.handlers):
        if getattr(handler, "_kaalyx_console", False):
            logger.removeHandler(handler)

    if not quiet:
        console_handler = RichHandler(
            console=get_console(),
            show_time=True,
            show_path=False,
            rich_tracebacks=True,
            markup=True,
            omit_repeated_times=False,
        )
        console_handler.setLevel(level)
        console_handler._kaalyx_console = True  # type: ignore[attr-defined]
        console_handler.setFormatter(logging.Formatter("%(message)s", datefmt="[%X]"))
        logger.addHandler(console_handler)

    logger.propagate = False
    return logger


def set_console_logging(enabled: bool) -> None:
    """Enable/disable the console log handler without touching file logging.

    Used to silence interleaved log lines while a ``rich.Live`` board owns the screen —
    the rotating file log keeps capturing everything regardless.

    Disabling DETACHES the console handler entirely (not merely raises its level): a handler
    left attached at CRITICAL+1 still lets a genuine CRITICAL record slip through, and any
    console write while a non-transient ``rich.Live`` is active makes Live checkpoint the
    current frame permanently and start a fresh board below — which is exactly the
    "board printed twice" bug. Full detach guarantees nothing reaches the shared console
    while the board owns it. Re-enabling re-attaches the same handler object.
    """
    global _detached_console_handler
    logger = logging.getLogger(_LOGGER_NAME)
    if enabled:
        # Re-attach a previously-detached handler (if any and not already present).
        h = _detached_console_handler
        if h is not None and h not in logger.handlers:
            logger.addHandler(h)
        _detached_console_handler = None
    else:
        for handler in list(logger.handlers):
            if getattr(handler, "_kaalyx_console", False):
                _detached_console_handler = handler
                logger.removeHandler(handler)


def attach_file_handler(log_path: Path) -> None:
    """Attach a rotating file handler for the current scan.

    Safe to call repeatedly; a file handler for the same resolved path is only added
    once. Called by the orchestrator once the scan's output directory exists.
    """
    logger = logging.getLogger(_LOGGER_NAME)
    resolved = str(log_path.resolve())
    for handler in logger.handlers:
        if getattr(handler, "_kaalyx_file_path", None) == resolved:
            return  # already attached

    log_path.parent.mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(
        log_path, maxBytes=10 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler._kaalyx_file_path = resolved  # type: ignore[attr-defined]
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    logger.addHandler(file_handler)


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a child logger under the ``kaalyx`` namespace.

    Args:
        name: Optional dotted suffix, e.g. ``"stages.osint"`` -> ``kaalyx.stages.osint``.
    """
    if name:
        return logging.getLogger(f"{_LOGGER_NAME}.{name}")
    return logging.getLogger(_LOGGER_NAME)
