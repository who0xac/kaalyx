"""Kaalyx exception hierarchy.

Kept deliberately small. The guiding principle is that a single
failed tool or stage must never crash the whole scan — so most failures are *caught and
logged*, not raised past the orchestrator. These exceptions exist for the cases where
raising is genuinely the right control-flow (configuration errors at startup, a tool
that is required-but-missing when the user explicitly asked for it, etc.).
"""

from __future__ import annotations


class KaalyxError(Exception):
    """Base class for all Kaalyx-specific errors."""


class ConfigError(KaalyxError):
    """Raised when configuration or environment is invalid at startup."""


class ToolNotFoundError(KaalyxError):
    """Raised when a required external tool is not available on PATH.

    Most tools are *optional* — if one is missing, Kaalyx logs it and skips the source.
    This is raised only when a tool the user explicitly requested (e.g. via ``--sqlmap``)
    is missing, where silently skipping would violate the user's intent.
    """

    def __init__(self, tool_name: str, message: str | None = None) -> None:
        self.tool_name = tool_name
        super().__init__(message or f"Required tool '{tool_name}' not found on PATH.")


class ToolExecutionError(KaalyxError):
    """Raised when a subprocess fails in a way the caller has opted to treat as fatal.

    By default the :class:`~kaalyx.core.runner.SubprocessRunner` returns a
    :class:`~kaalyx.core.runner.CommandResult` describing the failure rather than
    raising, so stages can decide per-tool how to react.
    """


class StageError(KaalyxError):
    """Raised for an unrecoverable problem inside a stage.

    Ordinary per-tool failures never surface as this; the orchestrator catches whatever
    a stage raises, records the stage as failed, and continues with the next stage.
    """


class TargetError(KaalyxError):
    """Raised when the scan target is malformed or cannot be classified."""
