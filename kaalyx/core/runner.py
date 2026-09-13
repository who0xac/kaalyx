"""Async subprocess runner — the single choke-point for invoking external tools.

Every recon/vuln tool Kaalyx orchestrates is launched through :class:`SubprocessRunner`.
Centralising this gives us, in one place:

* :func:`asyncio.create_subprocess_exec` execution (never ``shell=True``),
* per-command timeouts with clean process-tree termination,
* full stdout/stderr capture (and optional streaming to a raw ``.txt`` file),
* uniform, *non-raising* failure handling — a failed tool returns a
  :class:`CommandResult` describing the failure so the calling stage can log it and move
  on, honouring the rule that one tool must never crash the scan,
* concurrency limiting via an injected :class:`asyncio.Semaphore`.

The runner deliberately knows nothing about *which* tool it is running or how to parse
output — that belongs to the tool registry and the parsers.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path

from .logging import get_logger

logger = get_logger("runner")


@dataclass
class CommandResult:
    """Outcome of a single subprocess invocation.

    ``ok`` is the property stages should branch on. A result is *not* ok if the process
    could not be started, timed out, or exited non-zero (unless the caller marked a code
    as acceptable). Even a not-ok result carries whatever partial output was captured.
    """

    command: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False
    started: bool = True
    error: str | None = None  # populated when the process could not even be launched
    output_file: Path | None = None
    acceptable_codes: tuple[int, ...] = field(default=(0,))

    @property
    def ok(self) -> bool:
        if not self.started or self.timed_out or self.returncode is None:
            return False
        return self.returncode in self.acceptable_codes

    @property
    def command_str(self) -> str:
        return " ".join(self.command)

    def stdout_lines(self) -> list[str]:
        """Non-empty, stripped stdout lines — the common case for line-oriented tools."""
        return [line.strip() for line in self.stdout.splitlines() if line.strip()]


class SubprocessRunner:
    """Runs external commands as async subprocesses under a concurrency limit.

    Args:
        semaphore: Bounds how many commands run at once. Callers typically share the
            orchestrator-wide semaphore so the global ``max_parallel_tools`` limit holds.
        default_timeout: Seconds before a command is killed. ``0`` disables the timeout.
    """

    def __init__(
        self,
        semaphore: asyncio.Semaphore,
        *,
        default_timeout: float = 900.0,
    ) -> None:
        self._semaphore = semaphore
        self._default_timeout = default_timeout

    @staticmethod
    def tool_available(executable: str) -> bool:
        """Return ``True`` if *executable* is resolvable on PATH."""
        return shutil.which(executable) is not None

    async def run(
        self,
        command: list[str],
        *,
        timeout: float | None = None,
        stdin: str | None = None,
        cwd: str | Path | None = None,
        env: dict[str, str] | None = None,
        output_file: str | Path | None = None,
        acceptable_codes: tuple[int, ...] = (0,),
        label: str | None = None,
    ) -> CommandResult:
        """Execute *command* and return a :class:`CommandResult`.

        Never raises for ordinary process failures (missing binary, non-zero exit,
        timeout). It only propagates truly unexpected exceptions, and even those are
        caught and folded into a not-ok result so a stage's ``gather`` cannot be torn
        down by a single tool.

        Args:
            command: argv list; ``command[0]`` is the executable.
            timeout: Per-command timeout (seconds); falls back to the runner default.
                ``0`` or ``None`` with a zero default disables the timeout.
            stdin: Text piped to the process's stdin (e.g. a list of URLs).
            cwd: Working directory.
            env: Extra environment variables merged over ``os.environ``.
            output_file: If given, stdout is also written verbatim to this path
                (raw persistence lives with the stage, but this is handy for tools whose
                stdout *is* the artifact).
            acceptable_codes: Exit codes treated as success in addition to ``0``.
            label: Human-friendly name for logging (defaults to ``command[0]``).
        """
        name = label or command[0]
        effective_timeout = self._default_timeout if timeout is None else timeout

        if not self.tool_available(command[0]):
            msg = f"'{command[0]}' not found on PATH"
            logger.warning("[kaalyx.tool]%s[/] skipped — %s", name, msg)
            return CommandResult(
                command=command,
                returncode=None,
                stdout="",
                stderr="",
                duration_s=0.0,
                started=False,
                error=msg,
                acceptable_codes=acceptable_codes,
            )

        full_env = {**os.environ, **(env or {})}
        start = time.monotonic()

        async with self._semaphore:
            logger.debug("[kaalyx.tool]%s[/] $ %s", name, " ".join(command))
            try:
                proc = await asyncio.create_subprocess_exec(
                    *command,
                    stdin=asyncio.subprocess.PIPE if stdin is not None else None,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(cwd) if cwd else None,
                    env=full_env,
                )
            except (OSError, ValueError) as exc:
                duration = time.monotonic() - start
                logger.warning("[kaalyx.tool]%s[/] failed to start: %s", name, exc)
                return CommandResult(
                    command=command,
                    returncode=None,
                    stdout="",
                    stderr="",
                    duration_s=duration,
                    started=False,
                    error=str(exc),
                    acceptable_codes=acceptable_codes,
                )

            stdin_bytes = stdin.encode("utf-8", errors="replace") if stdin else None
            timed_out = False
            try:
                if effective_timeout and effective_timeout > 0:
                    stdout_b, stderr_b = await asyncio.wait_for(
                        proc.communicate(stdin_bytes), timeout=effective_timeout
                    )
                else:
                    stdout_b, stderr_b = await proc.communicate(stdin_bytes)
            except asyncio.TimeoutError:
                timed_out = True
                stdout_b, stderr_b = await self._terminate(proc)
                logger.warning(
                    "[kaalyx.tool]%s[/] timed out after %.0fs — terminated",
                    name,
                    effective_timeout,
                )
            except asyncio.CancelledError:
                await self._terminate(proc)
                raise
            except Exception as exc:  # pragma: no cover - defensive
                duration = time.monotonic() - start
                await self._terminate(proc)
                logger.error("[kaalyx.tool]%s[/] unexpected error: %s", name, exc)
                return CommandResult(
                    command=command,
                    returncode=None,
                    stdout="",
                    stderr="",
                    duration_s=duration,
                    started=True,
                    error=str(exc),
                    acceptable_codes=acceptable_codes,
                )

        duration = time.monotonic() - start
        stdout = stdout_b.decode("utf-8", errors="replace") if stdout_b else ""
        stderr = stderr_b.decode("utf-8", errors="replace") if stderr_b else ""

        out_path: Path | None = None
        if output_file is not None:
            out_path = Path(output_file)
            try:
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(stdout, encoding="utf-8")
            except OSError as exc:
                logger.warning("Could not write output file %s: %s", out_path, exc)
                out_path = None

        result = CommandResult(
            command=command,
            returncode=proc.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_s=duration,
            timed_out=timed_out,
            output_file=out_path,
            acceptable_codes=acceptable_codes,
        )

        if result.ok:
            logger.info(
                "[kaalyx.tool]%s[/] done in %.1fs (%d lines)",
                name,
                duration,
                len(result.stdout_lines()),
            )
        elif not timed_out:
            snippet = (stderr.strip().splitlines() or [""])[-1][:200]
            logger.warning(
                "[kaalyx.tool]%s[/] exited %s in %.1fs%s",
                name,
                proc.returncode,
                duration,
                f" — {snippet}" if snippet else "",
            )
        return result

    @staticmethod
    async def _terminate(proc: asyncio.subprocess.Process) -> tuple[bytes, bytes]:
        """Terminate a process tree as cleanly as possible and drain its pipes.

        Sends SIGTERM (or ``terminate()`` on Windows), waits briefly, then SIGKILL.
        Returns whatever output had been buffered so partial results aren't lost.
        """
        if proc.returncode is not None:
            return b"", b""
        try:
            proc.terminate()
        except ProcessLookupError:
            return b"", b""
        except Exception:  # pragma: no cover - platform quirks
            pass
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=5)
            return stdout_b or b"", stderr_b or b""
        except asyncio.TimeoutError:
            try:
                if os.name == "posix":
                    proc.send_signal(signal.SIGKILL)
                else:
                    proc.kill()
            except ProcessLookupError:
                pass
            try:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(), timeout=5
                )
                return stdout_b or b"", stderr_b or b""
            except Exception:  # pragma: no cover - defensive
                return b"", b""
        except Exception:  # pragma: no cover - defensive
            return b"", b""
