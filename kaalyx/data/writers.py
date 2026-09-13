"""Raw ``.txt`` file output for Kaalyx.

Every stage persists to *both* SQLite and raw files. This module
owns the raw side: the ``results/<domain>/<stage>/`` directory tree and simple, robust
append/write helpers. Raw files are deliberately plain text — they are what the user
greps, diffs, and feeds into other manual tooling — so we keep them tool-native (one
item per line) wherever possible and never let a write error abort a scan.

Directory layout::

    results/<domain>/
        kaalyx.log                      # full run log (attached by core.logging)
        <stage>/                        # osint | subdomains | hosts | web | vulns
            <artifact>.txt              # e.g. subfinder.txt, all_subdomains.txt
            raw/<tool>.stdout.txt       # verbatim tool stdout for traceability
"""

from __future__ import annotations

from pathlib import Path

from ..core.logging import get_logger

logger = get_logger("writers")


class ResultWriter:
    """Writes raw stage artifacts under ``results/<domain>/``.

    A single instance is created per scan (its ``base`` is ``results/<domain-slug>``)
    and shared with every stage. All methods swallow :class:`OSError` into a logged
    warning so filesystem hiccups never crash a scan — the SQLite copy is still authoritative.
    """

    def __init__(self, results_dir: str | Path, domain_slug: str) -> None:
        self.base = Path(results_dir) / domain_slug
        try:
            self.base.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.error("Could not create results dir %s: %s", self.base, exc)

    # -- path helpers ------------------------------------------------------------------

    def stage_dir(self, stage: str) -> Path:
        """Return (creating if needed) the directory for *stage*'s artifacts."""
        path = self.base / stage
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.warning("Could not create stage dir %s: %s", path, exc)
        return path

    def log_path(self) -> Path:
        """Path of the per-scan text log file (used by core.logging)."""
        return self.base / "kaalyx.log"

    # -- writing -----------------------------------------------------------------------

    def write_lines(
        self, stage: str, filename: str, lines: list[str], *, sort: bool = True
    ) -> Path | None:
        """Write an iterable of lines (deduplicated) to ``<stage>/<filename>``.

        Returns the path written, or ``None`` on failure.
        """
        cleaned = [ln.strip() for ln in lines if ln and ln.strip()]
        if sort:
            cleaned = sorted(set(cleaned))
        else:
            # Preserve order but drop dupes.
            seen: set[str] = set()
            ordered = []
            for ln in cleaned:
                if ln not in seen:
                    seen.add(ln)
                    ordered.append(ln)
            cleaned = ordered
        path = self.stage_dir(stage) / filename
        try:
            path.write_text("\n".join(cleaned) + ("\n" if cleaned else ""), encoding="utf-8")
            return path
        except OSError as exc:
            logger.warning("Could not write %s: %s", path, exc)
            return None

    def write_text(self, stage: str, filename: str, text: str) -> Path | None:
        """Write arbitrary text to ``<stage>/<filename>``."""
        path = self.stage_dir(stage) / filename
        try:
            path.write_text(text, encoding="utf-8")
            return path
        except OSError as exc:
            logger.warning("Could not write %s: %s", path, exc)
            return None

    def append_line(self, stage: str, filename: str, line: str) -> None:
        """Append a single line to ``<stage>/<filename>`` (for streaming/incremental output)."""
        path = self.stage_dir(stage) / filename
        try:
            with path.open("a", encoding="utf-8") as fh:
                fh.write(line.rstrip("\n") + "\n")
        except OSError as exc:
            logger.warning("Could not append to %s: %s", path, exc)

    def raw_tool_output(self, stage: str, tool: str, stdout: str) -> Path | None:
        """Persist a tool's verbatim stdout under ``<stage>/raw/<tool>.stdout.txt``."""
        raw_dir = self.stage_dir(stage) / "raw"
        try:
            raw_dir.mkdir(parents=True, exist_ok=True)
            path = raw_dir / f"{tool}.stdout.txt"
            path.write_text(stdout, encoding="utf-8")
            return path
        except OSError as exc:
            logger.warning("Could not write raw output for %s: %s", tool, exc)
            return None
