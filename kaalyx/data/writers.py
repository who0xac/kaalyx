"""Raw ``.txt`` file output for Kaalyx.

Every stage persists to *both* SQLite and raw files. This module
owns the raw side: the ``results/<domain>/<stage>/`` directory tree and simple, robust
append/write helpers. Raw files are deliberately plain text — they are what the user
greps, diffs, and feeds into other manual tooling — so we keep them tool-native (one
item per line) wherever possible and never let a write error abort a scan.

Directory layout::

    results/<domain>/
        kaalyx.log                        # full run log (attached by core.logging)
        <stage>/                          # osint | subdomains | hosts | web | vulns
            <source>.txt                  # READABLE, field-labeled per-source output
            <artifact>.txt                # cross-source rollups (subdomains.txt, emails.txt, …)
            tool_output/<source>.raw.<ext># verbatim, unprocessed RAW output per source/tool

Everything for one scan lives under ``results/<domain-slug>/`` and NOTHING is ever written
outside that per-target tree, so two targets can never contaminate each other's folder. A
stage also wipes its own output directory at the start of a run (:meth:`reset_stage_dir`) so a
re-scan can't inherit stale files from an earlier build or a different target.
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

    def reset_stage_dir(self, stage: str) -> None:
        """Wipe and recreate *stage*'s output directory before the stage runs.

        Guarantees a stage's folder contains ONLY the current scan's output — so a re-scan (or
        a folder that accumulated files from an earlier build, or any stray artifact) starts
        clean and can never present stale or cross-target data. Scoped strictly to
        ``<base>/<stage>`` (the current target's own tree); never touches anything outside it.
        Best-effort — a failure to clean is logged and the stage still runs.
        """
        import shutil
        path = self.base / stage
        try:
            if path.exists():
                shutil.rmtree(path)
        except OSError as exc:
            logger.warning("Could not reset stage dir %s: %s", path, exc)
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.warning("Could not recreate stage dir %s: %s", path, exc)

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

    def raw_source_output(self, stage: str, source: str, content: str,
                          ext: str = "txt", header: str = "") -> Path | None:
        """Persist ONE dedicated RAW file per source under ``<stage>/tool_output/<source>.raw.<ext>``
        — UNCONDITIONALLY, even when *content* is empty (an empty file records that the source ran
        and found nothing). The ``.raw`` in the name marks it as the verbatim, unformatted tool
        output, distinct from the readable ``<source>.txt`` in the stage folder. *header* is an
        optional first line (e.g. a skip reason) so an empty file still says why.
        """
        raw_dir = self.stage_dir(stage) / "tool_output"
        try:
            raw_dir.mkdir(parents=True, exist_ok=True)
            path = raw_dir / f"{source}.raw.{ext}"
            body = content if content is not None else ""
            if header:
                body = f"# {header}\n" + (body if body else "")
            path.write_text(body, encoding="utf-8")
            return path
        except OSError as exc:
            logger.warning("Could not write raw output for source %s: %s", source, exc)
            return None
