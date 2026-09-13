"""Checkpoint / resume state.

Every stage's completion is recorded so a crashed scan resumes from the last completed
stage rather than restarting from zero. We keep this state in a small JSON file per scan
(``checkpoints/<domain-slug>.json``) in addition to the ``stage_runs`` table, because the
checkpoint file must survive even a corrupted/locked database and is trivial to inspect
by hand.

The checkpoint records the scan id, the target, the options the scan was launched with,
and the set of completed stages. On resume we reattach to the same scan id (so all rows
accumulate under one scan) and skip stages already marked complete.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .logging import get_logger

logger = get_logger("checkpoint")


@dataclass
class Checkpoint:
    """Resumable state for a single scan."""

    domain: str
    slug: str
    scan_id: int
    options: dict = field(default_factory=dict)
    completed_stages: list[str] = field(default_factory=list)
    updated_at: str = ""

    def is_complete(self, stage: str) -> bool:
        return stage in self.completed_stages

    def mark_complete(self, stage: str) -> None:
        if stage not in self.completed_stages:
            self.completed_stages.append(stage)


class CheckpointStore:
    """Loads/saves :class:`Checkpoint` files under a checkpoint directory."""

    def __init__(self, checkpoint_dir: str | Path) -> None:
        self.dir = Path(checkpoint_dir)
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.warning("Could not create checkpoint dir %s: %s", self.dir, exc)

    def _path(self, slug: str) -> Path:
        return self.dir / f"{slug}.json"

    def load(self, slug: str) -> Checkpoint | None:
        """Return the checkpoint for *slug*, or ``None`` if none exists / is unreadable."""
        path = self._path(slug)
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return Checkpoint(**data)
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            logger.warning("Ignoring unreadable checkpoint %s: %s", path, exc)
            return None

    def save(self, checkpoint: Checkpoint) -> None:
        """Persist *checkpoint* atomically (write-temp-then-replace)."""
        checkpoint.updated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        path = self._path(checkpoint.slug)
        tmp = path.with_suffix(".json.tmp")
        try:
            tmp.write_text(json.dumps(asdict(checkpoint), indent=2), encoding="utf-8")
            tmp.replace(path)
        except OSError as exc:
            logger.warning("Could not save checkpoint %s: %s", path, exc)

    def clear(self, slug: str) -> None:
        """Remove a completed scan's checkpoint file."""
        path = self._path(slug)
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            logger.warning("Could not remove checkpoint %s: %s", path, exc)
