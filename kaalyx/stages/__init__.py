"""Pipeline stages for Kaalyx.

Each module here implements one part of the 6-part pipeline as a
:class:`~kaalyx.core.stage.Stage` subclass. The orchestrator is given a list of stage
*factories*; each factory carries a ``__stage_name__`` marker so the orchestrator can
decide (before instantiating) whether to skip a stage for a given target type.

Use :func:`make_factory` to turn a stage class into such a factory.
"""

from __future__ import annotations

from typing import Callable

from ..core.context import ScanContext
from ..core.stage import Stage


def make_factory(stage_cls: type[Stage]) -> Callable[[ScanContext], Stage]:
    """Wrap a stage class into an orchestrator factory, tagging it with its stage name."""

    def factory(ctx: ScanContext) -> Stage:
        return stage_cls(ctx)

    factory.__stage_name__ = stage_cls.name  # type: ignore[attr-defined]
    factory.__name__ = f"make_{stage_cls.name}"
    return factory
