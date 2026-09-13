"""Adaptive rate limiting + retry queue.

The contract, taken verbatim from the spec:

* Process URLs/requests in **chunks**.
* Detect ``429``/``503`` responses and **slow down for the NEXT chunk only** — never
  kill or restart in-flight work.
* Maintain a **retry queue** for anything blocked; retry it later at a safer rate.
* Log an item as unresolved **only after several genuine attempts**, never silently drop.

This module provides the reusable mechanism. Stages that make many HTTP requests (or feed
many URLs to a tool that reports rate-limit responses) drive an :class:`AdaptiveRateLimiter`
around their chunk loop and hand blocked items to its :class:`RetryQueue`.

The limiter is intentionally *reactive and per-chunk*: it never pre-emptively throttles a
chunk that is already running; it only widens the inter-item delay applied to the chunks
that follow, and narrows it again when chunks come back clean.
"""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, field
from typing import Generic, TypeVar

from .logging import get_logger

logger = get_logger("ratelimit")

T = TypeVar("T")

# HTTP status codes that mean "you are being throttled / the service is overloaded".
THROTTLE_CODES: frozenset[int] = frozenset({429, 503})


@dataclass
class RetryItem(Generic[T]):
    """An item awaiting retry, with a running count of genuine attempts."""

    payload: T
    attempts: int = 0


class RetryQueue(Generic[T]):
    """FIFO queue of items that were blocked and should be retried at a safer rate.

    Items exceeding ``max_retries`` genuine attempts are moved to :attr:`unresolved`
    rather than dropped, so the stage can persist them as "blocked/unresolved".
    """

    def __init__(self, max_retries: int = 3) -> None:
        self._queue: deque[RetryItem[T]] = deque()
        self.max_retries = max_retries
        self.unresolved: list[T] = []

    def __len__(self) -> int:
        return len(self._queue)

    def add(self, payload: T, attempts: int = 1) -> None:
        """Enqueue *payload* for retry (or file it as unresolved if out of attempts)."""
        if attempts >= self.max_retries:
            self.unresolved.append(payload)
            logger.warning("Item exhausted %d retries, marking unresolved", attempts)
        else:
            self._queue.append(RetryItem(payload, attempts))

    def drain(self) -> list[RetryItem[T]]:
        """Return and clear all currently queued items (for the next retry pass)."""
        items = list(self._queue)
        self._queue.clear()
        return items

    @property
    def has_pending(self) -> bool:
        return bool(self._queue)


@dataclass
class AdaptiveRateLimiter:
    """Tracks per-chunk throttling signals and computes the delay for the next chunk.

    Usage pattern inside a stage::

        limiter = AdaptiveRateLimiter(...)
        for chunk in chunks(items, limiter.chunk_size):
            limiter.begin_chunk()
            for item in chunk:
                await limiter.pace()          # applies the current inter-item delay
                status = await do_request(item)
                limiter.observe(status)       # note 429/503 etc.
            limiter.end_chunk()               # recompute delay for the *next* chunk
    """

    chunk_size: int = 50
    backoff_factor: float = 2.0
    max_delay_seconds: float = 30.0
    max_retries: int = 3

    _current_delay: float = field(default=0.0, init=False)
    _chunk_throttled: bool = field(default=False, init=False)
    _base_step: float = field(default=0.25, init=False)  # delay added on first throttle

    def begin_chunk(self) -> None:
        """Reset the per-chunk throttle flag before processing a new chunk."""
        self._chunk_throttled = False

    def observe(self, status_code: int | None) -> None:
        """Record an HTTP status; flags the chunk as throttled on 429/503."""
        if status_code in THROTTLE_CODES:
            self._chunk_throttled = True

    def observe_throttled(self) -> None:
        """Explicitly flag the current chunk as throttled (for non-HTTP signals)."""
        self._chunk_throttled = True

    async def pace(self) -> None:
        """Sleep the current inter-item delay (no-op while delay is zero)."""
        if self._current_delay > 0:
            await asyncio.sleep(self._current_delay)

    def end_chunk(self) -> None:
        """Recompute the delay applied to the *next* chunk based on this chunk's result.

        Throttled -> widen the delay (multiplicative back-off, capped).
        Clean      -> narrow it back toward zero so throughput recovers.
        """
        if self._chunk_throttled:
            new_delay = (
                self._base_step
                if self._current_delay == 0
                else self._current_delay * self.backoff_factor
            )
            self._current_delay = min(new_delay, self.max_delay_seconds)
            logger.info(
                "Throttling detected — next chunk paced at %.2fs/item", self._current_delay
            )
        elif self._current_delay > 0:
            # Recover gradually: halve the delay after a clean chunk.
            self._current_delay = max(0.0, self._current_delay / 2)
            if self._current_delay < 0.05:
                self._current_delay = 0.0

    @property
    def current_delay(self) -> float:
        return self._current_delay


def chunked(items: list[T], size: int) -> list[list[T]]:
    """Split *items* into consecutive chunks of at most *size* elements."""
    size = max(1, size)
    return [items[i : i + size] for i in range(0, len(items), size)]
