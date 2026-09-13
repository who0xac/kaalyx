"""Output parsers — turn heterogeneous tool output into normalised models.

Each recon/vuln tool emits its own format (line-oriented text, JSON lines, full JSON
documents). Parsers here convert those into the shared models in
:mod:`kaalyx.data.models` so stages stay focused on orchestration and persistence rather
than string-wrangling. Every parser is written to be *tolerant*: malformed or unexpected
lines are skipped (optionally logged), never fatal — a tool that changes its output
format slightly should degrade gracefully, not crash a scan.
"""

from __future__ import annotations

import json
from typing import Iterator


def iter_json_lines(text: str) -> Iterator[dict]:
    """Yield parsed JSON objects from JSON-lines (``jsonl``) output, skipping bad lines.

    Many ProjectDiscovery tools (dnsx, nuclei, katana, …) support ``-json`` / ``-jsonl``
    producing one JSON object per line; this is the common reader for them.
    """
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] not in "{[":
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            yield obj
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    yield item


def try_load_json(text: str):
    """Best-effort parse of a whole-document JSON string; returns ``None`` on failure."""
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None
