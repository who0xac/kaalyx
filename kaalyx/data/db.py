"""SQLite connection management and schema for Kaalyx.

One database file holds every scan the user has ever run (keyed by ``scan`` rows), which
is exactly what continuous monitoring needs: to know "what's new since last time" we
compare the current scan's rows against the most recent *previous* scan for the same
domain (see :mod:`kaalyx.data.repository` and :mod:`kaalyx.monitor.diff`).

The schema is created idempotently on connect. A lightweight ``schema_version`` row lets
future migrations key off the current version without an external migration framework.
WAL mode is enabled so the read-only web dashboard can query while a scan is writing.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from ..core.logging import get_logger

logger = get_logger("db")

SCHEMA_VERSION = 2

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- One row per scan run. `stage_state` / progress live in the checkpoint files;
-- this table is the durable record the dashboard and diffing read from.
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    domain        TEXT    NOT NULL,        -- normalised target hostname
    registrable   TEXT    NOT NULL,        -- apex/registrable domain
    target_type   TEXT    NOT NULL,        -- 'apex' | 'subdomain'
    started_at    TEXT    NOT NULL,
    finished_at   TEXT,
    status        TEXT    NOT NULL DEFAULT 'running',  -- running|completed|failed|aborted
    options_json  TEXT    NOT NULL DEFAULT '{}'        -- opt-in flags used for this run
);
CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);

-- Per-stage execution record for a scan (used for resume + dashboard timeline).
CREATE TABLE IF NOT EXISTS stage_runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    stage        TEXT    NOT NULL,         -- osint|subdomains|hosts|web|vulns
    status       TEXT    NOT NULL DEFAULT 'pending', -- pending|running|completed|failed|skipped
    started_at   TEXT,
    finished_at  TEXT,
    detail       TEXT    DEFAULT '',       -- summary / error message
    UNIQUE(scan_id, stage)
);

CREATE TABLE IF NOT EXISTS subdomains (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id             INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    hostname            TEXT    NOT NULL,
    source              TEXT    NOT NULL DEFAULT '',
    resolved            INTEGER NOT NULL DEFAULT 0,
    ip_addresses        TEXT    NOT NULL DEFAULT '',  -- comma-separated
    interesting         INTEGER NOT NULL DEFAULT 0,
    interesting_reason  TEXT,
    discovered_at       TEXT    NOT NULL,
    UNIQUE(scan_id, hostname)
);
CREATE INDEX IF NOT EXISTS idx_subdomains_scan ON subdomains(scan_id);

CREATE TABLE IF NOT EXISTS hosts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip             TEXT    NOT NULL,
    hostname       TEXT,
    open_ports     TEXT    NOT NULL DEFAULT '',       -- comma-separated ints
    is_cdn         INTEGER NOT NULL DEFAULT 0,
    cdn_name       TEXT,
    waf            TEXT,
    geo            TEXT,
    technologies   TEXT    NOT NULL DEFAULT '',
    source         TEXT    NOT NULL DEFAULT '',
    discovered_at  TEXT    NOT NULL,
    UNIQUE(scan_id, ip)
);
CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);

CREATE TABLE IF NOT EXISTS web_urls (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id          INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    url              TEXT    NOT NULL,
    source           TEXT    NOT NULL DEFAULT '',
    status_code      INTEGER,
    gf_patterns      TEXT    NOT NULL DEFAULT '',      -- comma-separated
    screenshot_path  TEXT,
    discovered_at    TEXT    NOT NULL,
    UNIQUE(scan_id, url)
);
CREATE INDEX IF NOT EXISTS idx_web_urls_scan ON web_urls(scan_id);

CREATE TABLE IF NOT EXISTS findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    dedup_key      TEXT    NOT NULL,
    title          TEXT    NOT NULL,
    category       TEXT    NOT NULL DEFAULT '',
    severity       TEXT    NOT NULL DEFAULT 'unknown',
    confidence     TEXT    NOT NULL DEFAULT 'unknown',
    target         TEXT    NOT NULL DEFAULT '',
    tools          TEXT    NOT NULL DEFAULT '',        -- comma-separated (dedup merges)
    description    TEXT    NOT NULL DEFAULT '',
    evidence       TEXT    NOT NULL DEFAULT '',
    reference      TEXT    NOT NULL DEFAULT '',
    raw            TEXT    NOT NULL DEFAULT '',
    alerted        INTEGER NOT NULL DEFAULT 0,         -- Telegram alert sent?
    discovered_at  TEXT    NOT NULL,
    UNIQUE(scan_id, dedup_key)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(scan_id, severity);

CREATE TABLE IF NOT EXISTS osint (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    kind           TEXT    NOT NULL,
    value          TEXT    NOT NULL,
    detail         TEXT    NOT NULL DEFAULT '',
    source         TEXT    NOT NULL DEFAULT '',
    discovered_at  TEXT    NOT NULL,
    UNIQUE(scan_id, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_osint_scan ON osint(scan_id);

CREATE TABLE IF NOT EXISTS emails (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    address        TEXT    NOT NULL,
    source         TEXT    NOT NULL DEFAULT '',
    breached       INTEGER NOT NULL DEFAULT 0,
    breach_count   INTEGER NOT NULL DEFAULT 0,
    breach_detail  TEXT    NOT NULL DEFAULT '',
    discovered_at  TEXT    NOT NULL,
    UNIQUE(scan_id, address)
);
CREATE INDEX IF NOT EXISTS idx_emails_scan ON emails(scan_id);

CREATE TABLE IF NOT EXISTS employees (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    name           TEXT    NOT NULL,
    source         TEXT    NOT NULL DEFAULT '',
    role           TEXT    NOT NULL DEFAULT '',
    discovered_at  TEXT    NOT NULL,
    UNIQUE(scan_id, name, source)
);
CREATE INDEX IF NOT EXISTS idx_employees_scan ON employees(scan_id);
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Open (creating if needed) the Kaalyx database and ensure the schema exists.

    Returns a connection with:
      * ``row_factory = sqlite3.Row`` for dict-like access,
      * foreign keys enforced,
      * WAL journalling so the dashboard can read during an active scan.
    """
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    _init_schema(conn)
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA)
    row = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        logger.debug("Initialised Kaalyx schema v%d", SCHEMA_VERSION)
    else:
        existing = int(row["value"])
        if existing != SCHEMA_VERSION:
            # Migration hook: only v1 exists today, so nothing to do yet.
            logger.warning(
                "DB schema v%d differs from code v%d — migrations not yet implemented",
                existing,
                SCHEMA_VERSION,
            )
    conn.commit()
