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

SCHEMA_VERSION = 3

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
    -- Discrete, queryable location/value columns for the web dashboard (Part 6). Secret-scan
    -- findings pack "repo | file:line | value" into evidence; these break that out so the
    -- dashboard can filter/sort/search on real fields instead of parsing a text blob.
    location       TEXT    NOT NULL DEFAULT '',         -- repo / owner / host the finding is in
    file_path      TEXT    NOT NULL DEFAULT '',         -- file within the repo (secrets)
    line_no        INTEGER,                             -- line within the file (NULL if n/a)
    secret_value   TEXT    NOT NULL DEFAULT '',         -- the full, unmasked detected value
    verified       INTEGER NOT NULL DEFAULT 0,          -- 1 if the secret live-authenticated
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
            _migrate(conn, existing)
            conn.execute(
                "UPDATE meta SET value = ? WHERE key = 'schema_version'",
                (str(SCHEMA_VERSION),),
            )
    # Indexes that reference a migration-added column live here (not in _SCHEMA's executescript)
    # so a pre-migration table without that column doesn't error out before _migrate runs. Safe
    # for both a fresh DB (column present from _SCHEMA) and a migrated one.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_verified ON findings(scan_id, verified)")
    conn.commit()


def _finding_columns(conn: sqlite3.Connection) -> set[str]:
    return {r["name"] for r in conn.execute("PRAGMA table_info(findings)").fetchall()}


def _migrate(conn: sqlite3.Connection, from_version: int) -> None:
    """Apply additive, non-destructive migrations to an existing DB (a per-domain re-scan opens
    the same file). Only ADD COLUMN so no data is ever lost. Idempotent — each column is added
    only if absent, so a partially-migrated DB is safe to re-open."""
    # v3: discrete queryable location/value columns on findings for the web dashboard.
    existing_cols = _finding_columns(conn)
    additive = [
        ("location", "TEXT NOT NULL DEFAULT ''"),
        ("file_path", "TEXT NOT NULL DEFAULT ''"),
        ("line_no", "INTEGER"),
        ("secret_value", "TEXT NOT NULL DEFAULT ''"),
        ("verified", "INTEGER NOT NULL DEFAULT 0"),
    ]
    for col, decl in additive:
        if col not in existing_cols:
            conn.execute(f"ALTER TABLE findings ADD COLUMN {col} {decl}")
    # The idx_findings_verified index is (re)created by _init_schema after this returns, once the
    # column is guaranteed present.
    logger.info("Migrated DB schema v%d → v%d (added finding location/value columns)",
                from_version, SCHEMA_VERSION)
