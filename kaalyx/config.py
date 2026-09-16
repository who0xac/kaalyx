"""Configuration loading for Kaalyx.

Precedence (highest wins): CLI flags > ``config.yaml`` > built-in defaults.
Secrets are read separately from a ``config.env`` file / the environment and are never mixed
into the YAML settings object.

The settings themselves are plain dataclasses so the rest of the codebase gets attribute
access and type hints rather than dict-key soup, while ``Secrets`` is a thin wrapper over
environment variables that reports which capabilities are available.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

from .core.exceptions import ConfigError

# --------------------------------------------------------------------------------------
# Standard config location (works the same whether run from source or pipx-installed).
# --------------------------------------------------------------------------------------


def config_dir() -> Path:
    """Return Kaalyx's config directory: ``$XDG_CONFIG_HOME/kaalyx`` or ``~/.config/kaalyx``.

    The conventional Linux location for a CLI tool's config. Independent of the current
    working directory, so a pipx-installed ``kaalyx`` always looks in the same place.
    """
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "kaalyx"


def config_file() -> Path:
    """Path of the config file in the standard config directory."""
    return config_dir() / "config.yaml"


def env_file() -> Path:
    """Path of the secrets file in the standard config directory.

    Named ``config.env`` (a normal visible file), not ``.env``, since a hidden dotfile is
    easy to miss with a plain ``ls``.
    """
    return config_dir() / "config.env"


def resolve_config_path(explicit: str | Path | None) -> Path | None:
    """Resolve which config.yaml to load. Precedence:

    1. an explicit ``--config`` path (must exist — a bad path is an error),
    2. ``./config.yaml`` in the CWD (convenient when working inside a source checkout),
    3. ``~/.config/kaalyx/config.yaml`` (the standard location for a pipx install).

    Returns the chosen path, or ``None`` when none exists (built-in defaults are then used).
    """
    if explicit is not None:
        return Path(explicit)
    cwd = Path("config.yaml")
    if cwd.is_file():
        return cwd
    standard = config_file()
    if standard.is_file():
        return standard
    return None


def resolve_env_path() -> Path | None:
    """Resolve which secrets file to load: ``./config.env`` in the CWD if present, else the
    standard ``~/.config/kaalyx/config.env``. A legacy ``./.env`` / ``~/.config/kaalyx/.env``
    is still honoured as a fallback so an existing install keeps working after the rename.
    Returns ``None`` if none exists (env-only secrets then)."""
    for candidate in (
        Path("config.env"),          # CWD, new name
        Path(".env"),                # CWD, legacy fallback
        env_file(),                  # standard dir, new name
        config_dir() / ".env",       # standard dir, legacy fallback
    ):
        if candidate.is_file():
            return candidate
    return None


def ensure_config_dir() -> tuple[Path, list[Path]]:
    """Create the config dir with template config.yaml and config.env if they're missing.

    Idempotent and non-destructive: only writes a file that does not already exist, so a
    user's edited config/secrets are never overwritten. Returns ``(dir, created_files)``.
    """
    created: list[Path] = []
    directory = config_dir()
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError:
        return directory, created  # can't create the dir at all — nothing to do

    # Write each template independently so a failure on one never blocks the other.
    for path, template in ((config_file(), _CONFIG_TEMPLATE), (env_file(), _ENV_TEMPLATE)):
        try:
            if not path.exists():
                path.write_text(template, encoding="utf-8")
                created.append(path)
        except OSError:
            # Non-fatal: fall back to built-in defaults / env-only secrets for this file.
            pass
    return directory, created


# --------------------------------------------------------------------------------------
# Settings dataclasses (mirror config.yaml). Defaults here ARE the built-in defaults.
# --------------------------------------------------------------------------------------


@dataclass
class GeneralConfig:
    # Root output directory. Empty string => the built-in default of
    # <Desktop>/kaalyx-results (resolved at runtime by output_root()). Everything for a
    # scan lives under <output_dir>/<domain>/: the raw per-stage .txt files, the scan's
    # SQLite database (kaalyx.db), and its checkpoint. Keeping the DB per-domain (not one
    # global file) is what lets a re-scan of the same target diff against history while
    # still living inside that domain's folder.
    output_dir: str = ""
    # Legacy/explicit overrides — normally derived from output_dir, but kept so an advanced
    # user can still pin absolute paths in config.yaml if they want.
    results_dir: str = ""
    database_path: str = ""
    checkpoint_dir: str = ""


@dataclass
class ConcurrencyConfig:
    max_parallel_tools: int = 8
    max_parallel_dns: int = 4
    default_tool_timeout: int = 900


@dataclass
class RateLimitConfig:
    chunk_size: int = 50
    backoff_factor: float = 2.0
    max_delay_seconds: float = 30.0
    max_retries: int = 3


@dataclass
class ScanConfig:
    full_nmap: bool = False
    brutespray: bool = False
    ipv6: bool = False
    sqlmap: bool = False


@dataclass
class TelegramConfig:
    enabled: bool = True
    alert_min_severity: str = "high"


@dataclass
class WebConfig:
    host: str = "127.0.0.1"
    port: int = 8787


@dataclass
class OsintConfig:
    """Per-source enable/disable toggles for the OSINT stage.

    Every OSINT sub-check can be turned off here (or via a matching ``--no-<source>`` CLI
    flag, which takes precedence). Default is all-on; sources with no tool/key installed
    skip themselves gracefully regardless of these toggles. Centralises the per-check
    booleans in one object.
    """

    whois: bool = True
    dns: bool = True                 # dnsx DNS records
    ip_info: bool = True             # resolved-IP geolocation / ASN / ISP-org / reverse-IP (keyless)
    mail_dns: bool = True            # SPF/DMARC/CAA/BIMI/MTA-STS/TLS-RPT
    m365: bool = True                # Microsoft 365 / Entra tenant mapping
    email_harvest: bool = True       # keyless email harvesting (email-format, skymem, pgp, security.txt)
    social: bool = True              # social-profile discovery from the homepage (keyless)
    breach_lookup: bool = True       # h8mail breach enrichment (needs key; else skips)
    leak_search: bool = True         # LeakSearch — actual leaked creds from ProxyNova/COMB dump
    github_subdomains: bool = True
    trufflehog: bool = True          # GitHub org secret scan (needs GITHUB_TOKEN)
    cloud_enum: bool = True
    s3scanner: bool = True
    badsecrets: bool = True
    retirejs: bool = True
    theharvester: bool = True        # emails/employees/hosts (external tool)
    third_party_misconfig: bool = True  # misconfig-mapper (external tool)
    api_leaks: bool = True           # porch-pirate (Postman) + SwaggerSpy (external tools)
    exposed_git: bool = True         # in-process /.git/config detection (keyless)
    firebase: bool = True            # Firebase Realtime DB exposure check (keyless)
    github_actions: bool = True      # gato — GitHub Actions audit (external tool, needs token)
    google_dorks: bool = True        # dork URL generation (no scraping)
    # Shodan-backed OSINT (needs SHODAN_API_KEY; each skips cleanly without it or when the
    # account's tier doesn't permit the query). These go beyond the domain-scoped hostname/ssl
    # search in the Subdomains stage — see PROJECT_MEMORY.md (paid-membership reversal).
    shodan_org: bool = True          # org/ASN infrastructure search (forgotten/internal hosts)
    shodan_favicon: bool = True      # favicon-hash pivot to related/look-alike infrastructure
    shodan_vulns: bool = True        # passive CVE/vuln tags for resolved IPs (no packets sent)
    shodan_host: bool = True         # per-IP deep lookup (ports/banners/history from cache)


@dataclass
class FlaggingConfig:
    interesting_keywords: list[str] = field(
        default_factory=lambda: [
            "dev", "staging", "stage", "test", "qa", "uat", "admin", "internal",
            "intranet", "vpn", "jenkins", "gitlab", "jira", "api", "beta", "demo",
            "backup", "old", "legacy", "portal",
        ]
    )


@dataclass
class Config:
    """Top-level Kaalyx settings object."""

    general: GeneralConfig = field(default_factory=GeneralConfig)
    concurrency: ConcurrencyConfig = field(default_factory=ConcurrencyConfig)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    web: WebConfig = field(default_factory=WebConfig)
    flagging: FlaggingConfig = field(default_factory=FlaggingConfig)
    osint: OsintConfig = field(default_factory=OsintConfig)


# --------------------------------------------------------------------------------------
# Loading & merging
# --------------------------------------------------------------------------------------


def output_root(config: "Config") -> Path:
    """Resolve the root output directory for scans.

    Precedence: an explicit ``general.output_dir`` in config, otherwise the built-in
    default ``<Desktop>/kaalyx-results``. On systems without a Desktop folder (headless
    servers/VPS), falls back to ``<home>/kaalyx-results`` so it always resolves to
    something writable and predictable.
    """
    configured = (config.general.output_dir or "").strip()
    if configured:
        return Path(configured).expanduser()

    home = Path.home()
    desktop = home / "Desktop"
    base = desktop if desktop.is_dir() else home
    return base / "kaalyx-results"


def resolve_paths(config: "Config", domain_slug: str) -> tuple[Path, Path, Path]:
    """Return ``(results_dir, database_path, checkpoint_dir)`` for a scan of *domain_slug*.

    By default all three live under ``<output_root>/<domain>/`` so a scan is fully
    self-contained in one folder (raw .txt files + kaalyx.db + checkpoint). Explicit
    ``general.results_dir`` / ``database_path`` / ``checkpoint_dir`` overrides still win
    for advanced users who set them in config.yaml.
    """
    root = output_root(config)
    domain_dir = root / domain_slug

    results = Path(config.general.results_dir).expanduser() if config.general.results_dir else root
    database = (
        Path(config.general.database_path).expanduser()
        if config.general.database_path
        else domain_dir / "kaalyx.db"
    )
    checkpoint = (
        Path(config.general.checkpoint_dir).expanduser()
        if config.general.checkpoint_dir
        else domain_dir / "checkpoints"
    )
    return results, database, checkpoint


def _apply_mapping(target: Any, data: dict[str, Any], path: str = "") -> None:
    """Recursively overlay a plain dict onto a (possibly nested) dataclass instance.

    Unknown keys raise :class:`ConfigError` so typos in config.yaml are caught early
    rather than silently ignored.
    """
    valid = {f.name: f for f in fields(target)}
    for key, value in data.items():
        where = f"{path}.{key}" if path else key
        if key not in valid:
            raise ConfigError(f"Unknown config key: '{where}'")
        current = getattr(target, key)
        if is_dataclass(current) and isinstance(value, dict):
            _apply_mapping(current, value, where)
        else:
            setattr(target, key, value)


def load_config(config_path: str | Path | None = None) -> Config:
    """Load settings from a YAML file, falling back to built-in defaults.

    Args:
        config_path: Path to a YAML config. If ``None``, resolution follows
            :func:`resolve_config_path` (explicit > ``./config.yaml`` > standard config dir);
            if nothing is found, pure built-in defaults are returned.
    """
    config = Config()
    config_path = resolve_config_path(config_path)

    if config_path is not None:
        path = Path(config_path)
        if not path.is_file():
            raise ConfigError(f"Config file not found: {path}")
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"Failed to parse {path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise ConfigError(f"Config root must be a mapping, got {type(raw).__name__}")
        _apply_mapping(config, raw)

    return config


# --------------------------------------------------------------------------------------
# Secrets (from config.env / environment) — kept strictly separate from settings.
# --------------------------------------------------------------------------------------


@dataclass
class Secrets:
    """API keys and tokens sourced from the environment / ``config.env``.

    A missing value simply disables the corresponding source or feature; Kaalyx never
    crashes because a key is absent. Booleans below let callers check availability
    without leaking the raw values around the codebase.
    """

    shodan_api_key: str | None = None
    censys_api_id: str | None = None
    censys_api_secret: str | None = None
    chaos_api_key: str | None = None
    github_tokens: list[str] = field(default_factory=list)
    ipinfo_token: str | None = None
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None

    # Breach/credential-lookup extras — all optional. When set, they let h8mail surface actual
    # leaked passwords/hashes (not just breach counts): an h8mail INI with credential-returning
    # API keys (Snusbase/Dehashed/Leak-Lookup), a local "Breach Compilation" folder, and/or a
    # local cleartext breach dump file. Absent => h8mail still runs and returns counts only.
    h8mail_config: str | None = None
    breach_comp_path: str | None = None
    local_breach_path: str | None = None

    # Round-robin cursor for GitHub token rotation (not persisted; per-process).
    _gh_cursor: int = 0

    @property
    def has_shodan(self) -> bool:
        return bool(self.shodan_api_key)

    @property
    def has_censys(self) -> bool:
        return bool(self.censys_api_id and self.censys_api_secret)

    @property
    def has_chaos(self) -> bool:
        return bool(self.chaos_api_key)

    @property
    def has_github(self) -> bool:
        return bool(self.github_tokens)

    @property
    def github_token(self) -> str | None:
        """The first GitHub token (back-compat for callers that want a single value)."""
        return self.github_tokens[0] if self.github_tokens else None

    def next_github_token(self) -> str | None:
        """Return the next GitHub token round-robin, to spread API usage (#6).

        With one token this always returns that token (identical to the old behaviour);
        with several it hands out a different one on each call so GitHub-dependent sources
        don't all hammer a single token's rate limit.
        """
        if not self.github_tokens:
            return None
        token = self.github_tokens[self._gh_cursor % len(self.github_tokens)]
        self._gh_cursor += 1
        return token

    @property
    def has_ipinfo(self) -> bool:
        return bool(self.ipinfo_token)

    @property
    def has_telegram(self) -> bool:
        return bool(self.telegram_bot_token and self.telegram_chat_id)


def load_secrets(env_path: str | Path | None = None) -> Secrets:
    """Load secrets from a ``config.env`` file (if present) plus the process environment.

    If *env_path* is ``None``, resolution follows :func:`resolve_env_path` (``./config.env`` >
    standard config dir). Values already in the environment take precedence over the file
    (conventional ``python-dotenv`` behaviour; lets shell exports / CI override).
    """
    if env_path is None:
        env_path = resolve_env_path()
    if env_path is not None:
        load_dotenv(dotenv_path=str(env_path), override=False)

    def _get(name: str) -> str | None:
        value = os.environ.get(name)
        return value.strip() if value and value.strip() else None

    return Secrets(
        shodan_api_key=_get("SHODAN_API_KEY"),
        censys_api_id=_get("CENSYS_API_ID"),
        censys_api_secret=_get("CENSYS_API_SECRET"),
        chaos_api_key=_get("CHAOS_API_KEY"),
        github_tokens=_collect_github_tokens(),
        ipinfo_token=_get("IPINFO_TOKEN"),
        telegram_bot_token=_get("TELEGRAM_BOT_TOKEN"),
        telegram_chat_id=_get("TELEGRAM_CHAT_ID"),
        h8mail_config=_get("H8MAIL_CONFIG"),
        breach_comp_path=_get("BREACH_COMP_PATH"),
        local_breach_path=_get("LOCAL_BREACH_PATH"),
    )


def _collect_github_tokens() -> list[str]:
    """Gather all configured GitHub tokens for rotation.

    Uses the numbered form only: ``GITHUB_TOKEN``, then ``GITHUB_TOKEN_2``,
    ``GITHUB_TOKEN_3`` … (contiguous). One token behaves exactly as a single-token setup.
    (The earlier comma-separated ``GITHUB_TOKENS`` form was removed — one clear format.)
    """
    tokens: list[str] = []

    def _add(value: str | None) -> None:
        value = (value or "").strip()
        if value and value not in tokens:
            tokens.append(value)

    _add(os.environ.get("GITHUB_TOKEN"))
    i = 2
    while True:
        val = os.environ.get(f"GITHUB_TOKEN_{i}")
        if val is None:
            break
        _add(val)
        i += 1
    return tokens


# --------------------------------------------------------------------------------------
# First-run templates written into ~/.config/kaalyx/ when the files don't exist yet.
# --------------------------------------------------------------------------------------

_CONFIG_TEMPLATE = """\
# Kaalyx configuration (settings only — secrets live in config.env alongside this file).
# Precedence: CLI flags > this file > built-in defaults. Delete any key to use its default.

general:
  # Root output directory. Leave blank for the default: <Desktop>/kaalyx-results
  # (falls back to ~/kaalyx-results on headless machines).
  output_dir: ""

concurrency:
  max_parallel_tools: 8
  max_parallel_dns: 4
  default_tool_timeout: 900

rate_limit:
  chunk_size: 50
  backoff_factor: 2.0
  max_delay_seconds: 30
  max_retries: 3

telegram:
  enabled: true          # auto-disabled if the bot token / chat id are missing in config.env
  alert_min_severity: high

# OSINT sub-checks — set any to false to skip it (a --skip-osint CLI flag also works).
osint:
  whois: true
  dns: true
  ip_info: true
  mail_dns: true
  m365: true
  email_harvest: true
  social: true
  breach_lookup: true
  leak_search: true
  github_subdomains: true
  trufflehog: true
  cloud_enum: true
  s3scanner: true
  badsecrets: true
  retirejs: true
  theharvester: true
  third_party_misconfig: true
  api_leaks: true
  exposed_git: true
  github_actions: true
  google_dorks: true
"""

_ENV_TEMPLATE = """\
# Kaalyx secrets. A blank value simply disables the source/feature that needs it —
# Kaalyx skips it gracefully, it never crashes for a missing key.

# GitHub (used by: github-subdomains, trufflehog, GitHub Actions audit)
# Get a token at: https://github.com/settings/tokens  (classic; scopes: repo, read:org)
# Multiple tokens are rotated to avoid rate limits — add GITHUB_TOKEN_2, _3, ... as needed.
GITHUB_TOKEN=
GITHUB_TOKEN_2=
GITHUB_TOKEN_3=

# Shodan (used by: subdomain discovery, domain-scoped host/ssl search)
# Get a key at: https://account.shodan.io
SHODAN_API_KEY=

# Censys (used by: subdomain discovery)
# Get credentials at: https://search.censys.io/account/api
CENSYS_API_ID=
CENSYS_API_SECRET=

# ProjectDiscovery Chaos (used by: subdomain discovery — Chaos dataset)
# Get a key at: https://cloud.projectdiscovery.io
CHAOS_API_KEY=

# ipinfo.io (used by: host stage — IP geolocation / ASN)
# Get a token at: https://ipinfo.io/account/token
IPINFO_TOKEN=

# Telegram notifications (used by: --notify scan alerts)
# Create a bot via @BotFather, then get your numeric chat id (e.g. via @userinfobot).
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=

# Breach / leaked-credential lookup (used by: breach_lookup source, h8mail).
# All optional. Without them, h8mail still runs and reports which breaches an email appears
# in; WITH them, h8mail can return the ACTUAL leaked passwords/hashes:
#   H8MAIL_CONFIG    = path to an h8mail INI with credential-returning API keys
#                      (Snusbase / Dehashed / Leak-Lookup). See `h8mail -g` for a template.
#   BREACH_COMP_PATH = path to a local "Breach Compilation" folder (h8mail -bc)
#   LOCAL_BREACH_PATH= path to a local cleartext breach dump file (h8mail -lb)
# (The keyless LeakSearch source needs no config — it queries the ProxyNova/COMB dump.)
H8MAIL_CONFIG=
BREACH_COMP_PATH=
LOCAL_BREACH_PATH=
"""
