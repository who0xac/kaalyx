"""Configuration loading for Kaalyx.

Precedence (highest wins): CLI flags > ``config.yaml`` > built-in defaults.
Secrets are read separately from a ``.env`` file / the environment and are never mixed
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
    skip themselves gracefully regardless of these toggles. Mirrors ReconFTW's per-check
    booleans but centralised in one object.
    """

    whois: bool = True
    dns: bool = True                 # dnsx DNS records
    mail_dns: bool = True            # SPF/DMARC/CAA/BIMI/MTA-STS/TLS-RPT
    m365: bool = True                # Microsoft 365 / Entra tenant mapping
    email_harvest: bool = True       # keyless email harvesting (email-format, skymem)
    breach_lookup: bool = True       # h8mail breach enrichment (needs key; else skips)
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
    github_actions: bool = True      # gato — GitHub Actions audit (external tool, needs token)
    google_dorks: bool = True        # dork URL generation (no scraping)


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
        config_path: Path to a YAML config. If ``None``, ``config.yaml`` in the current
            working directory is used when present; otherwise pure defaults are returned.
    """
    config = Config()

    if config_path is None:
        candidate = Path("config.yaml")
        config_path = candidate if candidate.is_file() else None

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
# Secrets (from .env / environment) — kept strictly separate from settings.
# --------------------------------------------------------------------------------------


@dataclass
class Secrets:
    """API keys and tokens sourced from the environment / ``.env``.

    A missing value simply disables the corresponding source or feature; Kaalyx never
    crashes because a key is absent. Booleans below let callers check availability
    without leaking the raw values around the codebase.
    """

    shodan_api_key: str | None = None
    censys_api_id: str | None = None
    censys_api_secret: str | None = None
    chaos_api_key: str | None = None
    github_token: str | None = None
    ipinfo_token: str | None = None
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None

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
        return bool(self.github_token)

    @property
    def has_ipinfo(self) -> bool:
        return bool(self.ipinfo_token)

    @property
    def has_telegram(self) -> bool:
        return bool(self.telegram_bot_token and self.telegram_chat_id)


def load_secrets(env_path: str | Path | None = None) -> Secrets:
    """Load secrets from a ``.env`` file (if present) plus the process environment.

    Values already set in the environment take precedence over the ``.env`` file, which
    is the conventional ``python-dotenv`` behaviour and lets CI / shell exports override.
    """
    load_dotenv(dotenv_path=env_path, override=False)

    def _get(name: str) -> str | None:
        value = os.environ.get(name)
        return value.strip() if value and value.strip() else None

    return Secrets(
        shodan_api_key=_get("SHODAN_API_KEY"),
        censys_api_id=_get("CENSYS_API_ID"),
        censys_api_secret=_get("CENSYS_API_SECRET"),
        chaos_api_key=_get("CHAOS_API_KEY"),
        github_token=_get("GITHUB_TOKEN"),
        ipinfo_token=_get("IPINFO_TOKEN"),
        telegram_bot_token=_get("TELEGRAM_BOT_TOKEN"),
        telegram_chat_id=_get("TELEGRAM_CHAT_ID"),
    )
