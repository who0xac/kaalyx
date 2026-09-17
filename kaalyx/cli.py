"""Kaalyx command-line interface (Typer).

Commands:

* ``kaalyx scan <target>``    — run the pipeline against a domain/subdomain.
* ``kaalyx resume <target>``  — resume the last interrupted scan for a target.
* ``kaalyx tools``            — pre-flight: show which external tools are on PATH.
* ``kaalyx web``              — launch the local dashboard (implemented later).

Flag precedence: CLI > config.yaml > built-in defaults. The opt-in scan behaviours
(``--full-nmap`` etc.) default to *off* and are surfaced here as boolean flags.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.table import Table

from . import __version__
from .config import load_config, load_secrets
from .core.context import ScanOptions
from .core.logging import get_console, get_logger, setup_logging
from .core.orchestrator import Orchestrator
from .core.target import TargetType, parse_target
from .core import tools as tool_registry
from .stages import make_factory
from .stages.osint import OsintStage

app = typer.Typer(
    add_completion=False,
    rich_markup_mode="rich",
    # Accept both -h and --help at the root AND on every subcommand. Typer/Click use each
    # command's own context_settings for its help option, so this is set here on the app
    # (which the root group uses) and again on each @app.command via _HELP_CTX below.
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "[green]Kaalyx — automated bug-bounty recon & vulnerability-discovery pipeline.[/]\n\n"
        "[green]Run [bold]kaalyx scan <domain>[/bold] to start, and [bold]kaalyx tools[/bold] "
        "to check or install the external tools it drives.[/]"
    ),
)
console = get_console()
logger = get_logger("cli")

# Every subcommand gets this so `-h` works identically to `--help` at every level
# (Click does not propagate the group's help_option_names to subcommands).
_HELP_CTX = {"help_option_names": ["-h", "--help"]}


def _version_callback(value: bool) -> None:
    if value:
        # Include the installed commit SHA: the version string is static (1.0.0 for every
        # commit), so the SHA is the ONLY way to tell which build is actually running — the
        # quickest check for a stale install without running a full scan.
        from .core.updater import installed_commit
        sha = None
        try:
            sha = installed_commit(timeout=2.0)
        except Exception:
            sha = None
        console.print(f"Kaalyx {__version__}" + (f" ({sha})" if sha else ""))
        raise typer.Exit()


# Kaalyx --help: a Usage line, flags grouped into labelled sections,
# then a USAGE EXAMPLES block. Colours follow Kaalyx's palette — section headers bold cyan,
# flag names bold yellow, descriptions dim, example commands bold vs. their dim comments.
_HELP_SECTIONS: list[tuple[str, list[tuple[str, str]]]] = [
    ("TARGET OPTIONS", [
        ("-t, --target <domain>", "Single domain to scan (apex or subdomain)."),
        ("-l, --target-list <file>", "File of domains, one per line; scanned in sequence."),
        ("    <domain>", "Positional shortcut for -t (one target)."),
    ]),
    ("SCAN MODE OPTIONS", [
        ("-o, --osint-only", "Run OSINT only (standalone)."),
        ("-f, --full", "Subdomains → Hosts → Web → Vuln (the default chain)."),
        ("-n, --no-vuln", "Full chain but stop before Vuln."),
        ("-a, --all", "Everything: OSINT + the full chain."),
    ]),
    ("OSINT SELECTION", [
        ("-O, --only-osint a,b,c", "Run ONLY these OSINT sources."),
        ("-K, --skip-osint a,b,c", "Skip these OSINT sources (see 'kaalyx osint-sources')."),
    ]),
    ("SCAN TWEAKS", [
        ("-S, --as-subdomain", "Force-treat the target as a subdomain (skip sub-enum)."),
        ("-A, --as-apex", "Force-treat the target as an apex domain."),
        ("-M, --full-nmap", "Deep nmap -p- -A -O scan (auto-skips CDN IPs)."),
        ("-N, --notify", "Send Telegram alerts (needs config.env credentials)."),
        ("-d, --dashboard", "Launch the local web dashboard after the scan."),
        ("-r, --report", "Generate a consolidated final report file."),
    ]),
    ("GENERAL OPTIONS", [
        ("-c, --config <file>", "Path to a config.yaml (default: ./config.yaml)."),
        ("-vv, --verbose", "Debug-level logging to console + file."),
        ("-R, --resume", "Resume this target's last scan from its checkpoint."),
        ("-h, --help", "Show this help and exit."),
        ("-v, --version", "Show version and exit."),
        ("-u, --update", "Update Kaalyx from GitHub (add -vv for detail)."),
    ]),
    ("COMMANDS", [
        ("scan <domain>", "Run a recon scan against a target."),
        ("resume <domain>", "Resume an interrupted scan from its checkpoint."),
        ("tools", "Check (--check) or install (--install) external tools."),
        ("config --path", "Show where config.yaml and config.env live."),
        ("web", "Launch the local web dashboard."),
        ("update", "Update Kaalyx to the latest version."),
        ("changelog", "Show recent Kaalyx changes."),
    ]),
]

# (command, explanatory comment) example pairs for the USAGE EXAMPLES block.
_HELP_EXAMPLES: list[tuple[str, str]] = [
    ("kaalyx scan example.com", "full default chain against one target"),
    ("kaalyx scan example.com --osint-only", "OSINT only, nothing else"),
    ("kaalyx scan example.com --all", "OSINT + Subdomains → Hosts → Web → Vuln"),
    ("kaalyx scan example.com --only-osint whois,dns,mail_dns,m365", "a subset of OSINT sources"),
    ("kaalyx scan -l targets.txt --no-vuln", "many targets, stop before the Vuln stage"),
    ("kaalyx tools --check", "see which external tools are installed vs. missing"),
]


def _render_help() -> None:
    """Render the grouped help (banner is printed separately by run())."""
    console.print(
        "[bold]Usage:[/] [bold white]kaalyx[/] "
        "[bright_cyan]scan[/] [bold yellow]<domain>[/] [dim][OPTIONS][/]   "
        "[dim](or: kaalyx <command> [OPTIONS])[/]\n"
    )
    for header, rows in _HELP_SECTIONS:
        console.print(f"[bold bright_cyan]{header}[/]")
        width = max(len(flag) for flag, _ in rows)
        for flag, desc in rows:
            console.print(f"  [bold yellow]{flag:<{width}}[/]  [dim]{desc}[/]")
        console.print()
    console.print("[bold bright_cyan]USAGE EXAMPLES[/]")
    for cmd, comment in _HELP_EXAMPLES:
        console.print(f"  [bold white]{cmd}[/]")
        console.print(f"      [dim]# {comment}[/]")


def _show_help(ctx: typer.Context) -> None:
    """Print the custom grouped help, then exit. Banner is printed by ``run()``."""
    _render_help()
    raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    _version: bool = typer.Option(
        False, "--version", "-V", "-v", callback=_version_callback, is_eager=True,
        help="Show version and exit.",
    ),
    _update: bool = typer.Option(
        False, "--update", "-u",
        help="Update Kaalyx to the latest version from GitHub and exit.",
    ),
    _verbose: bool = typer.Option(
        False, "--verbose", "-vv",
        help="With -u/--update: show technical detail (commit hashes, pipx output).",
    ),
) -> None:
    """Automated bug-bounty reconnaissance & vulnerability-discovery pipeline.

    Run [bold]kaalyx scan <domain>[/] to start a scan, and [bold]kaalyx tools[/] to check
    or install the external tools it drives.
    """
    # `-u/--update` is handled here (not via an eager callback) so it can read the sibling
    # `-vv/--verbose` flag — an eager callback runs before other options are parsed and so
    # can't see verbose. This makes `kaalyx -u -vv` work and match `kaalyx update -vv`.
    if _update:
        setup_logging()
        _do_update(verbose=_verbose)
        raise typer.Exit()

    # Show the banner + help on a bare `kaalyx` invocation. (`kaalyx --help` is handled by
    # the root help callback below so the banner also appears there.)
    if ctx.invoked_subcommand is None and not ctx.resilient_parsing:
        _show_help(ctx)


# --------------------------------------------------------------------------------------
# Shared option wiring
# --------------------------------------------------------------------------------------


# The four scan modes → which pipeline stages (by name, in order) they run.
# Only OSINT is implemented today; the other names are placeholders so the mode contract
# is real and ready as Parts 2–5 land. `_build_stage_factories` maps names to the stage
# classes that actually exist and silently omits not-yet-built ones.
_MODE_STAGES: dict[str, list[str]] = {
    "osint-only": ["osint"],
    "full":       ["subdomains", "hosts", "web", "vuln"],   # DEFAULT
    "no-vuln":    ["subdomains", "hosts", "web"],
    "all":        ["osint", "subdomains", "hosts", "web", "vuln"],
}

# Stage name → factory, for stages that are implemented. As Parts 2–5 are built, add them
# here; the mode selection above already references them.
_STAGE_REGISTRY = {
    "osint": lambda: make_factory(OsintStage),
    # "subdomains": lambda: make_factory(SubdomainsStage),   # Part 2 (pending)
    # "hosts":      lambda: make_factory(HostsStage),        # Part 3 (pending)
    # "web":        lambda: make_factory(WebStage),          # Part 4 (pending)
    # "vuln":       lambda: make_factory(VulnStage),         # Part 5 (pending)
}


def _build_stage_factories(mode: str) -> tuple[list, list[str]]:
    """Return ``(factories, pending)`` for a scan *mode*.

    ``factories`` are the stage factories that exist for the mode's stage list, in order.
    ``pending`` are the mode's stages that are specced but not yet implemented — surfaced
    to the user so a ``--full`` run today is honest about only OSINT being built so far.
    """
    wanted = _MODE_STAGES[mode]
    factories = [_STAGE_REGISTRY[name]() for name in wanted if name in _STAGE_REGISTRY]
    pending = [name for name in wanted if name not in _STAGE_REGISTRY]
    return factories, pending


def _apply_osint_selection(
    config, only: Optional[str], skip: Optional[str]
) -> None:
    """Apply --only-osint / --skip-osint selections onto config.osint (CLI wins).

    ``only`` disables every OSINT source except those named; ``skip`` disables just the
    named ones. Names are the source keys shown by ``kaalyx osint-sources``. Unknown names
    are reported and ignored rather than silently dropped.
    """
    from .stages.osint import SOURCE_LABELS

    valid = set(SOURCE_LABELS) | {"breach_lookup"}

    def _parse(value: str) -> list[str]:
        return [v.strip() for v in value.split(",") if v.strip()]

    if only:
        names = _parse(only)
        unknown = [n for n in names if n not in valid]
        if unknown:
            console.print(f"[yellow]Ignoring unknown OSINT source(s):[/] {', '.join(unknown)}")
        chosen = {n for n in names if n in valid}
        for src in valid:
            if hasattr(config.osint, src):
                setattr(config.osint, src, src in chosen)
    if skip:
        names = _parse(skip)
        unknown = [n for n in names if n not in valid]
        if unknown:
            console.print(f"[yellow]Ignoring unknown OSINT source(s):[/] {', '.join(unknown)}")
        for src in names:
            if src in valid and hasattr(config.osint, src):
                setattr(config.osint, src, False)


def _load_target_list(path: str) -> list[str]:
    """Read a target-list file: one domain per line, blanks and #-comments ignored."""
    try:
        raw = Path(path).expanduser().read_text(encoding="utf-8")
    except OSError as exc:
        console.print(f"[red]Cannot read target list:[/] {exc}")
        raise typer.Exit(code=2)
    targets = []
    for line in raw.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            targets.append(line)
    if not targets:
        console.print(f"[red]Target list is empty:[/] {path}")
        raise typer.Exit(code=2)
    return targets


def _scan_one(
    target_str: str,
    *,
    config,
    secrets,
    mode: str,
    resume: bool,
    options: "ScanOptions",
    notify: bool,
    report: bool,
    force_type,
) -> None:
    """Run the pipeline for a single target (used for both single and list runs)."""
    try:
        target = parse_target(target_str, force_type=force_type)
    except Exception as exc:
        console.print(f"[red]Invalid target '{target_str}':[/] {exc}")
        return  # in a list run, skip this one and keep going

    factories, pending = _build_stage_factories(mode)
    if not factories:
        # The selected mode's stages aren't built yet (e.g. explicit --full today). Point
        # the user at what actually works instead of leaving them stuck.
        console.print(
            "[yellow]Only the OSINT stage is currently implemented.[/] Run:\n"
            f"  [bold cyan]kaalyx scan {target.domain} --osint-only[/]"
        )
        return
    if pending:
        console.print(
            f"[dim]Skipping stages not implemented yet: {', '.join(pending)}.[/]"
        )

    orchestrator = Orchestrator(target, options, config, secrets, factories)
    try:
        scan_report = asyncio.run(orchestrator.run(resume=resume))
    finally:
        orchestrator.close()

    console.print(
        f"\n[bold]Scan #{scan_report.scan_id} {scan_report.status}[/] for {scan_report.domain}."
    )

    # Opt-in consolidated report, separate from the always-on raw per-stage output.
    if report:
        console.print(
            "[cyan]--report[/]: consolidated report generation is not available yet; "
            "per-stage raw output and the SQLite database are already written."
        )


def _run_scan(
    target_str: Optional[str],
    *,
    config_path: Optional[str],
    verbose: bool,
    resume: bool,
    mode: str = "full",
    target_list: Optional[str] = None,
    notify: bool = False,
    dashboard: bool = False,
    report: bool = False,
    full_nmap: bool = False,
    brutespray: bool = False,
    ipv6: bool = False,
    sqlmap: bool = False,
    as_subdomain: bool = False,
    as_apex: bool = False,
    only_osint: Optional[str] = None,
    skip_osint: Optional[str] = None,
) -> None:
    import logging

    setup_logging(logging.DEBUG if verbose else logging.INFO)
    # First-run bootstrap: create ~/.config/kaalyx/{config.yaml,config.env} templates if missing,
    # so a fresh pipx install has a config location without the user creating folders.
    from .config import ensure_config_dir

    _, created = ensure_config_dir()
    if created:
        from .config import config_dir
        console.print(
            f"[dim]First run: created config templates in {config_dir()} "
            "— edit config.env there to add API keys. See 'kaalyx config --path'.[/]"
        )
    config = load_config(config_path)
    secrets = load_secrets()
    _apply_osint_selection(config, only_osint, skip_osint)

    # Opt-in Telegram: --notify turns it on; it still needs config.env credentials to actually
    # send (the notifier no-ops without them). Absent the flag, force it off.
    config.telegram.enabled = bool(notify)
    if notify and not secrets.has_telegram:
        console.print(
            "[yellow]--notify set but TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID missing in config.env "
            "— notifications will be skipped.[/]"
        )

    force_type = None
    if as_subdomain:
        force_type = TargetType.SUBDOMAIN
    elif as_apex:
        force_type = TargetType.APEX

    options = ScanOptions(
        full_nmap=full_nmap or config.scan.full_nmap,
        brutespray=brutespray or config.scan.brutespray,
        ipv6=ipv6 or config.scan.ipv6,
        sqlmap=sqlmap or config.scan.sqlmap,
    )

    # Assemble the target list: --target-list file, else the single target/positional.
    if target_list:
        targets = _load_target_list(target_list)
    elif target_str:
        targets = [target_str]
    else:
        console.print("[red]No target given.[/] Provide a domain, -t/--target, or -l/--target-list.")
        raise typer.Exit(code=2)

    # Targets are processed SEQUENTIALLY. Each scan already saturates the box via the
    # per-scan concurrency semaphore + adaptive rate-limiter; running whole pipelines in
    # parallel would multiply subprocess/DNS/HTTP load past those per-scan limits and
    # break the rate-limiter (which is scoped to one scan). Sequential = predictable load
    # and each target gets full resources.
    multi = len(targets) > 1
    try:
        for idx, tgt in enumerate(targets, 1):
            if multi:
                console.rule(f"[bold cyan]Target {idx}/{len(targets)}: {tgt}[/]")
            _scan_one(
                tgt, config=config, secrets=secrets, mode=mode, resume=resume,
                options=options, notify=notify, report=report, force_type=force_type,
            )
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted — progress checkpointed; use `kaalyx resume`.[/]")
        raise typer.Exit(code=130)

    # Opt-in dashboard, launched after scanning completes (a separate viewer, not part
    # of the scan itself).
    if dashboard:
        console.print(
            "[cyan]--dashboard[/]: the web dashboard is not available yet; "
            "results are already in the SQLite database under the output directory."
        )


@app.command(context_settings=_HELP_CTX, short_help="Run a recon scan against a target.")
def scan(
    positional_target: Optional[str] = typer.Argument(
        None, metavar="[TARGET]",
        help="Domain to scan (shortcut for -t/--target). One positional arg = one target.",
    ),
    # --- Target ---
    target: Optional[str] = typer.Option(
        None, "--target", "-t", metavar="DOMAIN",
        help="Single domain to scan (apex or subdomain).",
        rich_help_panel="Target",
    ),
    target_list: Optional[str] = typer.Option(
        None, "--target-list", "-l", metavar="FILE",
        help="File of domains (one per line); each is scanned in sequence.",
        rich_help_panel="Target",
    ),
    # --- Scan mode (mutually exclusive; default = full chain) ---
    osint_only: bool = typer.Option(
        False, "--osint-only", "-o",
        help="Run OSINT only (standalone).",
        rich_help_panel="Scan mode (default: --full)",
    ),
    full: bool = typer.Option(
        False, "--full", "-f",
        help="Subdomains → Hosts → Web → Vuln (the default chain).",
        rich_help_panel="Scan mode (default: --full)",
    ),
    no_vuln: bool = typer.Option(
        False, "--no-vuln", "-n",
        help="Full chain but stop before Vuln (Subdomains → Hosts → Web).",
        rich_help_panel="Scan mode (default: --full)",
    ),
    all_stages: bool = typer.Option(
        False, "--all", "-a",
        help="Everything: OSINT + the full chain.",
        rich_help_panel="Scan mode (default: --full)",
    ),
    # --- Opt-in features ---
    notify: bool = typer.Option(
        False, "--notify", "-N",
        help="Send Telegram notifications (needs config.env credentials).",
        rich_help_panel="Opt-in features",
    ),
    dashboard: bool = typer.Option(
        False, "--dashboard", "-d",
        help="Launch the local web dashboard after the scan.",
        rich_help_panel="Opt-in features",
    ),
    report: bool = typer.Option(
        False, "--report", "-r",
        help="Generate a consolidated final report file.",
        rich_help_panel="Opt-in features",
    ),
    # --- General ---
    config: Optional[str] = typer.Option(
        None, "--config", "-c", metavar="FILE",
        help="Path to a config.yaml (default: ./config.yaml).",
        rich_help_panel="General",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-vv",
        help="Debug-level logging to console + file.",
        rich_help_panel="General",
    ),
    resume: bool = typer.Option(
        False, "--resume", "-R",
        help="Resume this target's last scan from its checkpoint.",
        rich_help_panel="General",
    ),
    # --- Target handling ---
    as_subdomain: bool = typer.Option(
        False, "--as-subdomain", "-S",
        help="Force-treat target as a subdomain (skip subdomain enum).",
        rich_help_panel="Target handling",
    ),
    as_apex: bool = typer.Option(
        False, "--as-apex", "-A",
        help="Force-treat target as an apex domain.",
        rich_help_panel="Target handling",
    ),
    # --- OSINT source selection ---
    only_osint: Optional[str] = typer.Option(
        None, "--only-osint", "-O", metavar="a,b,c",
        help="Run ONLY these OSINT sources (see 'kaalyx osint-sources').",
        rich_help_panel="OSINT selection",
    ),
    skip_osint: Optional[str] = typer.Option(
        None, "--skip-osint", "-K", metavar="a,b,c",
        help="Skip these OSINT sources (see 'kaalyx osint-sources').",
        rich_help_panel="OSINT selection",
    ),
    # --- Opt-in deep scans (off by default) ---
    full_nmap: bool = typer.Option(
        False, "--full-nmap", "-M",
        help="Deep nmap -p- -A -O scan (auto-skips CDN IPs).",
        rich_help_panel="Opt-in deep scans (off by default)",
    ),
    brutespray: bool = typer.Option(
        False, "--brutespray", "-B",
        help="Credential spraying against discovered services.",
        rich_help_panel="Opt-in deep scans (off by default)",
    ),
    ipv6: bool = typer.Option(
        False, "--ipv6", "-6",
        help="Also scan IPv6 targets.",
        rich_help_panel="Opt-in deep scans (off by default)",
    ),
    sqlmap: bool = typer.Option(
        False, "--sqlmap", "-Q",
        help="Run sqlmap for SQLi (nuclei sqli runs regardless).",
        rich_help_panel="Opt-in deep scans (off by default)",
    ),
) -> None:
    """Run the Kaalyx pipeline against a target.

    Give the target as a positional arg, [bold]-t/--target[/], or a file via
    [bold]-l/--target-list[/] (scanned sequentially). Scan modes are mutually exclusive;
    the default is [bold]--full[/] (Subdomains → Hosts → Web → Vuln). Always-on: dual
    SQLite+txt output, severity/confidence tagging, interesting-subdomain flagging,
    adaptive rate-limiting, checkpoint/resume, and scan-history for monitoring.

    [dim]Only Part 1 (OSINT) is implemented so far; other stages report as pending.[/]
    """
    # Resolve the scan mode from the mutually-exclusive mode flags.
    selected_modes = [
        name for name, on in (
            ("osint-only", osint_only), ("full", full), ("no-vuln", no_vuln), ("all", all_stages),
        ) if on
    ]
    if len(selected_modes) > 1:
        console.print(
            f"[red]Scan modes are mutually exclusive[/] — pick one of "
            f"--osint-only / --full / --no-vuln / --all (got: {', '.join(selected_modes)})."
        )
        raise typer.Exit(code=2)
    # Default mode. TODO(parts 2-5): once Subdomains/Hosts/Web/Vuln land, change the
    # no-flag default back to "full". Today only OSINT is implemented, so defaulting to
    # "full" would error on the common no-flag case — default to the one mode that works
    # and tell the user what happened, rather than making them guess a flag.
    default_mode = "osint-only"
    mode = selected_modes[0] if selected_modes else default_mode
    if not selected_modes:
        console.print(
            "[dim]No scan mode given — running [cyan]--osint-only[/] "
            "(the only stage implemented so far). Use --full/--all once more stages land.[/]"
        )

    # Resolve the target source.
    chosen_target = target or positional_target
    if target_list and (chosen_target):
        console.print("[red]Provide either a single target or --target-list, not both.[/]")
        raise typer.Exit(code=2)

    if as_subdomain and as_apex:
        console.print("[red]--as-subdomain and --as-apex are mutually exclusive.[/]")
        raise typer.Exit(code=2)
    if only_osint and skip_osint:
        console.print("[red]--only-osint and --skip-osint are mutually exclusive.[/]")
        raise typer.Exit(code=2)

    _run_scan(
        chosen_target, config_path=config, verbose=verbose, resume=resume,
        mode=mode, target_list=target_list,
        notify=notify, dashboard=dashboard, report=report,
        full_nmap=full_nmap, brutespray=brutespray, ipv6=ipv6, sqlmap=sqlmap,
        as_subdomain=as_subdomain, as_apex=as_apex,
        only_osint=only_osint, skip_osint=skip_osint,
    )


@app.command(context_settings=_HELP_CTX, short_help="Resume an interrupted scan.")
def resume(
    positional_target: Optional[str] = typer.Argument(
        None, metavar="[TARGET]",
        help="Target whose scan to resume (shortcut for -t/--target).",
    ),
    target: Optional[str] = typer.Option(
        None, "--target", "-t", metavar="DOMAIN",
        help="Target whose scan to resume (same as the positional argument).",
    ),
    config: Optional[str] = typer.Option(None, "--config", "-c"),
    verbose: bool = typer.Option(False, "--verbose", "-vv"),
) -> None:
    """Resume the last interrupted scan for a target from its last completed stage.

    Accepts the target as a positional argument or via -t/--target, exactly like `scan`.
    """
    chosen = target or positional_target
    if not chosen:
        console.print("[red]No target given.[/] Provide a domain or use -t/--target.")
        raise typer.Exit(code=2)
    _run_scan(chosen, config_path=config, verbose=verbose, resume=True)


# Per-source metadata for the osint-sources listing: name -> (kind, needs, description).
_OSINT_SOURCE_INFO: dict[str, tuple[str, str, str]] = {
    "whois": ("external", "whois", "Domain registration / registrar / name servers."),
    "dns": ("external", "dnsx", "A/AAAA/CNAME/MX/NS/TXT/SOA DNS records."),
    "mail_dns": ("in-process", "—", "SPF, DMARC, CAA, BIMI, MTA-STS, TLS-RPT posture."),
    "m365": ("in-process", "—", "Microsoft 365 / Entra tenant id, federation, brand."),
    "email_harvest": ("in-process", "—", "Keyless email harvesting (email-format, skymem)."),
    "breach_lookup": ("external", "h8mail + key", "Enrich harvested emails with breach data."),
    "github_subdomains": ("external", "GITHUB_TOKEN", "Subdomains from GitHub code search."),
    "trufflehog": ("external", "GITHUB_TOKEN", "Secret scan of the GitHub org."),
    "cloud_enum": ("external", "cloud_enum", "Multi-cloud resource enumeration."),
    "s3scanner": ("external", "s3scanner", "S3 bucket discovery / exposure."),
    "badsecrets": ("external", "badsecrets", "Known-secret / crypto misconfig detection."),
    "retirejs": ("external", "retire", "Vulnerable JS library detection."),
    "theharvester": ("external", "theHarvester", "Emails, employees (LinkedIn/Twitter), hosts."),
    "third_party_misconfig": ("external", "misconfig-mapper", "Third-party SaaS misconfig checks."),
    "api_leaks": ("external", "porch-pirate/swaggerspy", "Public Postman leaks + exposed Swagger/OpenAPI."),
    "exposed_git": ("in-process", "—", "Detect exposed /.git/config (source-code leak, HIGH)."),
    "github_actions": ("external", "gato + GITHUB_TOKEN (repo/admin:org scope)",
                       "GitHub Actions audit; needs broad token scope for results."),
    "google_dorks": ("in-process", "—", "Generate categorised dork URLs (no scraping)."),
}


@app.command(name="osint-sources", context_settings=_HELP_CTX, hidden=True)
def osint_sources() -> None:
    """List every OSINT sub-check and how to enable/disable it.

    Use the [bold]name[/] values with [bold]--only-osint[/] / [bold]--skip-osint[/] on
    'kaalyx scan', or toggle them in the [bold]osint:[/] section of config.yaml.
    """
    setup_logging()
    table = Table(
        title="Kaalyx OSINT sources", header_style="bold white",
        border_style="cyan", title_style="bold cyan",
    )
    table.add_column("Name", style="bold white")
    table.add_column("Type")
    table.add_column("Needs", style="magenta")
    table.add_column("Description", style="grey70")
    for name, (kind, needs, desc) in _OSINT_SOURCE_INFO.items():
        kind_style = "green" if kind == "in-process" else "cyan"
        table.add_row(name, f"[{kind_style}]{kind}[/]", needs, desc)
    console.print(table)
    console.print(
        "\n[dim]Example:[/] [bold]kaalyx scan example.com --skip-osint trufflehog,cloud_enum[/]"
        "\n[dim]        [/] [bold]kaalyx scan example.com --only-osint whois,dns,mail_dns,m365[/]"
    )


@app.command(context_settings=_HELP_CTX, short_help="Check or install external tools.")
def tools(
    config: Optional[str] = typer.Option(None, "--config", "-c"),
    install: bool = typer.Option(
        False, "--install", "-i",
        help="After reporting, install missing tools via scripts/install.sh.",
    ),
    check_only: bool = typer.Option(
        False, "--check-only",
        help="Report status only and exit (explicit alias for the default).",
    ),
    osint: bool = typer.Option(False, "--osint", help="With --install: OSINT-stage tools only."),
    subdomains: bool = typer.Option(False, "--subdomains", help="With --install: Subdomains-stage tools only."),
    hosts: bool = typer.Option(False, "--hosts", help="With --install: Hosts-stage tools only."),
    web_stage: bool = typer.Option(False, "--web", help="With --install: Web-stage tools only."),
    vuln: bool = typer.Option(False, "--vuln", help="With --install: Vuln-stage tools only."),
    verbose: bool = typer.Option(
        False, "--verbose", "-vv",
        help="With --install: show the underlying tools' raw output (apt/rustup/nuclei).",
    ),
) -> None:
    """Report which external tools are on PATH, and optionally install the missing ones.

    [bold]kaalyx tools[/]                    report status (default).
    [bold]kaalyx tools --check-only[/]       same as default, stated explicitly.
    [bold]kaalyx tools --install[/]          report, then install everything missing.
    [bold]kaalyx tools --install --osint[/]  install only the OSINT-stage tools.

    Installation is delegated to [bold]scripts/install.sh[/] (apt/pacman; Linux/Kali/Arch),
    so there is one source of truth for how each tool is installed.
    """
    setup_logging()
    load_config(config)  # validate the config file even though its values aren't used here

    # Which stage to (optionally) install. Multiple stage flags are not combined — pick one.
    stage_flags = [
        ("osint", osint), ("subdomains", subdomains), ("hosts", hosts),
        ("web", web_stage), ("vuln", vuln),
    ]
    selected = [name for name, on in stage_flags if on]
    if len(selected) > 1:
        console.print(
            f"[red]Pick a single stage for --install[/] (got: {', '.join(selected)})."
        )
        raise typer.Exit(code=2)
    stage = selected[0] if selected else "all"

    # Status-check paths (default, or --check-only) print the availability table. The
    # --install path goes STRAIGHT to install.sh — its own banner + phased, counted output
    # already shows what is installed/skipped/failed, so a leading table would just be a
    # redundant second block stacked above it.
    if not install:
        _report_tool_status(stage if selected else None)
        missing = [s.key for s in tool_registry.missing_tools()]
        if not missing:
            console.print("[green]All registered tools are available.[/]")
            return
        console.print(
            f"[yellow]{len(missing)} tool(s) not found on PATH:[/] {', '.join(missing)}"
        )
        console.print(
            "Kaalyx skips missing tools gracefully. Run [bold]kaalyx tools --install[/] "
            "to install them (or [bold]--install --osint[/] for just one stage)."
        )
        return

    # --install: delegate to scripts/install.sh for the chosen stage (no leading table).
    from .core import installer

    # install.sh prints its own banner, staged output, and Finished! line — don't echo a
    # duplicate success line here. Only surface a non-zero exit as an error.
    code = installer.run_install(stage, verbose=verbose)
    if code != 0:
        console.print(
            f"[yellow]Installer exited with code {code}.[/] "
            "See the messages above; you can also run scripts/install.sh manually."
        )
        raise typer.Exit(code=code)


def _report_tool_status(stage: Optional[str]) -> None:
    """Print the tool-availability table, optionally filtered to one pipeline stage."""
    report = tool_registry.availability_report()
    title = "Kaalyx external tool availability"
    if stage:
        title += f"  ({stage} stage)"
    table = Table(title=title)
    table.add_column("Tool", style="cyan")
    table.add_column("Part")
    table.add_column("On PATH")
    table.add_column("Needs key")
    for key, available in sorted(report.items()):
        spec = tool_registry.get(key)
        assert spec is not None
        if stage and spec.part.value != stage:
            continue
        status = "[green]yes[/]" if available else "[red]no[/]"
        table.add_row(key, spec.part.value, status, spec.requires_secret or "")
    console.print(table)


@app.command(context_settings=_HELP_CTX, short_help="Launch the local web dashboard.")
def web(
    config: Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Launch the local web dashboard (implemented in a later build step)."""
    console.print(
        "[yellow]The web dashboard is not implemented yet.[/] "
        "It will serve the SQLite results at the configured host/port."
    )
    raise typer.Exit(code=1)


# Friendly secret-name -> env var mapping for `kaalyx config --check-key <name>`.
_CHECK_KEY_ALIASES = {
    "shodan": "SHODAN_API_KEY",
    "github": "GITHUB_TOKEN",
    "ipinfo": "IPINFO_TOKEN",
    "censys": "CENSYS_API_ID",
    "chaos": "CHAOS_API_KEY",
    "telegram": "TELEGRAM_BOT_TOKEN",
}


def _mask(value: str) -> str:
    """Mask a secret for display: keep first/last 3 chars, hide the middle."""
    v = value.strip()
    if len(v) <= 8:
        return "•" * len(v)
    return f"{v[:3]}…{v[-3:]} (len={len(v)})"


def _check_key(name: str) -> None:
    """Standalone diagnostic for one secret: trace EXACTLY where the key is looked for and what
    is found, independent of running a scan. Prints the resolved config.env path, whether the
    file exists, whether the key line is present in the file (masked), the os.environ state, and
    the FINAL value load_secrets() resolves — so a stale/empty/wrong-dir config.env is obvious."""
    import os
    from .config import resolve_env_path, load_secrets
    from dotenv import dotenv_values

    env_name = _CHECK_KEY_ALIASES.get(name.strip().lower(), name.strip().upper())
    console.print(f"[bold]Secret check:[/] {env_name}\n")

    # 1) Which file does resolution pick (CWD ./config.env wins over the config dir)?
    resolved = resolve_env_path()
    console.print(f"  cwd                 : {Path.cwd()}")
    console.print(f"  resolved config.env : "
                  + (f"{resolved}" if resolved else "[yellow]none found (environment only)[/]"))
    if resolved is not None:
        console.print(f"  file exists         : "
                      + ("[green]yes[/]" if Path(resolved).is_file() else "[red]no[/]"))
        # 2) Is the key line present IN THAT FILE, and what's its value (masked)?
        try:
            fv = dotenv_values(str(resolved)).get(env_name)
        except Exception as exc:  # noqa: BLE001
            fv = None
            console.print(f"  [red]file parse error[/] : {exc}")
        if fv is None:
            console.print(f"  key line in file    : [yellow]absent[/]")
        elif not fv.strip():
            console.print(f"  key line in file    : [yellow]present but BLANK[/]")
        else:
            console.print(f"  key line in file    : [green]present[/] → {_mask(fv)}")
        # RAW line(s) as they literally appear in the file, with the value masked — this exposes
        # a content difference between one key's line and another's (inline comment, stray
        # character, wrong separator) that parsing might silently mishandle.
        try:
            raw_lines = Path(resolved).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            raw_lines = []
        hits = [ln for ln in raw_lines if ln.strip().lstrip("export").strip().startswith(env_name)]
        if hits:
            console.print("  raw file line(s)    :")
            for ln in hits:
                # Mask everything after the first '=' so the secret isn't printed verbatim.
                head, sep, val = ln.partition("=")
                shown = f"{head}{sep}{_mask(val) if val.strip() else '[blank]'}" if sep else ln
                console.print(f"    [dim]{shown}[/]")

    # 3) os.environ state (a non-empty export overrides the file; an empty one is ignored).
    env_val = os.environ.get(env_name)
    if env_val is None:
        console.print(f"  {env_name} in env : [dim]unset[/]")
    elif not env_val.strip():
        console.print(f"  {env_name} in env : [yellow]set but EMPTY (ignored — file wins)[/]")
    else:
        console.print(f"  {env_name} in env : [green]set[/] → {_mask(env_val)}")

    # GitHub supports MULTIPLE tokens for rotation (GITHUB_TOKEN, GITHUB_TOKEN_2, _3, …). Show
    # every numbered slot found in the file / env, not just the first, so a rotation setup is
    # verifiable — the single-key trace above only covered GITHUB_TOKEN.
    if env_name == "GITHUB_TOKEN":
        console.print("\n  [bold]GitHub token slots (rotation):[/]")
        file_vals = {}
        if resolved is not None:
            try:
                file_vals = dotenv_values(str(resolved))
            except Exception:  # noqa: BLE001
                file_vals = {}
        for i in range(1, 6):
            slot = "GITHUB_TOKEN" if i == 1 else f"GITHUB_TOKEN_{i}"
            env_v = (os.environ.get(slot) or "").strip()
            file_v = (file_vals.get(slot) or "").strip()
            resolved_v = env_v or file_v
            src = "env" if env_v else ("config.env" if file_v else "")
            if resolved_v:
                console.print(f"    {slot:<16} [green]set[/] → {_mask(resolved_v)}  [dim]({src})[/]")
            elif slot in os.environ or slot in file_vals:
                console.print(f"    {slot:<16} [yellow]present but BLANK[/]")
        # (slots with nothing at all are omitted to keep the list short)

    # 4) The FINAL resolved value load_secrets() produces (what a scan actually uses).
    secrets = load_secrets()
    if env_name == "GITHUB_TOKEN":
        final = secrets.github_tokens[0] if secrets.github_tokens else None
    else:
        attr = _ENV_TO_ATTR.get(env_name)
        final = getattr(secrets, attr, None) if attr else None
    console.print()
    if final:
        if env_name == "GITHUB_TOKEN":
            n = len(secrets.github_tokens)
            console.print(f"  [green]✔ RESOLVED[/] — {n} GitHub token(s) will be used "
                          f"(rotated across requests).")
        else:
            console.print(f"  [green]✔ RESOLVED[/] — the scan WILL use this key ({_mask(final)}).")
    else:
        console.print(f"  [red]✘ NOT RESOLVED[/] — the scan sees NO key; the source will skip.")
        console.print("  [dim]Most common cause: a stale/blank ./config.env in the current "
                      "directory shadowing the real one in the config dir. Run from a dir "
                      "without a local config.env, or fix that file.[/]")


# Map an env-var name to the Secrets attribute holding its resolved value (for --check-key).
_ENV_TO_ATTR = {
    "SHODAN_API_KEY": "shodan_api_key",
    "GITHUB_TOKEN": None,  # token list — handled specially below
    "IPINFO_TOKEN": "ipinfo_token",
    "CENSYS_API_ID": "censys_api_id",
    "CHAOS_API_KEY": "chaos_api_key",
    "TELEGRAM_BOT_TOKEN": "telegram_bot_token",
}


@app.command(context_settings=_HELP_CTX, short_help="Show where config.yaml and config.env live.")
def config(
    path: bool = typer.Option(
        False, "--path", help="Print the exact config.yaml and config.env paths and exit.",
    ),
    check_key: str = typer.Option(
        None, "--check-key",
        help="Diagnose a single secret (e.g. 'shodan', 'github', 'ipinfo'): which config.env "
             "is read, whether the key line is present, and the masked value. Exits after.",
    ),
) -> None:
    """Show (and create) Kaalyx's config directory, config.yaml and config.env locations.

    Running this creates ~/.config/kaalyx/ with template config.yaml and config.env if they
    don't exist yet, so a fresh pipx install can be configured without guessing paths.
    """
    from .config import config_file, env_file, ensure_config_dir

    if check_key is not None:
        _check_key(check_key)
        raise typer.Exit(0)

    directory, created = ensure_config_dir()
    cfg, env = config_file(), env_file()

    console.print(f"[bold]Config directory:[/] {directory}")
    console.print(
        f"  config.yaml : {cfg}  "
        + ("[green](exists)[/]" if cfg.exists() else "[yellow](missing)[/]")
    )
    console.print(
        f"  config.env  : {env}  "
        + ("[green](exists)[/]" if env.exists() else "[yellow](missing)[/]")
    )
    try:
        contents = sorted(p.name for p in directory.iterdir())
        console.print(f"\n[dim]Directory contents: {', '.join(contents)}[/]")
    except OSError:
        pass
    if created:
        console.print(
            f"\n[green]Created {len(created)} template file(s).[/] "
            "Edit them to add your settings and API keys."
        )
    console.print(
        "\n[dim]Lookup order: a --config path > ./config.yaml (in the current dir) > "
        "the config directory above. A local ./config.env also takes precedence over the one here.[/]"
    )


def _run_while_advancing(progress, task, fn, start_pct: int, ceiling_pct: int):
    """Run blocking *fn* in a thread while the dot-bar creeps from start toward a ceiling.

    The bar advances a little at a time while the work runs but never passes
    ``ceiling_pct`` — the caller decides the final value based on whether the step actually
    succeeded, so a failed step never fills the bar to 100%. Returns *fn*'s result.
    """
    import threading
    import time

    result: dict = {}

    def _worker():
        result["value"] = fn()

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()

    pct = float(start_pct)
    ceiling = max(start_pct, ceiling_pct - 1)
    while thread.is_alive():
        if pct < ceiling:
            pct += max(0.5, (ceiling - pct) * 0.08)  # ease-out toward the ceiling
            progress.update(task, completed=min(pct, ceiling))
        time.sleep(0.1)
    thread.join()
    return result.get("value")


# Conventional-commit prefix -> (nuclei-style tag, rich style). A message with no known
# prefix becomes an [INF] line with the raw text.
_COMMIT_TAGS: dict[str, tuple[str, str]] = {
    "fix":      ("FIX", "yellow"),
    "feat":     ("NEW", "green"),
    "chore":    ("CHG", "dim cyan"),
    "refactor": ("CHG", "dim cyan"),
    "docs":     ("CHG", "dim cyan"),
}
_TAG_STYLE = {"INF": "cyan", "FIX": "yellow", "NEW": "green", "CHG": "dim cyan"}


def _tag_for_commit(subject: str) -> tuple[str, str, str]:
    """Map a commit subject to ``(tag, style, cleaned_message)``.

    ``fix:`` → FIX, ``feat:`` → NEW, ``chore:``/``refactor:``/``docs:`` → CHG (prefix stripped);
    anything unprefixed → INF with the raw message.
    """
    head, sep, rest = subject.partition(":")
    key = head.strip().lower()
    # Drop a conventional-commit scope like "feat(cli)" -> "feat".
    key = key.split("(", 1)[0]
    if sep and key in _COMMIT_TAGS:
        tag, style = _COMMIT_TAGS[key]
        return tag, style, rest.strip()
    return "INF", _TAG_STYLE["INF"], subject.strip()


def _render_update_changelog(old_ref: str, new_ref: str, commits: list[tuple[str, str]]) -> None:
    """Print the update summary in the locked nuclei-style tagged format — SAME layout whether
    the update carried one commit or many, so the result is consistent every time::

        [INF] kaalyx updated  <old> → <new> · N commit(s)

          [FIX] <message>        (fix=yellow, feat/new=green, chore/refactor/docs=dim cyan)
          ...

        [INF] run 'kaalyx changelog' anytime · full history: github.com/who0xac/kaalyx/commits/main

    Each commit becomes one tagged line via _tag_for_commit (conventional-commit prefix stripped
    and mapped to [FIX]/[NEW]/[CHG], or [INF] for an unprefixed subject). When the commit list
    couldn't be fetched, the header still prints with the ref range.
    """
    n = len(commits)
    plural = "commit" if n == 1 else "commits"
    console.print(
        f"[cyan]\\[INF][/] kaalyx updated  [bold]{old_ref}[/] → [bold]{new_ref}[/] "
        f"· [bold]{n}[/] {plural}"
    )
    if commits:
        console.print()
        for _sha, subject in commits:
            tag, style, msg = _tag_for_commit(subject)
            console.print(f"  [{style}]\\[{tag}][/] {msg}")
    console.print()
    console.print(
        "[cyan]\\[INF][/] run [bold]kaalyx changelog[/] anytime · "
        "full history: [dim]github.com/who0xac/kaalyx/commits/main[/]"
    )


def _do_update(verbose: bool = False) -> None:
    """Check GitHub for a newer Kaalyx and, if found, reinstall via pipx.

    Shows a dot-style progress bar mapped to real milestones (check → prepare → pull →
    reinstall → done). Ends with one clear line — "already up to date" or "updated: old →
    new". Internals (commit hashes, pipx output) are shown only with --verbose. Shared by
    `kaalyx update` and the root `-u/--update` flag.
    """
    from .core import updater
    from .ui import dot_progress

    current = updater.current_version()

    def _network_message() -> None:
        console.print(
            "[yellow]⚠ Couldn't reach GitHub to check for updates[/] (no network or DNS "
            "issue). Try again when you have a connection."
        )

    # --- Step 1: check reachability + latest commit (bar fills while the API call runs). ---
    with dot_progress() as progress:
        task = progress.add_task("Checking for updates", total=100)

        latest = _run_while_advancing(
            progress, task, updater.latest_remote_commit, 0, 20
        )
        local_sha = updater.installed_commit()

        # No response from GitHub's API => network/DNS problem. Clear message, by default.
        # (Leave the bar where it stopped — do not fill it.)
        if latest is None:
            progress.stop()
            if verbose:
                console.print("[dim]GitHub commits API returned no result (see logs).[/]")
            _network_message()
            raise typer.Exit(code=1)

        progress.update(task, completed=20)  # check succeeded
        remote_sha, remote_full, remote_date = latest

        # Already up to date (provable only when we know the installed commit) => skip the
        # reinstall entirely. local_sha comes from what is *genuinely* installed (package
        # metadata / git HEAD), not merely from a prior recorded intention.
        if local_sha and local_sha == remote_sha:
            progress.stop()
            if verbose:
                console.print(f"[dim]installed commit: {local_sha} == latest {remote_sha}[/]")
            console.print(f"[green]✔ Already up to date[/] (v{current}, {remote_sha})")
            return

        # --- Step 2/3: upgrade in place (bar fills during the real work). ---
        # Lightweight-first internally (upgrade inside the existing pipx venv, full rebuild only
        # as a fallback) — but this mechanism detail is NOT shown to the user; the update simply
        # works or reports failure.
        # Pin the install to the exact remote commit so pip cannot serve a cached build.
        progress.update(task, description="Update found, preparing", completed=40)
        progress.update(task, description="Pulling latest changes", completed=45)
        progress.update(task, description="Reinstalling via pipx")
        code, output = _run_while_advancing(
            progress, task,
            lambda: updater.reinstall_from_repo(ref=remote_full, capture=True), 45, 100
        )
        # Fill to 100% only on genuine success; on failure leave it partial so the dots
        # never imply a completed update.
        if code == 0:
            progress.update(task, description="Done", completed=100)
        else:
            progress.stop()

    if verbose:
        console.print(f"[dim]installed commit: {local_sha or 'unknown (not a git checkout)'}[/]")
        console.print(f"[dim]latest commit   : {remote_sha}"
                      + (f"  ({remote_date})" if remote_date else "") + "[/]")
        if output:
            console.print(f"[dim]{output.strip()}[/]")

    # --- Failure handling: distinguish a network problem from a genuine failure. ---
    if code != 0:
        if updater.is_network_error(output):
            _network_message()
        else:
            console.print(
                f"[yellow]⚠ Update failed[/] (exit {code})."
                + ("" if verbose else " Run [bold]kaalyx update -vv[/] for details.")
            )
        raise typer.Exit(code=code)

    # --- Success is claimed ONLY when the commit now on disk is verifiably the remote one. ---
    # We do NOT trust pipx's exit code as proof: pip can exit 0 having served a cached build,
    # leaving old code in place. Read the commit pip actually pinned into the package's PEP
    # 610 metadata and require it to match the remote before recording state or reporting success.
    new_version = updater.installed_version_via_pipx()
    installed_now = updater.short_sha(updater.commit_from_package_metadata())

    if new_version is None:
        # pipx returned 0 but we can't confirm the install — do not claim success.
        console.print(
            "[yellow]⚠ Update finished but couldn't be verified.[/] "
            "Run [bold]kaalyx --version[/] to check."
        )
        raise typer.Exit(code=1)

    if verbose:
        console.print(f"[dim]commit on disk after install: {installed_now or 'unknown'}[/]")

    if installed_now is not None and installed_now != remote_sha:
        # The bytes on disk are NOT the remote commit — a genuine failure to update (stale
        # cache, or pipx installed something else). Never record a commit we didn't install.
        console.print(
            f"[yellow]⚠ Update did not take effect[/] — still on {installed_now}, "
            f"expected {remote_sha}."
            + ("" if verbose else " Run [bold]kaalyx update -vv[/] for details.")
        )
        raise typer.Exit(code=1)

    # Record the commit we just installed so the next run can tell "already up to date" from
    # a genuine update (a pipx install has no .git to read a HEAD from). Prefer the verified
    # on-disk commit; fall back to the remote full SHA if metadata was unreadable.
    updater.write_installed_commit(installed_now or remote_full)

    # Nuclei-style bracketed-tag changelog, matching the visual language of the tools Kaalyx
    # drives. Headline + one tagged line per commit, no borders.
    old_ref = local_sha or f"v{current}"
    new_ref = remote_sha
    commits = updater.commits_between(local_sha, remote_full)
    _render_update_changelog(old_ref, new_ref, commits)


@app.command(context_settings=_HELP_CTX, short_help="Update Kaalyx to the latest version.")
def update(
    verbose: bool = typer.Option(
        False, "--verbose", "-vv",
        help="Show technical detail (commit hashes, pipx output).",
    ),
) -> None:
    """Update Kaalyx to the latest version from GitHub (reinstalls via pipx)."""
    setup_logging()
    _do_update(verbose=verbose)


@app.command(context_settings=_HELP_CTX, short_help="Show recent Kaalyx changes.")
def changelog(
    limit: int = typer.Option(20, "--limit", "-n", help="How many recent commits to show."),
) -> None:
    """Show recent Kaalyx changes as nuclei-style tagged lines (newest first)."""
    setup_logging()
    from .core import updater

    commits = updater.recent_commits(limit=limit)
    if not commits:
        console.print(
            "[yellow]\\[INF][/] couldn't fetch the changelog — "
            "see [dim]github.com/who0xac/kaalyx/commits/main[/]"
        )
        raise typer.Exit(code=1)
    for _sha, subject in commits:
        tag, style, msg = _tag_for_commit(subject)
        console.print(f"[{style}]\\[{tag}][/] {msg}")
    console.print()
    console.print(
        "[cyan]\\[INF][/] full history: "
        "[dim]github.com/who0xac/kaalyx/commits/main[/]"
    )


def run() -> None:
    """Console-script entry point.

    Prints the banner ahead of the top-level help screen (``kaalyx``, ``kaalyx -h`` or
    ``kaalyx --help`` with no subcommand), then delegates to the Typer app. Subcommand
    help (e.g. ``kaalyx scan --help``) is left to Typer/Click untouched.
    """
    import sys

    argv = sys.argv[1:]
    root_help = not argv or all(a in ("-h", "--help") for a in argv)
    if root_help:
        # Root help (bare `kaalyx`, `kaalyx -h`, `kaalyx --help`): banner + our custom
        # custom grouped help, then exit — bypassing Typer's default box help so the
        # two never both print. Subcommand help (e.g. `kaalyx scan --help`) still goes to Typer.
        from .ui import print_main_banner

        print_main_banner()
        console.print()
        _render_help()
        return
    app()


if __name__ == "__main__":
    run()
