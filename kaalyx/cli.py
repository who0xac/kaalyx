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
        "[bold cyan]Kaalyx[/] — automated bug-bounty recon & vulnerability-discovery pipeline.\n\n"
        "Run [bold]kaalyx scan <domain>[/] to start, and [bold]kaalyx tools[/] to check or "
        "install the external tools it drives."
    ),
)
console = get_console()
logger = get_logger("cli")

# Every subcommand gets this so `-h` works identically to `--help` at every level
# (Click does not propagate the group's help_option_names to subcommands).
_HELP_CTX = {"help_option_names": ["-h", "--help"]}


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"Kaalyx {__version__}")
        raise typer.Exit()


def _update_callback(value: bool) -> None:
    if value:
        setup_logging()
        _do_update()
        raise typer.Exit()


def _print_quickstart() -> None:
    """Print the quick-start block shown at the top of root help / bare invocation.

    This is the first thing a new user sees after the banner: exactly what to type given
    what actually works today (OSINT only), so nobody has to guess.
    """
    from rich.panel import Panel
    from rich.text import Text

    body = Text()
    rows = [
        ("kaalyx scan <domain>", "Run an OSINT recon scan on a target"),
        ("kaalyx tools", "Check which external tools are installed"),
        ("kaalyx tools --install", "Install any missing tools"),
        ("kaalyx update", "Update Kaalyx to the latest version"),
    ]
    for i, (cmd, desc) in enumerate(rows):
        if i:
            body.append("\n")
        body.append(f"  {cmd:<28}", style="bold cyan")
        body.append(desc, style="white")
    body.append("\n\n")
    body.append(
        "Only the OSINT phase is implemented so far — other phases are in progress.",
        style="yellow",
    )
    console.print(
        Panel(body, title="[bold]Quick start[/]", title_align="left",
              border_style="cyan", padding=(0, 1))
    )


# Command reference shown in the main help: each command's one-line summary plus its key
# flags with short descriptions, so a new user sees the essentials without running each
# subcommand's own -h (which remains the full reference). Grouped like Typer's panels.
_COMMAND_REFERENCE: list[tuple[str, list[tuple[str, str, str]]]] = [
    ("Pipeline", [
        ("scan", "Run the Kaalyx pipeline against a target.", ""),
        ("", "", "--osint-only        OSINT phase only"),
        ("", "", "--no-vuln           Run up to Web Analysis, skip Vuln"),
        ("", "", "--all               Everything, including OSINT"),
        ("", "", "-t, --target        Single domain"),
        ("", "", "-l, --target-list   File with multiple domains"),
    ]),
    ("Info", [
        ("tools", "Check which external tools are installed.", ""),
        ("", "", "-i, --install       Install missing tools"),
        ("", "", "--check-only        Report only (no install)"),
        ("update", "Update Kaalyx to the latest version from GitHub.", ""),
        ("", "", "-vv, --verbose      Show technical detail"),
    ]),
]


def _print_command_reference() -> None:
    """Print the custom, flag-aware command reference panels for the main help screen.

    Each command's flags are shown under a ``kaalyx <cmd> [FLAGS]`` usage line and indented,
    so it is unmistakable the flags belong to that command — you type them AFTER the command
    name, they are not standalone options on bare ``kaalyx``.
    """
    from rich.panel import Panel
    from rich.text import Text

    for title, entries in _COMMAND_REFERENCE:
        lines: list[Text] = []
        for name, summary, flag_line in entries:
            if name:  # a command header row: "kaalyx <cmd>   <summary>"
                if lines:
                    lines.append(Text(""))  # blank line between commands
                row = Text("kaalyx ", style="dim")
                row.append(f"{name}", style="bold cyan")
                row.append("   " + summary, style="white")
                lines.append(row)
            else:      # a flag row, indented under its command
                lines.append(Text(f"    {flag_line}", style="dim"))
        body = Text("\n").join(lines)
        console.print(
            Panel(body, title=f"[bold]{title}[/]", title_align="left",
                  subtitle="[dim]flags go after the command name[/]", subtitle_align="right",
                  border_style="cyan", padding=(0, 1))
        )


def _show_help(ctx: typer.Context) -> None:
    """Print the standard help, then exit. The banner + quick-start are printed by ``run()``."""
    console.print(ctx.get_help())
    raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    _version: bool = typer.Option(
        False, "--version", "-V", "-v", callback=_version_callback, is_eager=True,
        help="Show version and exit.",
    ),
    _update: bool = typer.Option(
        False, "--update", "-u", callback=_update_callback, is_eager=True,
        help="Update Kaalyx to the latest version from GitHub and exit.",
    ),
) -> None:
    """Automated bug-bounty reconnaissance & vulnerability-discovery pipeline.

    Run [bold]kaalyx scan <domain>[/] to start a scan, and [bold]kaalyx tools[/] to check
    or install the external tools it drives.
    """
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
            "[yellow]Only the OSINT phase is currently implemented.[/] Run:\n"
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
    config = load_config(config_path)
    secrets = load_secrets()
    _apply_osint_selection(config, only_osint, skip_osint)

    # Opt-in Telegram: --notify turns it on; it still needs .env credentials to actually
    # send (the notifier no-ops without them). Absent the flag, force it off.
    config.telegram.enabled = bool(notify)
    if notify and not secrets.has_telegram:
        console.print(
            "[yellow]--notify set but TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID missing in .env "
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


@app.command(rich_help_panel="Pipeline", context_settings=_HELP_CTX, hidden=True)
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
        help="Send Telegram notifications (needs .env credentials).",
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
            "(the only phase implemented so far). Use --full/--all once more phases land.[/]"
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


@app.command(context_settings=_HELP_CTX, hidden=True)
def resume(
    target: str = typer.Argument(..., help="Target of the scan to resume."),
    config: Optional[str] = typer.Option(None, "--config", "-c"),
    verbose: bool = typer.Option(False, "--verbose", "-vv"),
) -> None:
    """Resume the last interrupted scan for TARGET from its last completed stage."""
    _run_scan(target, config_path=config, verbose=verbose, resume=True)


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


@app.command(rich_help_panel="Info", context_settings=_HELP_CTX, hidden=True)
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
    osint: bool = typer.Option(False, "--osint", help="With --install: OSINT-phase tools only."),
    subdomains: bool = typer.Option(False, "--subdomains", help="With --install: Subdomains-phase tools only."),
    hosts: bool = typer.Option(False, "--hosts", help="With --install: Hosts-phase tools only."),
    web_phase: bool = typer.Option(False, "--web", help="With --install: Web-phase tools only."),
    vuln: bool = typer.Option(False, "--vuln", help="With --install: Vuln-phase tools only."),
) -> None:
    """Report which external tools are on PATH, and optionally install the missing ones.

    [bold]kaalyx tools[/]                    report status (default).
    [bold]kaalyx tools --check-only[/]       same as default, stated explicitly.
    [bold]kaalyx tools --install[/]          report, then install everything missing.
    [bold]kaalyx tools --install --osint[/]  install only the OSINT-phase tools.

    Installation is delegated to [bold]scripts/install.sh[/] (apt/pacman; Linux/Kali/Arch),
    so there is one source of truth for how each tool is installed.
    """
    setup_logging()
    load_config(config)  # validate the config file even though its values aren't used here

    # Which phase to (optionally) install. Multiple phase flags are not combined — pick one.
    phase_flags = [
        ("osint", osint), ("subdomains", subdomains), ("hosts", hosts),
        ("web", web_phase), ("vuln", vuln),
    ]
    selected = [name for name, on in phase_flags if on]
    if len(selected) > 1:
        console.print(
            f"[red]Pick a single phase for --install[/] (got: {', '.join(selected)})."
        )
        raise typer.Exit(code=2)
    phase = selected[0] if selected else "all"

    _report_tool_status(phase if selected else None)

    missing = [s.key for s in tool_registry.missing_tools()]
    if not missing:
        console.print("[green]All registered tools are available.[/]")
        return

    if check_only or not install:
        console.print(
            f"[yellow]{len(missing)} tool(s) not found on PATH:[/] {', '.join(missing)}"
        )
        console.print(
            "Kaalyx skips missing tools gracefully. Run [bold]kaalyx tools --install[/] "
            "to install them (or [bold]--install --osint[/] for just one phase)."
        )
        return

    # --install: delegate to scripts/install.sh for the chosen phase.
    from .core import installer

    label = "all phases" if phase == "all" else f"the {phase} phase"
    console.print(f"\n[cyan]Installing missing tools for {label} via scripts/install.sh…[/]")
    code = installer.run_install(phase)
    if code == 0:
        console.print("[green]Installer finished. Re-run 'kaalyx tools' to confirm.[/]")
    else:
        console.print(
            f"[yellow]Installer exited with code {code}.[/] "
            "See the messages above; you can also run scripts/install.sh manually."
        )
        raise typer.Exit(code=code)


def _report_tool_status(phase: Optional[str]) -> None:
    """Print the tool-availability table, optionally filtered to one pipeline phase."""
    report = tool_registry.availability_report()
    title = "Kaalyx external tool availability"
    if phase:
        title += f"  ({phase} phase)"
    table = Table(title=title)
    table.add_column("Tool", style="cyan")
    table.add_column("Part")
    table.add_column("On PATH")
    table.add_column("Needs key")
    for key, available in sorted(report.items()):
        spec = tool_registry.get(key)
        assert spec is not None
        if phase and spec.part.value != phase:
            continue
        status = "[green]yes[/]" if available else "[red]no[/]"
        table.add_row(key, spec.part.value, status, spec.requires_secret or "")
    console.print(table)


@app.command(context_settings=_HELP_CTX, hidden=True)
def web(
    config: Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Launch the local web dashboard (implemented in a later build step)."""
    console.print(
        "[yellow]The web dashboard is not implemented yet.[/] "
        "It will serve the SQLite results at the configured host/port."
    )
    raise typer.Exit(code=1)


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
        remote_sha, remote_date = latest

        # Already up to date (provable only when we know the installed commit) => skip the
        # reinstall entirely.
        if local_sha and local_sha == remote_sha:
            progress.stop()
            if verbose:
                console.print(f"[dim]installed commit: {local_sha} == latest {remote_sha}[/]")
            console.print(f"[green]✔ Already up to date[/] (v{current})")
            return

        # --- Step 2/3: prepare + reinstall via pipx (bar fills during the real reinstall). ---
        progress.update(task, description="Update found, preparing", completed=40)
        progress.update(task, description="Pulling latest changes", completed=45)
        progress.update(task, description="Reinstalling via pipx")
        code, output = _run_while_advancing(
            progress, task, lambda: updater.reinstall_from_repo(capture=True), 45, 100
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
                + ("" if verbose else " Run [bold]kaalyx update --verbose[/] for details.")
            )
        raise typer.Exit(code=code)

    # --- Success is reported ONLY when pipx exited 0 AND the package is verifiably present. ---
    new_version = updater.installed_version_via_pipx()
    if new_version is None:
        # pipx returned 0 but we can't confirm the install — do not claim success.
        console.print(
            "[yellow]⚠ Update finished but couldn't be verified.[/] "
            "Run [bold]kaalyx --version[/] to check."
        )
        raise typer.Exit(code=1)

    if new_version != current:
        console.print(f"[green]✔ Updated to the latest version[/] (v{current} → v{new_version})")
    else:
        console.print(f"[green]✔ Updated to the latest version[/] (v{new_version})")


@app.command(rich_help_panel="Info", context_settings=_HELP_CTX, hidden=True)
def update(
    verbose: bool = typer.Option(
        False, "--verbose", "-vv",
        help="Show technical detail (commit hashes, pipx output).",
    ),
) -> None:
    """Update Kaalyx to the latest version from GitHub (reinstalls via pipx)."""
    setup_logging()
    _do_update(verbose=verbose)


def run() -> None:
    """Console-script entry point.

    Prints the banner ahead of the top-level help screen (``kaalyx``, ``kaalyx -h`` or
    ``kaalyx --help`` with no subcommand), then delegates to the Typer app. Subcommand
    help (e.g. ``kaalyx scan --help``) is left to Typer/Click untouched.
    """
    import sys

    argv = sys.argv[1:]
    root_help = not argv or (
        all(a in ("-h", "--help") for a in argv) and len(argv) >= 1
    )
    if root_help:
        from .ui import print_main_banner

        print_main_banner()
        _print_quickstart()
        _print_command_reference()
    app()


if __name__ == "__main__":
    run()
