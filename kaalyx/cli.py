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
    help=(
        "[bold cyan]Kaalyx[/] — automated bug-bounty recon & vulnerability-discovery pipeline.\n\n"
        "Run [bold]kaalyx scan <domain>[/] to start. Use [bold]kaalyx osint-sources[/] to list "
        "the OSINT sub-checks you can enable/disable, and [bold]kaalyx tools[/] to see which "
        "external tools are installed."
    ),
)
console = get_console()
logger = get_logger("cli")


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"Kaalyx {__version__}")
        raise typer.Exit()


def _show_help(ctx: typer.Context) -> None:
    """Print the standard help, then exit. The banner is printed by ``run()``."""
    console.print(ctx.get_help())
    raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    _version: bool = typer.Option(
        False, "--version", "-V", callback=_version_callback, is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Automated bug-bounty reconnaissance & vulnerability-discovery pipeline.

    Run [bold]kaalyx scan <domain>[/] to start a scan. See [bold]kaalyx osint-sources[/]
    for the OSINT sub-checks and [bold]kaalyx tools[/] for external-tool availability.
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
    if pending:
        console.print(
            f"[yellow]Note:[/] stage(s) not yet implemented, skipped this run: "
            f"{', '.join(pending)}."
        )
    if not factories:
        console.print(
            f"[yellow]Nothing to run for '{target.domain}':[/] the selected mode's "
            f"stages ({', '.join(_MODE_STAGES[mode])}) are not implemented yet."
        )
        return

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


@app.command(rich_help_panel="Pipeline")
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
        False, "--verbose", "-v",
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
    mode = selected_modes[0] if selected_modes else "full"

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


@app.command()
def resume(
    target: str = typer.Argument(..., help="Target of the scan to resume."),
    config: Optional[str] = typer.Option(None, "--config", "-c"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
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


@app.command(name="osint-sources", rich_help_panel="Info")
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


@app.command(rich_help_panel="Info")
def tools(
    config: Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Pre-flight check: report which external tools are available on PATH."""
    setup_logging()
    load_config(config)  # validate the config file even though its values aren't used here

    report = tool_registry.availability_report()
    table = Table(title="Kaalyx external tool availability")
    table.add_column("Tool", style="cyan")
    table.add_column("Part")
    table.add_column("On PATH")
    table.add_column("Needs key")
    for key, available in sorted(report.items()):
        spec = tool_registry.get(key)
        assert spec is not None
        status = "[green]yes[/]" if available else "[red]no[/]"
        key_note = spec.requires_secret or ""
        table.add_row(key, spec.part.value, status, key_note)
    console.print(table)

    missing = [s.key for s in tool_registry.missing_tools()]
    if missing:
        console.print(
            f"[yellow]{len(missing)} tool(s) not found on PATH:[/] {', '.join(missing)}"
        )
        console.print(
            "Kaalyx will skip missing tools gracefully; install the ones you need."
        )
    else:
        console.print("[green]All registered tools are available.[/]")


@app.command()
def web(
    config: Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Launch the local web dashboard (implemented in a later build step)."""
    console.print(
        "[yellow]The web dashboard is not implemented yet.[/] "
        "It will serve the SQLite results at the configured host/port."
    )
    raise typer.Exit(code=1)


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
    app()


if __name__ == "__main__":
    run()
