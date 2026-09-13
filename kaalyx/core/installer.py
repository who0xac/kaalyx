"""Locate and drive ``scripts/install.sh`` for the ``kaalyx tools --install`` command.

Kaalyx does not reimplement tool-installation logic in Python — that lives once, in
``scripts/install.sh`` (with its ``--osint-only`` / ``--subdomains-only`` / … phase flags).
This module just finds that script and shells out to it with the matching flag, so there
is a single source of truth for how each external tool is installed.

The installer is a bash script targeting apt/pacman (Linux/Kali/Arch). On a host without
bash, or when the script can't be found (e.g. a pipx install with no repo checkout), the
caller reports that clearly and does nothing destructive.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .logging import get_logger

logger = get_logger("installer")

# CLI phase name -> the install.sh flag that installs just that phase's tools.
PHASE_FLAG = {
    "osint": "--osint-only",
    "subdomains": "--subdomains-only",
    "hosts": "--hosts-only",
    "web": "--web-only",
    "vuln": "--vuln-only",
    "all": "--all",
}


def find_install_script() -> Path | None:
    """Return the path to ``scripts/install.sh`` if it can be located, else ``None``.

    Looks alongside the installed package (``<repo>/scripts/install.sh`` relative to the
    ``kaalyx`` package) and in the current working directory, covering both a source
    checkout and running from within a cloned repo.
    """
    package_root = Path(__file__).resolve().parent.parent.parent  # …/<repo>
    candidates = [
        package_root / "scripts" / "install.sh",
        Path.cwd() / "scripts" / "install.sh",
        Path.cwd() / "install.sh",
    ]
    for path in candidates:
        if path.is_file():
            return path
    return None


def bash_available() -> bool:
    """True if a ``bash`` interpreter is on PATH to run the installer."""
    return shutil.which("bash") is not None


def run_install(phase: str) -> int:
    """Run ``install.sh`` for *phase* ('osint'|'subdomains'|'hosts'|'web'|'vuln'|'all').

    Streams the installer's output straight to the terminal (it has its own progress/
    coloured logging). Returns the script's exit code, or a non-zero sentinel if it could
    not be launched. Never raises — the caller surfaces the outcome.
    """
    flag = PHASE_FLAG.get(phase)
    if flag is None:
        logger.error("Unknown install phase '%s'", phase)
        return 2

    script = find_install_script()
    if script is None:
        logger.error(
            "install.sh not found. Clone the repo and run scripts/install.sh manually, "
            "or run 'kaalyx tools' to see what's missing."
        )
        return 3

    if not bash_available():
        logger.error(
            "bash is not available on this system. scripts/install.sh targets apt/pacman "
            "(Linux/Kali/Arch); run it there, or install the missing tools manually."
        )
        return 4

    cmd = ["bash", str(script), flag]
    logger.info("Running installer: %s %s", script, flag)
    try:
        completed = subprocess.run(cmd, check=False)
        return completed.returncode
    except OSError as exc:  # pragma: no cover - launch failure
        logger.error("Failed to launch installer: %s", exc)
        return 5
