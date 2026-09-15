"""Drive ``scripts/install.sh`` for the ``kaalyx tools --install`` command.

Kaalyx does not reimplement tool-installation logic in Python — that lives once, in
``scripts/install.sh`` (with its ``--osint-only`` / ``--subdomains-only`` / … stage flags),
so there is a single source of truth for how each external tool is installed.

Locating the script has to work in two very different situations:
  * a dev git checkout — the script sits next to the package, and
  * a pipx install straight from GitHub — pipx packages only the Python code, so there is
    NO ``scripts/install.sh`` on disk.

So we prefer the local script when present, and otherwise fetch the exact same script from
the repo (``raw.githubusercontent.com``) at runtime into a temp file and run that. This is
the architecturally cleanest option: one source of truth (the repo's script), it works in
every install mode, and it always runs the latest installer.

The installer is a bash script targeting apt/pacman (Linux/Kali/Arch). On a host without
bash, the caller reports that clearly and does nothing destructive.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import httpx

from .logging import get_logger

logger = get_logger("installer")

# Raw URL of the installer in the repo (kept in one place; branch matches the updater).
_RAW_INSTALL_URL = "https://raw.githubusercontent.com/who0xac/kaalyx/main/scripts/install.sh"

# CLI stage name -> the install.sh flag that installs just that stage's tools.
STAGE_FLAG = {
    "osint": "--osint-only",
    "subdomains": "--subdomains-only",
    "hosts": "--hosts-only",
    "web": "--web-only",
    "vuln": "--vuln-only",
    "all": "--all",
}


def find_local_install_script() -> Path | None:
    """Return a local ``scripts/install.sh`` if one exists (dev checkout), else ``None``."""
    package_root = Path(__file__).resolve().parent.parent.parent  # …/<repo>
    for path in (
        package_root / "scripts" / "install.sh",
        Path.cwd() / "scripts" / "install.sh",
        Path.cwd() / "install.sh",
    ):
        if path.is_file():
            return path
    return None


def fetch_install_script(timeout: float = 30.0) -> Path | None:
    """Download the installer from the repo to a temp file and return its path, or ``None``.

    Used when there is no local script (the pipx-from-GitHub case).
    """
    try:
        resp = httpx.get(_RAW_INSTALL_URL, timeout=timeout, follow_redirects=True)
        if resp.status_code != 200 or "install" not in resp.text.lower():
            logger.debug("Fetching install.sh returned HTTP %s", resp.status_code)
            return None
        tmp = Path(tempfile.gettempdir()) / "kaalyx-install.sh"
        tmp.write_text(resp.text, encoding="utf-8")
        return tmp
    except (httpx.HTTPError, OSError) as exc:
        logger.debug("Could not fetch install.sh: %s", exc)
        return None


def bash_available() -> bool:
    """True if a ``bash`` interpreter is on PATH to run the installer."""
    return shutil.which("bash") is not None


def resolve_install_script() -> tuple[Path | None, str]:
    """Return ``(path, source)`` for the installer: a local script if present, else a
    freshly-fetched copy. ``source`` is 'local' or 'github' (or '' when unavailable)."""
    local = find_local_install_script()
    if local is not None:
        return local, "local"
    fetched = fetch_install_script()
    if fetched is not None:
        return fetched, "github"
    return None, ""


def run_install(stage: str, verbose: bool = False) -> int:
    """Run the installer for *stage* ('osint'|'subdomains'|'hosts'|'web'|'vuln'|'all').

    Streams the installer's output to the terminal (it has its own coloured logging). When
    *verbose* is True, passes ``-vv`` so the installer shows the underlying tools' raw output
    (apt/rustup/nuclei) instead of the clean one-line summaries. Returns the script's exit
    code, or a non-zero sentinel if it could not be run. Never raises.
    """
    flag = STAGE_FLAG.get(stage)
    if flag is None:
        logger.error("Unknown install stage '%s'", stage)
        return 2

    if not bash_available():
        logger.error(
            "bash is not available on this system. The installer targets apt/pacman "
            "(Linux/Kali/Arch); run it there, or install the missing tools manually."
        )
        return 4

    script, source = resolve_install_script()
    if script is None:
        logger.error(
            "Could not obtain install.sh (no local copy and GitHub was unreachable). "
            "Check your connection, or clone the repo and run scripts/install.sh manually."
        )
        return 3

    if source == "github":
        logger.info("Using installer fetched from GitHub.")
    cmd = ["bash", str(script), flag]
    if verbose:
        cmd.append("-vv")
    try:
        completed = subprocess.run(cmd, check=False)
        return completed.returncode
    except OSError as exc:  # pragma: no cover - launch failure
        logger.error("Failed to launch installer: %s", exc)
        return 5
