"""Self-update: pull the latest Kaalyx from GitHub and reinstall via pipx.

Kaalyx is distributed as a pipx-installed package from the GitHub repo (there are no formal
PyPI releases or version tags yet), so "up to date" is defined against the latest commit on
the repo's default branch rather than a release tag. The updater:

1. reads the locally installed version and the current commit it was built from (if the
   install is a git checkout),
2. asks GitHub for the latest commit on ``main``,
3. if they differ (or the state can't be compared), reinstalls from the repo with
   ``pipx install --force``,
4. reports current vs latest and whether an update happened.

Everything is best-effort and non-destructive: network or tooling failures are reported and
the command exits cleanly rather than leaving a half-updated install.
"""

from __future__ import annotations

import shutil
import subprocess

import httpx

from .. import __version__
from .logging import get_logger

logger = get_logger("updater")

REPO = "who0xac/kaalyx"
BRANCH = "main"
REPO_URL = f"https://github.com/{REPO}"
_LATEST_COMMIT_API = f"https://api.github.com/repos/{REPO}/commits/{BRANCH}"


def latest_remote_commit(timeout: float = 15.0) -> tuple[str, str] | None:
    """Return ``(short_sha, iso_date)`` of the latest commit on the repo's branch.

    ``None`` on any network/parse failure (the caller reports it and exits cleanly).
    """
    try:
        resp = httpx.get(
            _LATEST_COMMIT_API,
            headers={"Accept": "application/vnd.github+json", "User-Agent": "kaalyx-updater"},
            timeout=timeout,
            follow_redirects=True,
        )
        if resp.status_code != 200:
            logger.warning("GitHub API returned HTTP %s", resp.status_code)
            return None
        data = resp.json()
        sha = str(data.get("sha", ""))[:7]
        date = (
            data.get("commit", {}).get("committer", {}).get("date", "")
            if isinstance(data.get("commit"), dict)
            else ""
        )
        return (sha, date) if sha else None
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        logger.warning("Could not reach GitHub to check for updates: %s", exc)
        return None


def pipx_available() -> bool:
    return shutil.which("pipx") is not None


def installed_commit(timeout: float = 5.0) -> str | None:
    """Return the short git commit this Kaalyx was built from, if discoverable.

    Kaalyx ships from a git checkout, so when the working tree is a repo we can read HEAD to
    decide whether the install already matches the latest remote commit. Returns ``None`` if
    the install isn't a git checkout (e.g. a pipx build has no .git), in which case the
    caller can't prove up-to-date and updates unconditionally.
    """
    from pathlib import Path

    repo_dir = Path(__file__).resolve().parent.parent.parent
    if not (repo_dir / ".git").exists():
        return None
    try:
        out = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        sha = out.stdout.strip()
        return sha or None
    except (OSError, subprocess.SubprocessError):
        return None


def reinstall_from_repo(capture: bool = True) -> tuple[int, str]:
    """Reinstall Kaalyx from the GitHub repo via ``pipx install --force``.

    Uses pipx's git spec so a pipx user gets an in-place upgrade to the latest ``main``.
    When *capture* is True, pipx's output is captured (hidden) and returned so the caller can
    show it only under --verbose; when False it streams to the terminal. Returns
    ``(exit_code, captured_output)``.
    """
    if not pipx_available():
        return 3, (
            "pipx is not on PATH. Kaalyx self-update uses pipx; install pipx, or update "
            f"manually with: pip install --force-reinstall 'git+{REPO_URL}.git@{BRANCH}'."
        )

    spec = f"git+{REPO_URL}.git@{BRANCH}"
    cmd = ["pipx", "install", "--force", spec]
    try:
        if capture:
            # Decode as UTF-8 with replacement: pipx prints emoji (✨🌟) that crash the
            # default cp1252 pipe reader on Windows.
            completed = subprocess.run(
                cmd, check=False, capture_output=True,
                encoding="utf-8", errors="replace",
            )
            return completed.returncode, (completed.stdout or "") + (completed.stderr or "")
        completed = subprocess.run(cmd, check=False)
        return completed.returncode, ""
    except OSError as exc:  # pragma: no cover
        return 4, f"Failed to launch pipx: {exc}"


def installed_version_via_pipx(timeout: float = 10.0) -> str | None:
    """Best-effort read of the version pipx currently reports for kaalyx (post-update)."""
    if not pipx_available():
        return None
    try:
        out = subprocess.run(
            ["pipx", "list", "--short"], capture_output=True, text=True,
            timeout=timeout, check=False,
        )
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "kaalyx":
                return parts[1]
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def current_version() -> str:
    return __version__
