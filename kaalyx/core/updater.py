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


def reinstall_from_repo() -> int:
    """Reinstall Kaalyx from the GitHub repo via ``pipx install --force``.

    Uses pipx's git spec so a user who installed with pipx gets an in-place upgrade to the
    latest ``main`` without re-cloning. Returns the pipx exit code (non-zero sentinel if it
    could not be launched).
    """
    if not pipx_available():
        logger.error(
            "pipx is not on PATH. Kaalyx self-update uses pipx; install pipx, or update "
            "manually with: pip install --force-reinstall 'git+%s@%s'.", REPO_URL, BRANCH
        )
        return 3

    spec = f"git+{REPO_URL}.git@{BRANCH}"
    cmd = ["pipx", "install", "--force", spec]
    logger.info("Reinstalling via: %s", " ".join(cmd))
    try:
        completed = subprocess.run(cmd, check=False)
        return completed.returncode
    except OSError as exc:  # pragma: no cover
        logger.error("Failed to launch pipx: %s", exc)
        return 4


def current_version() -> str:
    return __version__
