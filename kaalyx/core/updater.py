"""Self-update: pull the latest Kaalyx from GitHub and reinstall via pipx.

Kaalyx is distributed as a pipx install from the GitHub repo (no PyPI releases or version
tags yet), so "up to date" is defined against the latest commit on the repo's default branch
rather than a release tag.

Knowing *which* commit the current install was built from is the crux of reporting
honestly. A pipx install has NO ``.git`` directory, so we cannot read a local git HEAD.
Instead, after every successful update we record the commit we just installed in a small
state file (``~/.local/state/kaalyx/installed_commit``). On the next run we compare that
recorded commit against the remote's latest: equal => already up to date; different (or no
record yet) => update. A dev git checkout falls back to reading ``.git`` HEAD directly.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import httpx

from .. import __version__
from .logging import get_logger

logger = get_logger("updater")

REPO = "who0xac/kaalyx"
BRANCH = "main"
REPO_URL = f"https://github.com/{REPO}"
_LATEST_COMMIT_API = f"https://api.github.com/repos/{REPO}/commits/{BRANCH}"


def _state_file() -> Path:
    """Path of the file recording the commit the current install was built from.

    Uses ``$XDG_STATE_HOME`` when set, else ``~/.local/state`` (Linux/mac convention; on
    Windows it lands under the user's home, which is fine and writable).
    """
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "kaalyx" / "installed_commit"


def read_installed_commit() -> str | None:
    """Return the commit recorded from the last successful update, if any."""
    path = _state_file()
    try:
        sha = path.read_text(encoding="utf-8").strip()
        return sha or None
    except OSError:
        return None


def write_installed_commit(sha: str) -> None:
    """Record *sha* as the commit the current install was built from (best-effort)."""
    path = _state_file()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(sha.strip(), encoding="utf-8")
    except OSError as exc:  # pragma: no cover - non-fatal
        logger.debug("Could not record installed commit: %s", exc)


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
            logger.debug("GitHub API returned HTTP %s", resp.status_code)
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
        # The caller reports this cleanly to the user; keep it at debug to avoid double noise.
        logger.debug("Could not reach GitHub to check for updates: %s", exc)
        return None


def pipx_available() -> bool:
    return shutil.which("pipx") is not None


def installed_commit(timeout: float = 5.0) -> str | None:
    """Return the short commit this Kaalyx install was built from, or ``None`` if unknown.

    Order of truth:
      1. a dev git checkout — read ``.git`` HEAD directly (always authoritative locally), else
      2. the recorded state file from the last successful update (the pipx-install case).

    ``None`` only when neither is available (a fresh pipx install that has never self-updated
    through this tool) — the caller then can't prove up-to-date and treats it as "update".
    """
    repo_dir = Path(__file__).resolve().parent.parent.parent
    if (repo_dir / ".git").exists():
        try:
            out = subprocess.run(
                ["git", "-C", str(repo_dir), "rev-parse", "--short", "HEAD"],
                capture_output=True, text=True, timeout=timeout, check=False,
            )
            sha = out.stdout.strip()
            if sha:
                return sha
        except (OSError, subprocess.SubprocessError):
            pass
    return read_installed_commit()


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


# Substrings that mark a pipx/pip/git failure as a network-reachability problem rather than
# a genuine build/packaging error — so the CLI can show the clear "couldn't reach GitHub"
# message instead of a generic failure.
_NETWORK_ERROR_HINTS = (
    "could not resolve host",
    "failed to connect",
    "connection timed out",
    "temporary failure in name resolution",
    "network is unreachable",
    "getaddrinfo",
    "name or service not known",
    "connection refused",
    "ssl",
    "timed out",
    "unable to access",
    "operation timed out",
    "no address associated with hostname",
)


def is_network_error(output: str) -> bool:
    """True if *output* from a failed pipx/git run looks like a network/DNS problem."""
    low = output.lower()
    return any(hint in low for hint in _NETWORK_ERROR_HINTS)


def current_version() -> str:
    return __version__
