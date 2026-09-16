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


def short_sha(sha: str | None) -> str | None:
    """Normalise any commit SHA to a common 7-char prefix for comparison/display.

    ``git rev-parse --short`` returns a *variable*-length abbreviation (git widens it as a
    repo grows to keep it unambiguous), while the GitHub API gives a full 40-char SHA. Both
    must be reduced to the same width or equality checks misfire — a full SHA and its own
    abbreviation would compare unequal. 7 is git's conventional floor and unambiguous for a
    repo this size.
    """
    if not sha:
        return None
    return sha.strip()[:7] or None


def latest_remote_commit(timeout: float = 15.0) -> tuple[str, str, str] | None:
    """Return ``(short_sha, full_sha, iso_date)`` of the latest commit on the repo's branch.

    The *full* SHA matters: we pin the pipx install to it (``@<full_sha>``) so the install
    URL changes per commit — which is what actually defeats pip's URL-keyed clone/wheel
    cache — and we record it verbatim as install state. ``None`` on any network/parse
    failure (the caller reports it and exits cleanly).
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
        full = str(data.get("sha", "")).strip()
        date = (
            data.get("commit", {}).get("committer", {}).get("date", "")
            if isinstance(data.get("commit"), dict)
            else ""
        )
        return (full[:7], full, date) if full else None
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        # The caller reports this cleanly to the user; keep it at debug to avoid double noise.
        logger.debug("Could not reach GitHub to check for updates: %s", exc)
        return None


def commits_between(base: str | None, head: str, timeout: float = 15.0) -> list[tuple[str, str]]:
    """Return ``[(short_sha, subject), …]`` for the commits from *base* (exclusive) to *head*.

    Uses GitHub's compare API (``/compare/{base}...{head}``), newest first. The *subject* is
    each commit message's first line, verbatim (prefix stripping is a display concern left to
    the caller). Returns an empty list on any failure or when *base* is unknown — the caller
    then just shows the headline without a per-commit changelog.
    """
    if not base or base == head:
        return []
    url = f"https://api.github.com/repos/{REPO}/compare/{base}...{head}"
    try:
        resp = httpx.get(
            url,
            headers={"Accept": "application/vnd.github+json", "User-Agent": "kaalyx-updater"},
            timeout=timeout, follow_redirects=True,
        )
        if resp.status_code != 200:
            logger.debug("compare API returned HTTP %s", resp.status_code)
            return []
        commits = resp.json().get("commits") or []
        out: list[tuple[str, str]] = []
        for c in commits:
            sha = str(c.get("sha", ""))[:7]
            msg = str((c.get("commit") or {}).get("message", "")).strip()
            subject = msg.splitlines()[0] if msg else ""
            if sha and subject:
                out.append((sha, subject))
        out.reverse()  # compare returns oldest-first; show newest-first
        return out
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        logger.debug("Could not fetch commit list %s: %s", url, exc)
        return []


def recent_commits(limit: int = 20, timeout: float = 15.0) -> list[tuple[str, str]]:
    """Return ``[(short_sha, subject), …]`` for the most recent commits, newest first.

    Prefers a local git checkout (``git log``); falls back to GitHub's commits API for a
    pipx install with no ``.git``. Empty list on total failure.
    """
    repo_dir = Path(__file__).resolve().parent.parent.parent
    if (repo_dir / ".git").exists():
        try:
            out = subprocess.run(
                ["git", "-C", str(repo_dir), "log", f"-{max(1, limit)}",
                 "--format=%h%x09%s"],
                capture_output=True, text=True, timeout=timeout, check=False,
            )
            rows = [
                (line.split("\t", 1)[0], line.split("\t", 1)[1])
                for line in out.stdout.splitlines() if "\t" in line
            ]
            if rows:
                return rows
        except (OSError, subprocess.SubprocessError):
            pass
    # pipx-install fallback: GitHub commits API.
    try:
        resp = httpx.get(
            f"https://api.github.com/repos/{REPO}/commits",
            params={"sha": BRANCH, "per_page": max(1, min(limit, 100))},
            headers={"Accept": "application/vnd.github+json", "User-Agent": "kaalyx-updater"},
            timeout=timeout, follow_redirects=True,
        )
        if resp.status_code != 200:
            return []
        out2: list[tuple[str, str]] = []
        for c in resp.json() or []:
            sha = str(c.get("sha", ""))[:7]
            msg = str((c.get("commit") or {}).get("message", "")).strip()
            subject = msg.splitlines()[0] if msg else ""
            if sha and subject:
                out2.append((sha, subject))
        return out2
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        logger.debug("Could not fetch recent commits: %s", exc)
        return []


def pipx_available() -> bool:
    return shutil.which("pipx") is not None


def commit_from_package_metadata() -> str | None:
    """Return the exact commit pip resolved when it installed this package, or ``None``.

    pip records the resolved VCS commit for any ``git+…`` install in a PEP 610
    ``direct_url.json`` file inside the installed distribution's metadata
    (``vcs_info.commit_id``). This is *authoritative* for a pipx install — it reflects the
    bytes actually on disk, not what we hoped got installed — so it's how we verify an update
    genuinely happened rather than trusting pipx's exit code. Absent for an editable/dev
    install (there is no VCS pin), hence ``None`` there.
    """
    try:
        import importlib.metadata as im

        raw = im.distribution("kaalyx").read_text("direct_url.json")
        if not raw:
            return None
        import json

        info = json.loads(raw).get("vcs_info") or {}
        commit = str(info.get("commit_id", "")).strip()
        return commit or None
    except Exception as exc:  # metadata missing, not a VCS install, malformed JSON, …
        logger.debug("Could not read commit from package metadata: %s", exc)
        return None


def installed_commit(timeout: float = 5.0) -> str | None:
    """Return the short commit this Kaalyx install was built from, or ``None`` if unknown.

    Order of truth (most authoritative first):
      1. a dev git checkout — read ``.git`` HEAD directly, else
      2. the exact commit pip pinned in the installed package's PEP 610 metadata
         (reflects the bytes truly on disk for a ``git+…`` pipx install), else
      3. the recorded state file from the last successful update.

    Prefer (2) over (3) so a stale/incorrectly-written state file can never override what is
    genuinely installed. ``None`` only when none are available — the caller then can't prove
    up-to-date and treats it as "update".
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
                return short_sha(sha)
        except (OSError, subprocess.SubprocessError):
            pass
    return short_sha(commit_from_package_metadata() or read_installed_commit())


def reinstall_from_repo(ref: str | None = None, capture: bool = True) -> tuple[int, str]:
    """Reinstall Kaalyx from the GitHub repo by uninstalling then re-installing via pipx.

    Deliberately does NOT use ``pipx install --force``: on pipx's uv backend (the current
    Debian/Kali default), ``--force`` refuses to replace a venv it did not create in the
    current session ("Not removing existing venv ... because it was not created in this
    session"), so the update fails. Uninstalling first removes the venv outright; the install
    afterwards creates a fresh one with nothing to overwrite.

    *ref* is the git ref to install; pass the full commit SHA (from
    :func:`latest_remote_commit`) so the install is pinned to exactly that commit. This is
    what makes an update genuine: ``git+…@main`` is the *same URL* every run, so pip happily
    serves a cached clone/wheel; ``git+…@<sha>`` is a distinct URL per commit, sidestepping
    that cache. We *also* pass ``--no-cache-dir`` and ``--force-reinstall`` to pip as a
    belt-and-braces guarantee of a fresh build. Falls back to ``main`` only if no ref is given.

    When *capture* is True, pipx's output is captured (hidden) and returned so the caller can
    show it only under --verbose; when False it streams to the terminal. Returns
    ``(exit_code, captured_output)``.
    """
    target = ref or BRANCH
    if not pipx_available():
        return 3, (
            "pipx is not on PATH. Kaalyx self-update uses pipx; install pipx, or update "
            f"manually with: pip install --force-reinstall --no-cache-dir "
            f"'git+{REPO_URL}.git@{target}'."
        )

    # Installing a git+ spec requires git on PATH to clone the repo. Without it pip fails deep
    # in its output with an opaque clone error; check up front and say so plainly.
    if shutil.which("git") is None:
        return 5, (
            "git is not on PATH. Installing from GitHub needs git to clone the repo. "
            "Install it (e.g. `sudo apt install git`) and retry."
        )

    spec = f"git+{REPO_URL}.git@{target}"

    # UV_VENV_CLEAR=1 tells uv (pipx's default backend on current Debian/Kali) it may replace an
    # existing venv; harmlessly ignored by the pip backend. Kept as belt-and-braces, but it is
    # NOT the primary mechanism — see below.
    env = dict(os.environ)
    env["UV_VENV_CLEAR"] = "1"

    def _run(cmd: list[str]) -> tuple[int, str]:
        try:
            if capture:
                # Decode as UTF-8 with replacement: pipx prints emoji (✨🌟) that crash the
                # default cp1252 pipe reader on Windows.
                completed = subprocess.run(
                    cmd, check=False, capture_output=True,
                    encoding="utf-8", errors="replace", env=env,
                )
                out = (completed.stdout or "") + (completed.stderr or "")
                return completed.returncode, f"$ {' '.join(cmd)}\n{out}"
            completed = subprocess.run(cmd, check=False, env=env)
            return completed.returncode, ""
        except OSError as exc:  # pragma: no cover
            return 4, f"Failed to launch pipx ({' '.join(cmd)}): {exc}"

    output_parts: list[str] = []

    # PRIMARY (lightweight) path: upgrade IN PLACE inside the existing pipx venv via
    # `pipx runpip kaalyx install --upgrade <spec>`. This reuses the venv and lets pip reinstall
    # ONLY what actually changed (kaalyx itself, plus any dependency whose pin moved) — no full
    # teardown, no rebuilding every unchanged dependency from scratch. `--force-reinstall` is
    # scoped so pip always replaces kaalyx's own files (never serving a stale build for the same
    # version string), while `--upgrade` leaves satisfied dependencies untouched. `--no-deps` is
    # deliberately NOT used, so a genuinely new/changed dependency is still pulled in.
    light_cmd = [
        "pipx", "runpip", "kaalyx", "install",
        "--upgrade", "--force-reinstall", "--no-cache-dir", "--no-deps",
        spec,
    ]
    code, out = _run(light_cmd)
    output_parts.append(f"[step: in-place upgrade via pipx runpip (--no-deps)]\n{out}")
    if code == 0:
        # A code-only change is done. Follow with a deps-only pass so a moved/added dependency
        # pin is still satisfied without reinstalling the ones that didn't change.
        code_deps, out_deps = _run(
            ["pipx", "runpip", "kaalyx", "install", "--upgrade", "--no-cache-dir", spec])
        output_parts.append(f"[step: dependency top-up (--upgrade)]\n{out_deps}")
        # The in-place code upgrade already succeeded; a deps top-up failure (e.g. offline) does
        # not undo it, so report success on the code upgrade.
        return 0, "\n".join(output_parts)

    if is_network_error(out):
        return code, "\n".join(output_parts)  # a retry won't fix a network problem

    # FALLBACK (full reinstall): if the in-place upgrade path isn't available (older pipx without
    # `runpip`, a corrupted venv, or a metadata mismatch), fall back to the robust
    # uninstall-then-install. No `--force`: on pipx's uv backend `pipx install --force` refuses
    # to replace a venv it didn't create this session, so we uninstall first (removes the venv
    # outright) then install fresh, pinned to the exact commit.
    output_parts.append("[note: in-place upgrade unavailable — falling back to full reinstall]")
    _, unout = _run(["pipx", "uninstall", "kaalyx"])
    output_parts.append(f"[step: pipx uninstall kaalyx]\n{unout}")

    code, out2 = _run(["pipx", "install",
                       "--pip-args=--no-cache-dir --force-reinstall", spec])
    output_parts.append(f"[step: pipx install (pinned)]\n{out2}")
    if code == 0 or is_network_error(out2):
        return code, "\n".join(output_parts)

    # Some older pipx builds mishandle the multi-flag --pip-args string; retry without it.
    code, out3 = _run(["pipx", "install", spec])
    output_parts.append(f"[step: retry pipx install without --pip-args]\n{out3}")
    return code, "\n".join(output_parts)


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
