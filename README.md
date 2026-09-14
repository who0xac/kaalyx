# Kaalyx

```
 _  __           _
| |/ /__ _  __ _| |_   ___  __
| ' // _` |/ _` | | | | \ \/ /
| . \ (_| | (_| | | |_| |>  <
|_|\_\__,_|\__,_|_|\__, /_/\_\
                    |___/
```

**Automated Recon & Vulnerability Engine** — a fully automated bug-bounty
reconnaissance + vulnerability-discovery pipeline for a single target domain.

Kaalyx is an **orchestrator**: it drives 40+ external recon/vuln CLI tools in a
structured 6-part pipeline, persists everything to both SQLite and raw files, and
surfaces results through a rich terminal UI, a local web dashboard, and Telegram alerts —
so you spend your time on manual deep-dive testing instead of babysitting tools.

> Author: who0xac · Use only against systems you own or are explicitly authorised to assess.

---

## Installation

Kaalyx has **two** parts to install: the external CLI tools it orchestrates, and the
Kaalyx Python package itself.

### 1. Install the external recon/vuln tools

`scripts/install.sh` installs the external tools (subfinder, nuclei, theHarvester, …) on
**apt** (Debian/Kali/Ubuntu) or **pacman** (Arch). It's resilient — a failed tool never
aborts the rest — and idempotent, so you can re-run it any time.

```bash
# Full install (all pipeline phases):
./scripts/install.sh              # or: --install / --all

# See what's installed vs. missing without installing anything:
./scripts/install.sh --check

# Install only the tools for one phase:
./scripts/install.sh --osint-only
./scripts/install.sh --subdomains-only
./scripts/install.sh --hosts-only
./scripts/install.sh --web-only
./scripts/install.sh --vuln-only

# Full help + banner:
./scripts/install.sh --help
```

### 2. Install Kaalyx itself (pipx)

Kaalyx is a Python 3.11+ package. Install it with **pipx** from the project root so the
`kaalyx` command lands on your PATH in an isolated environment:

```bash
pipx install .
kaalyx --help
kaalyx scan example.com
```

For development, an editable install into a virtualenv also works:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

---

## Usage

```bash
kaalyx scan example.com            # run the pipeline against a target
kaalyx scan app.example.com        # a bare subdomain skips subdomain enumeration
kaalyx resume example.com          # resume an interrupted scan from its checkpoint
kaalyx tools                       # pre-flight: which external tools are on PATH
kaalyx osint-sources               # list every OSINT sub-check + how to toggle it
```

Select or skip OSINT sub-checks per run:

```bash
kaalyx scan example.com --skip-osint trufflehog,cloud_enum
kaalyx scan example.com --only-osint whois,dns,mail_dns,m365
```

---

## Configuration

Kaalyx reads two files: **`config.yaml`** (settings) and **`.env`** (API keys/secrets).

When installed with pipx, both live in the standard config directory:

```
~/.config/kaalyx/config.yaml
~/.config/kaalyx/.env
```

(`$XDG_CONFIG_HOME/kaalyx/` is honoured if set.) The first time you run a scan — or any
time you run the command below — Kaalyx creates that directory with template files if they
don't exist yet, so a fresh install just works. To see the exact paths on your machine:

```bash
kaalyx config --path
```

**Lookup order** (highest wins): a `--config PATH` flag → `./config.yaml` in the current
directory (handy inside a source checkout) → `~/.config/kaalyx/config.yaml`. A local `./.env`
likewise takes precedence over `~/.config/kaalyx/.env`.

Edit `~/.config/kaalyx/.env` to add keys. Any missing key simply disables that source —
Kaalyx never crashes for a missing key. CLI flags override `config.yaml`, which overrides
the built-in defaults.

### Multiple GitHub tokens (rate-limit rotation)

`github-subdomains`, `trufflehog`, and the GitHub Actions audit all use a GitHub token, so a
single token can hit GitHub's API rate limit quickly. Provide several and Kaalyx rotates
across them. One token behaves exactly as a single-token setup. Use the numbered form:

```dotenv
GITHUB_TOKEN=token1
GITHUB_TOKEN_2=token2
GITHUB_TOKEN_3=token3
```

The generated `~/.config/kaalyx/.env` documents every key — which tool uses it and where to
get it — so it's clear what to fill in on first open.

---

## Project layout

```
kaalyx/            # the Python package (orchestrator, stages, data, UI, …)
scripts/
  install.sh       # external-tool installer (apt/pacman)
config.yaml        # default settings (overridable)
.env.example       # secrets template
pyproject.toml     # packaging + `kaalyx` entry point (pipx-installable)
```
