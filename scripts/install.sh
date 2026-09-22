#!/usr/bin/env bash
#
# Kaalyx — external recon/vuln tool installer.
#
# Installs the 40+ external CLI tools the Kaalyx pipeline orchestrates. Kaalyx itself
# (the Python package) is installed separately with pipx — see `--help` and the README.
#
# Supports apt (Debian/Kali/Ubuntu) and pacman (Arch). Every independent tool install is
# wrapped in `try` so one failure never aborts the rest. Run with `--help` for options.
#
set -Eeuo pipefail

set +H

BIN_DIR="${HOME}/bin"
SRC_DIR="${HOME}/src"
GOBIN_DIR="${HOME}/go/bin"
CARGO_BIN="${HOME}/.cargo/bin"
# Per-tool install logs live here so a failed step can show its REAL error (pip/clone stderr)
# instead of a bare "failed". The tail is printed inline on failure; the full log is kept.
LOG_DIR="${SRC_DIR}/.install-logs"

mkdir -p "${BIN_DIR}" "${SRC_DIR}" "${GOBIN_DIR}" "${LOG_DIR}"

export GOPATH="${HOME}/go"
export GOBIN="${GOBIN_DIR}"
export PATH="${BIN_DIR}:${GOBIN_DIR}:${CARGO_BIN}:${PATH}"

# --- Colors (single source of truth; consistent with Kaalyx's rich palette) ---------------
#   art=red  tagline=yellow  author=dim   stage headers=bold cyan
#   success=green  skipped=yellow  failed=red   Finished!=bold green
C_RED=$'\033[0;31m';  C_GREEN=$'\033[0;32m'; C_YELLOW=$'\033[0;33m'
C_CYAN=$'\033[0;36m'; C_DIM=$'\033[2m';       C_BOLD=$'\033[1m'; C_NC=$'\033[0m'

log()  { printf '\n\033[1;32m[+]\033[0m %s\n' "$1"; }
info() { printf '\033[1;36m[*]\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$1"; }
fail() { printf '\033[1;31m[-]\033[0m %s\n' "$1"; exit 1; }

# Stage header: "Running: <name>" in bold cyan.
stage_header() { printf '\n%s%sRunning: %s%s\n' "${C_BOLD}" "${C_CYAN}" "$1" "${C_NC}"; }

# --- Per-tool progress counters + category tallies -----------------------------------------
# Each install stage resets the counter, sets a total, then calls tool_step for every tool.
# Four DISTINCT per-tool states, so the output/summary is never ambiguous:
#   present  → already installed, no action needed. A SUCCESS state; counts toward OK.
#   ok       → we just installed it (this run). Counts toward OK.
#   skipped  → genuinely not attempted, an unmet precondition (shown WITH a reason).
#   failed   → the install ran and failed.
# The summary reports "X OK (Y already installed), Z skipped, W failed" so already-present and
# freshly-installed are both OK, and a real skip (with its reason) stands apart.
_STEP_i=0          # current index within the active category
_STEP_total=0      # total tools in the active category (shown as [i/total])
declare -A _CAT_OK _CAT_PRESENT _CAT_SKIP _CAT_FAIL _CAT_TOTAL

begin_category() {  # begin_category <label> <total>
    _CAT_LABEL="$1"; _STEP_total="$2"; _STEP_i=0
    _CAT_OK["$1"]=0; _CAT_PRESENT["$1"]=0; _CAT_SKIP["$1"]=0; _CAT_FAIL["$1"]=0; _CAT_TOTAL["$1"]="$2"
}

# tool_step <name> <present|ok|skipped|failed> [verb_or_reason] — print "[i/total] name
# <status>" coloured, and roll the result into the active category's tally. For "ok" the third
# arg is the success verb (installed/ready); for "skipped" it is the reason shown after the tag.
tool_step() {
    local name="$1" status="$2" extra="${3:-}"
    _STEP_i=$((_STEP_i + 1))
    case "${status}" in
        present) _CAT_PRESENT["${_CAT_LABEL}"]=$(( ${_CAT_PRESENT["${_CAT_LABEL}"]} + 1 ))
                 printf '  [%d/%d] %s %salready installed%s\n' "${_STEP_i}" "${_STEP_total}" "${name}" "${C_CYAN}" "${C_NC}" ;;
        ok)      _CAT_OK["${_CAT_LABEL}"]=$(( ${_CAT_OK["${_CAT_LABEL}"]} + 1 ))
                 printf '  [%d/%d] %s %s%s%s\n' "${_STEP_i}" "${_STEP_total}" "${name}" "${C_GREEN}" "${extra:-installed}" "${C_NC}" ;;
        skipped) _CAT_SKIP["${_CAT_LABEL}"]=$(( ${_CAT_SKIP["${_CAT_LABEL}"]} + 1 ))
                 printf '  [%d/%d] %s %sskipped%s%s\n' "${_STEP_i}" "${_STEP_total}" "${name}" "${C_YELLOW}" "${C_NC}" \
                        "${extra:+$(printf ' %s(%s)%s' "${C_DIM}" "${extra}" "${C_NC}")}" ;;
        *)       _CAT_FAIL["${_CAT_LABEL}"]=$(( ${_CAT_FAIL["${_CAT_LABEL}"]} + 1 ))
                 printf '  [%d/%d] %s %sfailed%s\n' "${_STEP_i}" "${_STEP_total}" "${name}" "${C_RED}" "${C_NC}" ;;
    esac
}

# run_tool <name> <ok_verb> <command...> — run an install command, classify the outcome, count
# it. Already-present => "present" (already installed, counts OK); command succeeds and the
# binary appears => "ok"; otherwise "failed". Never aborts the run (mirrors `try`). For
# repositories we print a "(clone)" progress line before running so the clone is visible.
run_tool() {
    local name="$1" ok_verb="$2"; shift 2
    # "Present" means genuinely runnable. For a Repositories tool, a wrapper on PATH is NOT
    # proof — its venv deps may have failed — so we verify it actually runs before skipping.
    # A broken-but-present repo tool falls through to (re)install, which self-heals.
    if [[ "${_CAT_LABEL}" == "Repositories" ]]; then
        if wrapper_runnable "${name}"; then
            tool_step "${name}" present
            return 0
        fi
    elif command -v "${name}" >/dev/null 2>&1; then
        tool_step "${name}" present
        return 0
    fi
    if [[ "${_CAT_LABEL}" == "Repositories" ]]; then
        printf '  [%d/%d] %s %s(clone)%s\n' "$((_STEP_i + 1))" "${_STEP_total}" "${name}" "${C_DIM}" "${C_NC}"
    fi
    # The install function returns non-zero on a broken/failed install (deps failed / not
    # runnable). Capture its stdout+stderr to a per-tool log so a failure shows the REAL error
    # (pip/clone output) rather than a bare "failed". Verify runnability after it runs.
    local logf="${LOG_DIR}/${name}.log" rc=0
    "$@" >"${logf}" 2>&1 || rc=$?
    local ok=1
    if [[ ${rc} -eq 0 ]]; then
        if [[ "${_CAT_LABEL}" == "Repositories" ]]; then
            wrapper_runnable "${name}" || ok=0
        elif ! command -v "${name}" >/dev/null 2>&1; then
            ok=0
        fi
    else
        ok=0
    fi
    if [[ ${ok} -eq 1 ]]; then
        tool_step "${name}" ok "${ok_verb}"
    else
        tool_step "${name}" failed
        # Surface the actual error: the last lines of the captured log, indented.
        printf '        %s— error (last lines of %s):%s\n' "${C_DIM}" "${logf}" "${C_NC}"
        tail -n 12 "${logf}" 2>/dev/null | sed 's/^/          /'
    fi
}

# skip_tool <name> <reason> — record a genuine skip (unmet precondition), shown with its reason.
skip_tool() {
    tool_step "$1" skipped "$2"
}

# Network connectivity precheck — one clear "Network OK" / failure line before any install.
network_precheck() {
    stage_header "Network precheck"
    local host
    for host in github.com raw.githubusercontent.com; do
        if curl -fsS --max-time 8 -o /dev/null "https://${host}" 2>/dev/null; then
            printf '  %sNetwork OK%s\n' "${C_GREEN}" "${C_NC}"
            return 0
        fi
    done
    printf '  %sNetwork unreachable%s — could not reach github.com. Check your connection/proxy and retry.\n' \
        "${C_RED}" "${C_NC}"
    return 1
}

# Runs one independent install step without letting its failure abort the
# rest of the script. Each tool below is unrelated to the others, so a
# single network hiccup or build error in one (e.g. a cargo build) used to
# take down every tool listed after it, thanks to `set -e` + the ERR trap.
# Foundational steps (system packages, Go, Rust, Docker) are NOT run
# through this, since nothing else works without them.
try() {
    "$@" || warn "${1} failed (exit $?) — continuing with the rest of the install."
}

# ============================================================================
#  Banner + help
# ============================================================================

# Build/version line: "main-v1.0.0-<short-sha>". The sha is best-effort from
# the repo the script lives in (blank when run outside a checkout).
build_version() {
    local sha=""
    sha="$(git -C "$(dirname "${BASH_SOURCE[0]:-$0}")/.." rev-parse --short HEAD 2>/dev/null || true)"
    if [[ -n "${sha}" ]]; then
        printf 'main-v1.0.0-%s' "${sha}"
    else
        printf 'main-v1.0.0'
    fi
}

print_banner() {
    # Same palette as the main Kaalyx banner: art red; version bold yellow; the " | "
    # separator dim; tagline bold green; author dim.
    local C_BYELLOW=$'\033[1;33m' C_BGREEN=$'\033[1;32m'
    printf '%s\n' "${C_RED}"
    cat <<'ART'
 _  __           _
| |/ /__ _  __ _| |_   ___  __
| ' // _` |/ _` | | | | \ \/ /
| . \ (_| | (_| | | |_| |>  <
|_|\_\__,_|\__,_|_|\__, /_/\_\
                    |___/
ART
    printf '%s' "${C_NC}"
    printf '    %s%s%s  |  %s%s%s\n' \
        "${C_BYELLOW}" "$(build_version)" "${C_NC}" \
        "${C_BGREEN}" "Automated Recon & Vulnerability Engine" "${C_NC}"
    printf '    %sAuthor: who0xac%s\n' "${C_DIM}" "${C_NC}"
}

print_help() {
    print_banner
    cat <<'HELP'

Installs the external recon/vulnerability CLI tools that the Kaalyx pipeline
orchestrates. Supports apt (Debian/Kali/Ubuntu) and pacman (Arch).

USAGE
    ./install.sh [FLAG]

    With no flag, a full install runs (same as --all / --install).

GENERAL
    -h, --help          Show this help and exit.
        --check         Report which required tools are already installed vs.
                        missing, and exit. Installs nothing (dry run).
        --install       Run the full install (all stages). Default behaviour.
        --all           Alias for --install.

INSTALL A SINGLE STAGE ONLY
        --osint-only        Tools for Part 1 — OSINT.
        --subdomains-only   Tools for Part 2 — Subdomain enumeration.
        --hosts-only        Tools for Part 3 — Host / port / service analysis.
        --web-only          Tools for Part 4 — Web analysis / URL collection.
        --vuln-only         Tools for Part 5 — Vulnerability checks.

    Stage installs still install the shared foundation first (system packages,
    Go, Rust, Docker as needed) so the stage tools can build.

INSTALL KAALYX ITSELF (separate from this script)
    Kaalyx is a Python package installed with pipx, from the project root:

        pipx install .

    That puts the `kaalyx` command on PATH. Then run e.g.:

        kaalyx scan example.com

NOTES
    * Missing tools are skipped gracefully; re-run any time to fill gaps.
    * Use the installed tools only against systems you own or are authorised
      to assess.

HELP
}

# ============================================================================
#  Argument parsing — decide the run MODE and which STAGES to install
# ============================================================================

MODE="install"            # install | check
VERBOSE=0                 # -vv/--verbose: show underlying tools' raw output (apt/rust/nuclei…)
declare -a STAGES=()      # empty => all stages
_STAGE_SET=0              # whether a stage flag was given

parse_args() {
    if [[ $# -eq 0 ]]; then
        STAGES=(osint subdomains hosts web vuln)
        return
    fi
    # Loop so -vv/--verbose can appear together with a mode/stage flag in any order.
    local a
    for a in "$@"; do
        case "${a}" in
            -h|--help)          print_help; exit 0 ;;
            -vv|--verbose)      VERBOSE=1 ;;
            --check)            MODE="check"; STAGES=(osint subdomains hosts web vuln); _STAGE_SET=1 ;;
            --install|--all)    STAGES=(osint subdomains hosts web vuln); _STAGE_SET=1 ;;
            --osint-only)       STAGES=(osint); _STAGE_SET=1 ;;
            --subdomains-only)  STAGES=(subdomains); _STAGE_SET=1 ;;
            --hosts-only)       STAGES=(hosts); _STAGE_SET=1 ;;
            --web-only)         STAGES=(web); _STAGE_SET=1 ;;
            --vuln-only)        STAGES=(vuln); _STAGE_SET=1 ;;
            *)                  warn "Unknown option: ${a}"; print_help; exit 2 ;;
        esac
    done
    # Only -vv given (no stage/mode flag) => full install, verbose.
    [[ "${_STAGE_SET}" -eq 1 ]] || STAGES=(osint subdomains hosts web vuln)
}

# run_quiet <label> <command...> — run a noisy foundation command (apt, rustup, nuclei
# templates). By default its output is hidden and we print a single clean status line; with
# -vv the raw output streams through. Returns the command's exit code.
run_quiet() {
    local label="$1"; shift
    if [[ "${VERBOSE}" -eq 1 ]]; then
        "$@"
        return $?
    fi
    local out rc
    out="$("$@" 2>&1)"; rc=$?
    if [[ ${rc} -eq 0 ]]; then
        printf '  %s%s%s\n' "${C_GREEN}" "${label}" "${C_NC}"
    else
        printf '  %s%s (see -vv for detail)%s\n' "${C_YELLOW}" "${label}" "${C_NC}"
        # On failure, surface the tail of the captured output so it isn't lost entirely.
        printf '%s\n' "${out}" | tail -5
    fi
    return ${rc}
}

want_stage() {
    local stage="$1"
    local p
    for p in "${STAGES[@]}"; do
        [[ "${p}" == "${stage}" ]] && return 0
    done
    return 1
}

parse_args "$@"

# ============================================================================
#  Stage → tool mapping (for --check and for the per-stage verification report).
#  Kept in sync with the tools each pipeline stage actually invokes.
# ============================================================================

# Part 1 — OSINT (final spec incl. the 5 gap-closing additions).
OSINT_TOOLS=(
    whois dnsx github-subdomains trufflehog cloud_enum s3scanner badsecrets
    retire theHarvester misconfig-mapper h8mail porch-pirate swaggerspy gato
    git-dumper msftrecon spoofy dnstwist gitgraber
)
# Part 2 — Subdomains.
SUBDOMAIN_TOOLS=(
    subfinder findomain assetfinder sublist3r chaos subdominator crtsh shodan
    censys github-subdomains alterx puredns massdns dnsx dnsreaper
)
# Part 3 — Hosts.
HOST_TOOLS=(naabu httpx nmap wafw00f)
# Part 4 — Web analysis.
WEB_TOOLS=(gowitness gau waybackurls katana gospider uro gf secretfinder trufflehog)
# Part 5 — Vulnerability checks.
VULN_TOOLS=(kxss dalfox nuclei interactsh-client sqlmap sstimap corsy oralyzer)

# Foundation always installed (unless pure --check).
FOUNDATION_TOOLS=(go rustc cargo docker uv anew)

collect_selected_tools() {
    local -n out="$1"
    out=("${FOUNDATION_TOOLS[@]}")
    want_stage osint      && out+=("${OSINT_TOOLS[@]}")
    want_stage subdomains && out+=("${SUBDOMAIN_TOOLS[@]}")
    want_stage hosts      && out+=("${HOST_TOOLS[@]}")
    want_stage web        && out+=("${WEB_TOOLS[@]}")
    want_stage vuln       && out+=("${VULN_TOOLS[@]}")
    # Deduplicate while preserving order.
    local seen="" t deduped=()
    for t in "${out[@]}"; do
        [[ ",${seen}," == *",${t},"* ]] && continue
        seen="${seen},${t}"
        deduped+=("${t}")
    done
    out=("${deduped[@]}")
}

# ============================================================================
#  --check : status report only, no installation
# ============================================================================

run_check() {
    print_banner
    export PATH="${HOME}/.local/bin:/usr/local/go/bin:${GOBIN_DIR}:${CARGO_BIN}:${BIN_DIR}:${PATH}"

    local -a tools
    collect_selected_tools tools

    echo
    echo "============================================================"
    echo "                 TOOL STATUS  (--check)"
    echo "     stages: ${STAGES[*]}"
    echo "============================================================"

    local ok=0 missing=0
    for tool in "${tools[@]}"; do
        if command -v "${tool}" >/dev/null 2>&1; then
            printf '\033[1;32m[OK]\033[0m      %-18s %s\n' "${tool}" "$(command -v "${tool}")"
            ok=$((ok + 1))
        else
            printf '\033[1;31m[MISSING]\033[0m %-18s\n' "${tool}"
            missing=$((missing + 1))
        fi
    done

    echo "============================================================"
    printf 'Installed: \033[1;32m%d\033[0m   Missing: \033[1;31m%d\033[0m\n' "${ok}" "${missing}"
    echo
    echo "Run without --check (or with a stage flag) to install the missing tools."
    exit 0
}

if [[ "${MODE}" == "check" ]]; then
    run_check
fi

# ============================================================================
#  From here down: actual installation.
# ============================================================================

print_banner

stage_header "Install/Update"

trap 'fail "Installation failed around line ${LINENO}."' ERR

# Network connectivity precheck before touching anything — a clear early failure beats a
# confusing mid-install one.
if ! network_precheck; then
    fail "No network connectivity — aborting before installing anything."
fi

if [[ "${EUID}" -eq 0 ]]; then
    SUDO=""
    USER="${USER:-root}"
else
    SUDO="sudo"
fi

ARCH="$(uname -m)"

case "${ARCH}" in
    x86_64)
        GO_ARCH="amd64"
        ;;
    aarch64|arm64)
        GO_ARCH="arm64"
        ;;
    *)
        fail "Unsupported architecture: ${ARCH}"
        ;;
esac

if command -v apt-get >/dev/null 2>&1; then
    PKG="apt"
elif command -v pacman >/dev/null 2>&1; then
    PKG="pacman"
else
    fail "Supported package managers: apt and pacman."
fi

install_system_packages() {

    log "Installing system dependencies..."

    if [[ "${PKG}" == "apt" ]]; then

        ${SUDO} apt-get update

        ${SUDO} apt-get install -y \
            curl \
            wget \
            git \
            jq \
            unzip \
            tar \
            gzip \
            ca-certificates \
            build-essential \
            pkg-config \
            libssl-dev \
            libpcap-dev \
            libffi-dev \
            libxml2-dev \
            libxslt1-dev \
            zlib1g-dev \
            python3 \
            python3-pip \
            python3-venv \
            python3-dev \
            perl \
            make \
            gcc \
            nmap \
            dnsutils \
            whois \
            tmux \
            zsh \
            pipx \
            nodejs \
            npm \
            docker.io

    elif [[ "${PKG}" == "pacman" ]]; then

        ${SUDO} pacman -Sy --needed --noconfirm \
            curl \
            wget \
            git \
            jq \
            unzip \
            tar \
            gzip \
            ca-certificates \
            base-devel \
            openssl \
            libpcap \
            libffi \
            libxml2 \
            libxslt \
            zlib \
            python \
            python-pip \
            perl \
            make \
            gcc \
            nmap \
            bind \
            whois \
            tmux \
            zsh \
            python-pipx \
            nodejs \
            npm \
            docker
    fi
}

stage_header "Foundation (system packages, Go, Rust, Docker)"
run_quiet "System dependencies: up to date" install_system_packages

configure_shell() {
    local rc="$1"

    touch "${rc}"

    add_path_line() {
        local line="$1"

        if ! grep -Fqx "${line}" "${rc}" 2>/dev/null; then
            printf '%s\n' "${line}" >> "${rc}"
        fi
    }

    add_path_line 'export GOPATH="$HOME/go"'
    add_path_line 'export GOBIN="$HOME/go/bin"'
    add_path_line 'export PATH="$HOME/go/bin:$HOME/.cargo/bin:$HOME/bin:$HOME/.local/bin:$PATH"'
}

log "Configuring Bash and Zsh..."

configure_shell "${HOME}/.bashrc"
configure_shell "${HOME}/.zshrc"

install_go() {

    if command -v go >/dev/null 2>&1; then
        log "Go already installed: $(go version)"
        return
    fi

    log "Installing latest stable Go..."

    local version
    local archive

    version="$(
        curl -fsSL https://go.dev/dl/?mode=json |
        jq -r '[.[] | select(.stable == true)][0].version'
    )"

    [[ -n "${version}" && "${version}" != "null" ]] ||
        fail "Unable to determine latest Go version."

    archive="/tmp/${version}.linux-${GO_ARCH}.tar.gz"

    curl -fL \
        "https://go.dev/dl/${version}.linux-${GO_ARCH}.tar.gz" \
        -o "${archive}"

    ${SUDO} rm -rf /usr/local/go
    ${SUDO} tar -C /usr/local -xzf "${archive}"

    rm -f "${archive}"

    export PATH="/usr/local/go/bin:${GOBIN_DIR}:${CARGO_BIN}:${BIN_DIR}:${PATH}"

    log "Go installed: $(/usr/local/go/bin/go version)"
}

run_quiet "Go toolchain: ready" install_go

install_rust() {

    export PATH="${CARGO_BIN}:${PATH}"

    if command -v rustup >/dev/null 2>&1; then
        log "rustup already installed."
    else
        log "Installing Rust + rustc + Cargo..."

        curl \
            --proto '=https' \
            --tlsv1.2 \
            -sSf \
            https://sh.rustup.rs |
            sh -s -- -y
    fi

    [[ -f "${HOME}/.cargo/env" ]] && source "${HOME}/.cargo/env"

    rustup toolchain install stable --profile default
    rustup default stable

    log "rustc: $(rustc --version)"
    log "Cargo: $(cargo --version)"
}

# Rust is only needed to build findomain from source (a Subdomains-stage tool).
# Skip it entirely for stage installs that don't need it, to save time.
if want_stage subdomains; then
    run_quiet "Rust toolchain: ready" install_rust
else
    info "Skipping Rust toolchain (no selected stage needs a cargo build)."
fi

install_docker() {

    if ! command -v docker >/dev/null 2>&1; then
        warn "Docker package was not found after dependency installation."
        return
    fi

    log "Configuring Docker..."

    ${SUDO} systemctl enable --now docker 2>/dev/null || true

    if getent group docker >/dev/null 2>&1; then
        ${SUDO} usermod -aG docker "${USER}" || true
    fi

    log "Docker: $(docker --version)"
    warn "A new login/session may be required for docker group changes."
}

run_quiet "Docker: ready" install_docker

# ============================================================================
#  Shared install helpers
# ============================================================================

go_install() {
    local name="$1"
    local package="$2"

    export PATH="/usr/local/go/bin:${GOBIN_DIR}:${CARGO_BIN}:${BIN_DIR}:${PATH}"

    if [[ -x "${GOBIN_DIR}/${name}" ]]; then
        info "${name} already installed."
        return
    fi

    log "Installing ${name}..."

    if ! go install "${package}@latest"; then
        warn "go install ${package} failed; skipping ${name}."
        return
    fi

    [[ -x "${GOBIN_DIR}/${name}" ]] || {
        warn "${name} did not appear in ${GOBIN_DIR}"
        return
    }

    ln -sf "${GOBIN_DIR}/${name}" "${BIN_DIR}/${name}"
}

# pipx install with graceful --user pip fallback (used by several Python tools).
pipx_install() {
    local spec="$1"     # PyPI name or VCS URL
    local cmd="$2"      # resulting command name in ~/.local/bin

    if command -v "${cmd}" >/dev/null 2>&1 || [[ -x "${BIN_DIR}/${cmd}" ]]; then
        info "${cmd} already installed."
        return
    fi

    log "Installing ${cmd}..."

    python3 -m pipx install "${spec}" 2>/dev/null ||
    python3 -m pip install --user "${spec}" --break-system-packages 2>/dev/null ||
    python3 -m pip install --user "${spec}" --break-system-packages || {
        warn "Failed to install ${cmd}; skipping."
        return
    }

    export PATH="${HOME}/.local/bin:${PATH}"
    [[ -x "${HOME}/.local/bin/${cmd}" ]] &&
        ln -sf "${HOME}/.local/bin/${cmd}" "${BIN_DIR}/${cmd}"
}

# Clone a repo, build a venv, and write a wrapper script into ~/bin that runs `entry`
# (the repo's main .py) through that venv. `req` selects dependency install: "req" =
# requirements.txt, "self" = `pip install .`, or a space-separated package list.
# Runnable check for a git+venv tool: it counts as installed ONLY if its wrapper exists AND
# its entry script actually runs (a lightweight `--help` that neither errors nor complains
# about missing deps). A wrapper alone means nothing — the venv's requirements may have failed
# to install, which is exactly the "already installed but broken" bug this guards against.
git_venv_runnable() {
    local name="$1" dir="${SRC_DIR}/$1"
    [[ -x "${BIN_DIR}/${name}" ]] || return 1
    [[ -x "${dir}/.venv/bin/python" ]] || return 1
    local out
    out="$("${BIN_DIR}/${name}" --help 2>&1 | head -20 || true)"
    # A working tool prints usage/help; a broken one prints an import/requirements error.
    if printf '%s' "${out}" | grep -qiE 'no module named|modulenotfound|please pip install|pip install -r|importerror|traceback'; then
        return 1
    fi
    return 0
}

# Runnable check for a custom wrapper (crtsh/gato/corsy etc.): the wrapper exists AND running
# it with --help doesn't blow up with an import/requirements error. Same principle as
# git_venv_runnable but for tools with bespoke install functions.
wrapper_runnable() {
    local name="$1"
    [[ -x "${BIN_DIR}/${name}" ]] || return 1
    local out
    out="$("${BIN_DIR}/${name}" --help 2>&1 | head -20 || true)"
    if printf '%s' "${out}" | grep -qiE 'no module named|modulenotfound|please pip install|pip install -r|importerror|traceback'; then
        return 1
    fi
    return 0
}

git_venv_tool() {
    local name="$1" repo="$2" entry="$3" req="${4:-}"

    if git_venv_runnable "${name}"; then
        info "${name} already installed."
        return
    fi

    log "Installing ${name}..."

    local dir="${SRC_DIR}/${name}"
    if [[ -d "${dir}/.git" ]]; then
        git -C "${dir}" pull --ff-only || true
    else
        rm -rf "${dir}"          # a stale/partial clone would poison the venv; start clean
        git clone --depth 1 "${repo}" "${dir}"
    fi

    # Recreate the venv if it's missing (a prior partial install may have left none).
    [[ -x "${dir}/.venv/bin/python" ]] || python3 -m venv "${dir}/.venv"
    "${dir}/.venv/bin/pip" install --upgrade pip setuptools wheel >/dev/null 2>&1 || true

    # Install dependencies — do NOT swallow failure; capture it so we can report a broken tool.
    local dep_rc=0
    if [[ "${req}" == "req" ]]; then
        # Prefer requirements.txt when present; otherwise fall back to installing the package
        # itself so pyproject.toml / setup.py-only repos (e.g. cloud_enum, which dropped its
        # requirements.txt for a pyproject) still get their declared dependencies. A repo with
        # neither has no deps to install (dep_rc stays 0).
        if [[ -f "${dir}/requirements.txt" ]]; then
            "${dir}/.venv/bin/pip" install -r "${dir}/requirements.txt" || dep_rc=$?
        elif [[ -f "${dir}/pyproject.toml" || -f "${dir}/setup.py" ]]; then
            "${dir}/.venv/bin/pip" install "${dir}" || dep_rc=$?
        else
            warn "${name}: no requirements.txt / pyproject.toml / setup.py — installing with no deps."
        fi
    elif [[ "${req}" == "self" ]]; then
        "${dir}/.venv/bin/pip" install "${dir}" || dep_rc=$?
    elif [[ -n "${req}" ]]; then
        # shellcheck disable=SC2086
        "${dir}/.venv/bin/pip" install ${req} || dep_rc=$?
    fi

    cat > "${BIN_DIR}/${name}" <<EOF
#!/usr/bin/env bash
exec "${dir}/.venv/bin/python" "${dir}/${entry}" "\$@"
EOF
    chmod +x "${BIN_DIR}/${name}"

    # Verify the tool actually runs now; if not, it's a failed install, not a success.
    if [[ ${dep_rc} -ne 0 ]]; then
        warn "${name}: dependency install failed (pip exit ${dep_rc}); the tool may not run."
        return 1
    fi
    if ! git_venv_runnable "${name}"; then
        warn "${name}: installed but does not run cleanly (missing deps / import error)."
        return 1
    fi
}

install_uv() {
    if command -v uv >/dev/null 2>&1; then
        return
    fi
    log "Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="${HOME}/.local/bin:${PATH}"
}

install_massdns() {

    if command -v massdns >/dev/null 2>&1; then
        log "massdns already installed."
        return
    fi

    log "Building massdns from source (required by puredns)..."

    local dir="${SRC_DIR}/massdns"

    if [[ -d "${dir}/.git" ]]; then
        git -C "${dir}" pull --ff-only || true
    else
        git clone https://github.com/blechschmidt/massdns.git "${dir}"
    fi

    make -C "${dir}"

    ${SUDO} install -m 0755 "${dir}/bin/massdns" /usr/local/bin/massdns
    ln -sf /usr/local/bin/massdns "${BIN_DIR}/massdns"
}

install_chromium() {

    if command -v chromium >/dev/null 2>&1 ||
       command -v chromium-browser >/dev/null 2>&1 ||
       command -v google-chrome >/dev/null 2>&1; then
        log "A Chrome/Chromium binary is already installed."
        return
    fi

    log "Installing Chromium (required by gowitness for screenshots)..."

    if [[ "${PKG}" == "apt" ]]; then
        ${SUDO} apt-get install -y chromium ||
            ${SUDO} apt-get install -y chromium-browser ||
            warn "Chromium package not found in apt repos; install Google Chrome manually."
    elif [[ "${PKG}" == "pacman" ]]; then
        ${SUDO} pacman -S --needed --noconfirm chromium ||
            warn "Chromium package not found in pacman repos; install Google Chrome manually."
    fi
}

# ============================================================================
#  Subdomains
# ============================================================================

install_findomain() {

    if command -v findomain >/dev/null 2>&1; then
        log "findomain already installed."
        return
    fi

    log "Installing findomain..."

    if [[ "${PKG}" == "pacman" ]]; then
        ${SUDO} pacman -S --needed --noconfirm findomain
        return
    fi

    export PATH="${CARGO_BIN}:${PATH}"

    local dir="${SRC_DIR}/findomain"

    if [[ -d "${dir}/.git" ]]; then
        git -C "${dir}" pull --ff-only || true
    else
        git clone https://github.com/findomain/findomain.git "${dir}"
    fi

    (cd "${dir}" && cargo build --release)

    ln -sf "${dir}/target/release/findomain" "${BIN_DIR}/findomain"
}

install_sublist3r() {
    git_venv_tool sublist3r https://github.com/aboul3la/Sublist3r.git sublist3r.py req
}

install_crtsh() {

    if wrapper_runnable crtsh; then
        log "crtsh already installed."
        return
    fi

    log "Installing crtsh..."

    local dir="${SRC_DIR}/crtsh"

    if [[ -d "${dir}/.git" ]]; then
        git -C "${dir}" pull --ff-only || true
    else
        git clone https://github.com/YashGoti/crtsh.git "${dir}"
    fi

    local source="${dir}/crtsh.py"

    if [[ ! -f "${source}" ]]; then
        warn "crtsh.py was not found at ${source}; inspect the repository layout."
        return 1
    fi

    [[ -x "${dir}/.venv/bin/python" ]] || python3 -m venv "${dir}/.venv"
    "${dir}/.venv/bin/pip" install --upgrade pip >/dev/null 2>&1 || true
    local dep_rc=0
    "${dir}/.venv/bin/pip" install requests || dep_rc=$?

    cat > "${BIN_DIR}/crtsh" <<EOF
#!/usr/bin/env bash
exec "${dir}/.venv/bin/python" "${source}" "\$@"
EOF
    chmod +x "${BIN_DIR}/crtsh"
    [[ ${dep_rc} -eq 0 ]] || { warn "crtsh: dependency install failed (pip exit ${dep_rc})."; return 1; }
}

install_shodan() { pipx_install shodan shodan; }

install_subdominator() {

    if [[ -x "${BIN_DIR}/subdominator" ]]; then
        log "subdominator already installed."
        return
    fi

    install_uv
    export PATH="${HOME}/.local/bin:${PATH}"

    if ! command -v uv >/dev/null 2>&1; then
        warn "uv was not found on PATH; skipping subdominator."
        return
    fi

    log "Installing subdominator..."

    uv tool install subdominator

    [[ -x "${HOME}/.local/bin/subdominator" ]] &&
        ln -sf "${HOME}/.local/bin/subdominator" "${BIN_DIR}/subdominator"
}

install_censys() {

    if command -v censys >/dev/null 2>&1; then
        log "Censys CLI already installed."
        return
    fi

    log "Installing Censys CLI (cencli)..."

    export PATH="/usr/local/go/bin:${GOBIN_DIR}:${CARGO_BIN}:${BIN_DIR}:${PATH}"

    go install github.com/censys/cencli/cmd/cencli@latest || {
        warn "cencli install failed; skipping."
        return
    }

    [[ -x "${GOBIN_DIR}/cencli" ]] || {
        warn "cencli did not appear in ${GOBIN_DIR}"
        return
    }

    ln -sf "${GOBIN_DIR}/cencli" "${BIN_DIR}/censys"
}

install_dnsreaper() {

    if [[ -x "${BIN_DIR}/dnsreaper" ]]; then
        log "dnsreaper already installed."
        return
    fi

    if ! command -v docker >/dev/null 2>&1; then
        warn "Docker is required for DNSReaper but was not found; skipping."
        return
    fi

    log "Pulling DNSReaper (official image: punksecurity/dnsreaper)..."

    ${SUDO} docker pull punksecurity/dnsreaper

    cat > "${BIN_DIR}/dnsreaper" <<'EOF'
#!/usr/bin/env bash
if [[ "${EUID}" -eq 0 ]]; then
    exec docker run --rm -it -v "$(pwd)":/etc/dnsreaper punksecurity/dnsreaper "$@"
else
    exec sudo docker run --rm -it -v "$(pwd)":/etc/dnsreaper punksecurity/dnsreaper "$@"
fi
EOF

    chmod +x "${BIN_DIR}/dnsreaper"
}

# ============================================================================
#  OSINT   (includes the 5 gap-closing tools)
# ============================================================================


install_trufflehog() {

    if command -v trufflehog >/dev/null 2>&1; then
        log "trufflehog already installed."
        return
    fi

    log "Installing trufflehog..."

    curl -sSfL \
        https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh |
        sh -s -- -b "${BIN_DIR}"
}

# cloud_enum: git clone + venv (README uses `uv sync`, but a venv + requirements install
# gives us the same runnable cloud_enum.py with the pattern used by our other Python tools).
install_cloud_enum() {
    git_venv_tool cloud_enum https://github.com/initstring/cloud_enum.git cloud_enum.py req
}

install_badsecrets() { pipx_install badsecrets badsecrets; }

# retire.js — npm global package. Requires Node/npm (installed as a system package above).
install_retirejs() {

    if command -v retire >/dev/null 2>&1; then
        log "retire.js already installed."
        return
    fi

    if ! command -v npm >/dev/null 2>&1; then
        warn "npm not found; cannot install retire.js. Install Node.js/npm and re-run."
        return
    fi

    log "Installing retire.js (npm -g retire)..."

    # Prefer a user-level global prefix so we don't need sudo for npm.
    npm install -g retire 2>/dev/null ||
    ${SUDO} npm install -g retire || {
        warn "npm install -g retire failed; skipping retire.js."
        return
    }

    # Link into ~/bin if npm's global bin isn't already the same as ours.
    local npm_bin
    npm_bin="$(npm bin -g 2>/dev/null || true)"
    if [[ -n "${npm_bin}" && -x "${npm_bin}/retire" ]]; then
        ln -sf "${npm_bin}/retire" "${BIN_DIR}/retire"
    fi
}

install_theharvester() {

    if [[ -x "${BIN_DIR}/theHarvester" ]] || command -v theHarvester >/dev/null 2>&1; then
        log "theHarvester already installed."
        return
    fi

    install_uv
    export PATH="${HOME}/.local/bin:${PATH}"

    log "Installing theHarvester (git clone + uv sync)..."

    local dir="${SRC_DIR}/theHarvester"
    if [[ -d "${dir}/.git" ]]; then
        git -C "${dir}" pull --ff-only || true
    else
        git clone --depth 1 https://github.com/laramies/theHarvester.git "${dir}"
    fi

    if command -v uv >/dev/null 2>&1; then
        (cd "${dir}" && uv sync) || warn "uv sync for theHarvester failed."
        cat > "${BIN_DIR}/theHarvester" <<EOF
#!/usr/bin/env bash
cd "${dir}" && exec uv run theHarvester "\$@"
EOF
        chmod +x "${BIN_DIR}/theHarvester"
    else
        warn "uv not available; skipping theHarvester."
    fi
}

install_h8mail()      { pipx_install h8mail h8mail; }
install_porch_pirate() { pipx_install porch-pirate porch-pirate; }
# dnstwist: typosquatting / look-alike domain discovery. Published on PyPI with a `dnstwist`
# console entry point, so pipx (isolated, on PATH) matches our other Python CLI tools.
install_dnstwist()    { pipx_install dnstwist dnstwist; }

# S3Scanner (sa7mon): prefer the distro apt package (simpler, no Go toolchain needed) and fall
# back to `go install` only if apt doesn't provide it. Kali ships `s3scanner`, and it's the same
# tool with the same `-bucket <name>` flag we already invoke, so the apt build is a drop-in. The
# runnable check (does `s3scanner --help` work) decides success either way.
install_s3scanner() {
    if command -v s3scanner >/dev/null 2>&1; then
        info "s3scanner already installed."
        return
    fi
    if [[ "${PKG}" == "apt" ]] && ${SUDO} apt-get install -y s3scanner 2>/dev/null \
            && command -v s3scanner >/dev/null 2>&1; then
        log "s3scanner installed from apt."
        return
    fi
    # Fallback: build from source with Go (the previous method).
    log "apt s3scanner unavailable; building from source via go install…"
    go_install s3scanner github.com/sa7mon/s3scanner
}

# gitGraber (hisxo): git clone + venv. Service-specific secret-pattern scanner (AWS/Stripe/
# Twilio/Mailgun/… regexes) — complementary to trufflehog. Ships wordlists/keywords.txt. Needs
# a config.py with GITHUB_TOKENS; Kaalyx GENERATES that at scan time from GITHUB_TOKEN (never
# committed), so install just needs the code + deps runnable.
install_gitgraber() {
    git_venv_tool gitGraber https://github.com/hisxo/gitGraber.git gitGraber.py req
}

# LeakSearch (JoelGMSec): git clone + venv + wrapper. Kaalyx invokes it as `LeakSearch`
# (capital L — matches the entry script name), querying the keyless ProxyNova/COMB dump.
install_leaksearch() {
    git_venv_tool LeakSearch https://github.com/JoelGMSec/LeakSearch.git LeakSearch.py req
}
install_git_dumper()  { pipx_install git-dumper git-dumper; }

# SwaggerSpy: git clone + venv + wrapper (swaggerspy.py). Kaalyx invokes it as `swaggerspy`.
install_swaggerspy() {
    git_venv_tool swaggerspy https://github.com/UndeadSec/SwaggerSpy.git swaggerspy.py req
}

# gato (GitHub Attack Toolkit) — git clone + venv + `pip install .`. Repo is archived
# (superseded by Trajan) but still functional; Kaalyx uses it for the Actions audit.
install_gato() {

    if wrapper_runnable gato; then
        info "gato already installed."
        return
    fi

    log "Installing gato (GitHub Actions audit)..."

    local dir="${SRC_DIR}/gato"
    if [[ -d "${dir}/.git" ]]; then
        git -C "${dir}" pull --ff-only || true
    else
        git clone --depth 1 https://github.com/praetorian-inc/gato.git "${dir}"
    fi

    [[ -x "${dir}/.venv/bin/python" ]] || python3 -m venv "${dir}/.venv"
    "${dir}/.venv/bin/pip" install --upgrade pip setuptools wheel >/dev/null 2>&1 || true
    "${dir}/.venv/bin/pip" install "${dir}" || { warn "gato pip install failed."; return 1; }

    if [[ -x "${dir}/.venv/bin/gato" ]]; then
        ln -sf "${dir}/.venv/bin/gato" "${BIN_DIR}/gato"
    fi
    wrapper_runnable gato || { warn "gato installed but does not run cleanly."; return 1; }
}

# msftrecon (Arcanum-Sec) — git clone + venv + wrapper (msftrecon.py).
install_msftrecon() {
    git_venv_tool msftrecon https://github.com/Arcanum-Sec/msftrecon.git msftrecon.py req
}

# Spoofy (MattKeeley) — git clone + venv + wrapper (spoofy.py).
install_spoofy() {
    git_venv_tool spoofy https://github.com/MattKeeley/Spoofy.git spoofy.py req
}

# ============================================================================
#  Hosts
# ============================================================================

install_wafw00f() { pipx_install wafw00f wafw00f; }

# ============================================================================
#  Web analysis
# ============================================================================


install_uro() { pipx_install uro uro; }

install_secretfinder() {
    git_venv_tool secretfinder https://github.com/m4ll0k/SecretFinder.git SecretFinder.py req
}

install_gf_patterns() {

    local patterns="${HOME}/.gf"

    if [[ -d "${patterns}/.git" ]]; then
        log "Updating gf patterns..."
        git -C "${patterns}" pull --ff-only || true
        return
    fi

    if [[ -d "${patterns}" ]] && [[ -n "$(ls -A "${patterns}" 2>/dev/null)" ]]; then
        info "${patterns} already exists and is not empty; assuming gf patterns are in place."
        return
    fi

    mkdir -p "${patterns}"

    log "Installing gf patterns (github.com/1ndianl33t/Gf-Patterns)..."

    git clone https://github.com/1ndianl33t/Gf-Patterns.git "${patterns}"
}

# ============================================================================
#  Vulnerability checks
# ============================================================================


install_sqlmap() {

    if [[ -x "${BIN_DIR}/sqlmap" ]]; then
        log "sqlmap already installed."
        return
    fi

    log "Installing sqlmap..."

    local dir="${SRC_DIR}/sqlmap"

    if [[ -d "${dir}/.git" ]]; then
        git -C "${dir}" pull --ff-only || true
    else
        git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "${dir}"
    fi

    cat > "${BIN_DIR}/sqlmap" <<EOF
#!/usr/bin/env bash
exec python3 "${dir}/sqlmap.py" "\$@"
EOF

    chmod +x "${BIN_DIR}/sqlmap"
}

install_sstimap() {
    git_venv_tool sstimap https://github.com/vladko312/SSTImap.git sstimap.py req
}

install_corsy() {

    if wrapper_runnable corsy; then
        log "Corsy already installed."
        return
    fi

    log "Installing Corsy..."

    local dir="${SRC_DIR}/Corsy"

    if [[ -d "${dir}/.git" ]]; then
        git -C "${dir}" pull --ff-only || true
    else
        git clone https://github.com/s0md3v/Corsy.git "${dir}"
    fi

    [[ -x "${dir}/.venv/bin/python" ]] || python3 -m venv "${dir}/.venv"
    "${dir}/.venv/bin/pip" install --upgrade pip >/dev/null 2>&1 || true

    local dep_rc=0
    if [[ -f "${dir}/requirements.txt" ]]; then
        "${dir}/.venv/bin/pip" install -r "${dir}/requirements.txt" || dep_rc=$?
    else
        "${dir}/.venv/bin/pip" install requests || dep_rc=$?
    fi

    cat > "${BIN_DIR}/corsy" <<EOF
#!/usr/bin/env bash
exec "${dir}/.venv/bin/python" "${dir}/corsy.py" "\$@"
EOF
    chmod +x "${BIN_DIR}/corsy"
    [[ ${dep_rc} -eq 0 ]] || { warn "corsy: dependency install failed (pip exit ${dep_rc})."; return 1; }
}

install_oralyzer() { pipx_install "git+https://github.com/r0075h3ll/Oralyzer.git" oralyzer; }

update_nuclei_templates() {

    export PATH="${GOBIN_DIR}:${BIN_DIR}:${PATH}"

    if command -v nuclei >/dev/null 2>&1; then
        run_quiet "Nuclei templates: updated" nuclei -update-templates
    fi
}

# ============================================================================
#  Run the selected stages
# ============================================================================

# anew is a shared plumbing tool used across stages; install it up front (not counted).
go_install anew github.com/tomnomnom/anew

# ============================================================================
#  Method-grouped install manifest
#
#  Tools are installed in three categorised, separately-counted groups by INSTALL METHOD —
#  Go tools, Python/pip tools, and cloned repositories — rather than one flat list. Each
#  manifest row is:  <stages>|<method>|<name>|<install-cmd...>
#    stages : comma list (osint,subdomains,hosts,web,vuln) — row runs if any is selected
#    method : go | py | repo
#    name   : the resulting binary/command on PATH
#    rest   : the install invocation (a go_install/pipx-backed helper/git helper call)
#  A tool needed by several stages appears once; dedup keeps it from installing twice.
# ============================================================================
MANIFEST=(
  # --- Go tools ---
  "subdomains|go|subfinder|go_install subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
  "subdomains|go|assetfinder|go_install assetfinder github.com/tomnomnom/assetfinder"
  "subdomains|go|chaos|go_install chaos github.com/projectdiscovery/chaos-client/cmd/chaos"
  "subdomains,osint|go|dnsx|go_install dnsx github.com/projectdiscovery/dnsx/cmd/dnsx"
  "subdomains|go|puredns|go_install puredns github.com/d3mondev/puredns/v2"
  "subdomains|go|alterx|go_install alterx github.com/projectdiscovery/alterx/cmd/alterx"
  "subdomains,osint|go|github-subdomains|go_install github-subdomains github.com/gwen001/github-subdomains"
  "osint|go|misconfig-mapper|go_install misconfig-mapper github.com/intigriti/misconfig-mapper/cmd/misconfig-mapper"
  "hosts|go|naabu|go_install naabu github.com/projectdiscovery/naabu/v2/cmd/naabu"
  "hosts|go|httpx|go_install httpx github.com/projectdiscovery/httpx/cmd/httpx"
  "web|go|gowitness|go_install gowitness github.com/sensepost/gowitness"
  "web|go|gau|go_install gau github.com/lc/gau/v2/cmd/gau"
  "web|go|waybackurls|go_install waybackurls github.com/tomnomnom/waybackurls"
  "web|go|katana|go_install katana github.com/projectdiscovery/katana/cmd/katana"
  "web|go|gospider|go_install gospider github.com/jaeles-project/gospider"
  "web|go|gf|go_install gf github.com/tomnomnom/gf"
  "vuln|go|kxss|go_install kxss github.com/Emoe/kxss"
  "vuln|go|dalfox|go_install dalfox github.com/hahwul/dalfox/v2"
  "vuln|go|nuclei|go_install nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
  "vuln|go|interactsh-client|go_install interactsh-client github.com/projectdiscovery/interactsh/cmd/interactsh-client"
  # --- Python / pip tools ---
  "osint|py|badsecrets|install_badsecrets"
  "osint|py|h8mail|install_h8mail"
  "osint|py|porch-pirate|install_porch_pirate"
  "osint|py|theHarvester|install_theharvester"
  "osint|py|retire|install_retirejs"
  "osint|py|dnstwist|install_dnstwist"
  "subdomains|py|shodan|install_shodan"
  "subdomains|py|subdominator|install_subdominator"
  "subdomains|py|censys|install_censys"
  "hosts|py|wafw00f|install_wafw00f"
  "web|py|uro|install_uro"
  "vuln|py|corsy|install_corsy"
  "vuln|py|oralyzer|install_oralyzer"
  # --- Repositories (git clone + venv/wrapper, or image pull) ---
  "osint|repo|trufflehog|install_trufflehog"
  "osint,web|repo|trufflehog|install_trufflehog"
  "osint|repo|cloud_enum|install_cloud_enum"
  "osint|repo|s3scanner|install_s3scanner"
  "osint|repo|gitgraber|install_gitgraber"
  "osint|repo|LeakSearch|install_leaksearch"
  "osint|repo|swaggerspy|install_swaggerspy"
  "osint|repo|gato|install_gato"
  "subdomains|repo|massdns|install_massdns"
  "subdomains|repo|findomain|install_findomain"
  "subdomains|repo|sublist3r|install_sublist3r"
  "subdomains|repo|crtsh|install_crtsh"
  "subdomains|repo|dnsreaper|install_dnsreaper"
  "web|repo|secretfinder|install_secretfinder"
  "vuln|repo|sqlmap|install_sqlmap"
  "vuln|repo|sstimap|install_sstimap"
)

# manifest_selected <method> -> emit "name<TAB>cmd..." rows for the given method whose stages
# intersect the selected STAGES, de-duplicated by tool name (first occurrence wins).
manifest_selected() {
    local want_method="$1" seen="" row stages method name rest p hit
    for row in "${MANIFEST[@]}"; do
        IFS='|' read -r stages method name rest <<<"${row}"
        [[ "${method}" == "${want_method}" ]] || continue
        [[ ",${seen}," == *",${name},"* ]] && continue
        hit=0
        IFS=',' read -ra _ph <<<"${stages}"
        for p in "${_ph[@]}"; do want_stage "${p}" && { hit=1; break; }; done
        [[ "${hit}" -eq 1 ]] || continue
        seen="${seen},${name}"
        printf '%s\t%s\n' "${name}" "${rest}"
    done
}

# install_group <method> <label> <ok_verb> — one categorised, counted install pass.
install_group() {
    local method="$1" label="$2" ok_verb="$3"
    local -a rows=()
    local line
    while IFS= read -r line; do [[ -n "${line}" ]] && rows+=("${line}"); done < <(manifest_selected "${method}")
    local total="${#rows[@]}"
    [[ "${total}" -gt 0 ]] || return 0
    stage_header "Installing ${label} (${total})"
    begin_category "${label}" "${total}"
    local name cmd
    for line in "${rows[@]}"; do
        name="${line%%$'\t'*}"; cmd="${line#*$'\t'}"
        # shellcheck disable=SC2086
        run_tool "${name}" "${ok_verb}" ${cmd}
    done
}

install_group go   "Go tools"     "installed"
install_group py   "Python tools" "ready"
install_group repo "Repositories" "ready"

# Supporting side-steps that aren't counted tools (a headless browser for screenshots, the gf
# pattern set, and the nuclei template DB refresh). Run only for the stages that need them.
if want_stage web;  then try install_chromium; try install_gf_patterns; fi
if want_stage vuln; then try update_nuclei_templates; fi

# ============================================================================
#  httpx name-collision guard (Python httpx CLI vs ProjectDiscovery httpx)
# ============================================================================

resolve_httpx_conflict() {

    local go_httpx="${GOBIN_DIR}/httpx"

    [[ -x "${go_httpx}" ]] || return

    local go_httpx_real
    go_httpx_real="$(readlink -f "${go_httpx}")"

    local dir candidate real moved
    moved=0

    local saved_ifs="${IFS}"
    IFS=':'
    for dir in ${PATH}; do
        IFS="${saved_ifs}"

        [[ -n "${dir}" ]] || continue
        candidate="${dir}/httpx"
        [[ -x "${candidate}" ]] || continue

        real="$(readlink -f "${candidate}" 2>/dev/null || echo "${candidate}")"
        [[ "${real}" == "${go_httpx_real}" ]] && continue

        if head -c2 "${candidate}" 2>/dev/null | grep -q '#!'; then
            warn "Found a conflicting 'httpx' at ${candidate} (Python httpx CLI) ahead of ProjectDiscovery's on PATH; renaming to ${candidate}-pypi."
            mv -f "${candidate}" "${candidate}-pypi"
            moved=1
        else
            warn "Found an unrecognized 'httpx' at ${candidate} on PATH; leaving it — check manually if 'httpx' still misbehaves."
        fi

        IFS=':'
    done
    IFS="${saved_ifs}"

    hash -r 2>/dev/null || true
}

if want_stage hosts; then try resolve_httpx_conflict; fi

# ============================================================================
#  Publish everything to /usr/local/bin
# ============================================================================

publish_to_usr_local_bin() {

    log "Publishing installed tools to /usr/local/bin..."

    local f name target

    for f in "${BIN_DIR}"/* "${CARGO_BIN}"/*; do
        [[ -e "${f}" ]] || continue
        name="$(basename "${f}")"
        target="$(readlink -f "${f}")"
        [[ -x "${target}" ]] || continue
        ${SUDO} ln -sf "${target}" "/usr/local/bin/${name}"
    done

    for f in go gofmt; do
        if [[ -x "/usr/local/go/bin/${f}" ]]; then
            ${SUDO} ln -sf "/usr/local/go/bin/${f}" "/usr/local/bin/${f}"
        fi
    done
}

try publish_to_usr_local_bin

if command -v docker >/dev/null 2>&1; then
    ${SUDO} usermod -aG docker "${USER}" 2>/dev/null || true
fi

export PATH="${HOME}/.local/bin:/usr/local/go/bin:${GOBIN_DIR}:${CARGO_BIN}:${BIN_DIR}:${PATH}"

# ============================================================================
#  Tool Installation Summary — per-category OK / skipped / failed counts
# ============================================================================

print_summary() {
    printf '\n%s%s--- Tool Installation Summary ---%s\n' "${C_BOLD}" "${C_CYAN}" "${C_NC}"
    local cat present okc
    for cat in "Go tools" "Python tools" "Repositories"; do
        [[ -n "${_CAT_TOTAL[${cat}]:-}" ]] || continue   # only categories that actually ran
        present="${_CAT_PRESENT[${cat}]:-0}"
        okc=$(( ${_CAT_OK[${cat}]:-0} + present ))       # OK = freshly installed + already present
        printf '  %-20s %s%d OK%s (%d already installed), %s%d skipped%s, %s%d failed%s (of %d)\n' \
            "${cat}:" \
            "${C_GREEN}"  "${okc}"                    "${C_NC}" "${present}" \
            "${C_YELLOW}" "${_CAT_SKIP[${cat}]:-0}"   "${C_NC}" \
            "${C_RED}"    "${_CAT_FAIL[${cat}]:-0}"   "${C_NC}" \
            "${_CAT_TOTAL[${cat}]:-0}"
    done
}

print_apikey_reminder() {
    printf '\n%s%sRemember to set your API keys%s in %s~/.config/kaalyx/config.env%s:\n' \
        "${C_BOLD}" "${C_CYAN}" "${C_NC}" "${C_BOLD}" "${C_NC}"
    printf '  %sGITHUB_TOKEN%s      github-subdomains, trufflehog, GitHub Actions audit, org discovery\n' "${C_YELLOW}" "${C_NC}"
    printf '  %sSHODAN_API_KEY%s    Shodan subdomain / host search\n' "${C_YELLOW}" "${C_NC}"
    printf '  %sCENSYS_API_ID%s     Censys subdomain search (+ CENSYS_API_SECRET)\n' "${C_YELLOW}" "${C_NC}"
    printf '  %sCHAOS_API_KEY%s     ProjectDiscovery Chaos dataset\n' "${C_YELLOW}" "${C_NC}"
    printf '  %sIPINFO_TOKEN%s      IP geolocation / ASN (host stage)\n' "${C_YELLOW}" "${C_NC}"
    printf '  %sTELEGRAM_BOT_TOKEN%s  scan alerts (+ TELEGRAM_CHAT_ID)\n' "${C_YELLOW}" "${C_NC}"
    printf '  %sH8MAIL_CONFIG / BREACH_COMP_PATH / LOCAL_BREACH_PATH%s  optional: h8mail leaked-credential recovery\n' "${C_DIM}" "${C_NC}"
    printf '  %sMissing keys simply disable their source — Kaalyx never crashes for an absent key.%s\n' "${C_DIM}" "${C_NC}"
}

print_summary
print_apikey_reminder

cat <<EOF

Install paths:  src=${SRC_DIR}  go=${GOBIN_DIR}  cargo=${CARGO_BIN}  bin=${BIN_DIR}

Install Kaalyx itself (from the project root):  pipx install .   then:  kaalyx scan example.com
Start a new shell so PATH changes take effect:  exec zsh   (or: exec bash)
Use the installed tools only against systems you own or are authorised to assess.
EOF

if [[ "${EUID}" -ne 0 ]]; then
    printf '%sDocker group change may need a re-login; dnsreaper falls back to sudo until then.%s\n' \
        "${C_DIM}" "${C_NC}"
fi

printf '\n%s%sFinished!%s\n' "${C_BOLD}" "${C_GREEN}" "${C_NC}"
printf '%s────────────────────────────────────────────────────────────%s\n' "${C_GREEN}" "${C_NC}"
