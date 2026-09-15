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

mkdir -p "${BIN_DIR}" "${SRC_DIR}" "${GOBIN_DIR}"

export GOPATH="${HOME}/go"
export GOBIN="${GOBIN_DIR}"
export PATH="${BIN_DIR}:${GOBIN_DIR}:${CARGO_BIN}:${PATH}"

# --- Colors (single source of truth; consistent with Kaalyx's rich palette) ---------------
#   art=red  tagline=yellow  author=dim   phase headers=bold cyan
#   success=green  skipped=yellow  failed=red   Finished!=bold green
C_RED=$'\033[0;31m';  C_GREEN=$'\033[0;32m'; C_YELLOW=$'\033[0;33m'
C_CYAN=$'\033[0;36m'; C_DIM=$'\033[2m';       C_BOLD=$'\033[1m'; C_NC=$'\033[0m'

log()  { printf '\n\033[1;32m[+]\033[0m %s\n' "$1"; }
info() { printf '\033[1;36m[*]\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$1"; }
fail() { printf '\033[1;31m[-]\033[0m %s\n' "$1"; exit 1; }

# ReconFTW-style phase header: "Running: <phase>" in bold cyan.
phase() { printf '\n%s%sRunning: %s%s\n' "${C_BOLD}" "${C_CYAN}" "$1" "${C_NC}"; }

# --- Per-tool progress counters + category tallies -----------------------------------------
# Each install phase resets the counter, sets a total, then calls tool_step for every tool.
# Results roll up into per-category OK/skipped/failed tallies printed in the final summary.
_STEP_i=0          # current index within the active category
_STEP_total=0      # total tools in the active category (shown as [i/total])
declare -A _CAT_OK _CAT_SKIP _CAT_FAIL _CAT_TOTAL

begin_category() {  # begin_category <label> <total>
    _CAT_LABEL="$1"; _STEP_total="$2"; _STEP_i=0
    _CAT_OK["$1"]=0; _CAT_SKIP["$1"]=0; _CAT_FAIL["$1"]=0; _CAT_TOTAL["$1"]="$2"
}

# tool_step <name> <ok|skipped|failed> — print "[i/total] name <status>" in the right color.
tool_step() {
    local name="$1" status="$2"
    _STEP_i=$((_STEP_i + 1))
    case "${status}" in
        ok)      _CAT_OK["${_CAT_LABEL}"]=$(( ${_CAT_OK["${_CAT_LABEL}"]} + 1 ))
                 printf '  [%d/%d] %s %sinstalled%s\n' "${_STEP_i}" "${_STEP_total}" "${name}" "${C_GREEN}" "${C_NC}" ;;
        skipped) _CAT_SKIP["${_CAT_LABEL}"]=$(( ${_CAT_SKIP["${_CAT_LABEL}"]} + 1 ))
                 printf '  [%d/%d] %s %sskipped%s\n' "${_STEP_i}" "${_STEP_total}" "${name}" "${C_YELLOW}" "${C_NC}" ;;
        *)       _CAT_FAIL["${_CAT_LABEL}"]=$(( ${_CAT_FAIL["${_CAT_LABEL}"]} + 1 ))
                 printf '  [%d/%d] %s %sfailed%s\n' "${_STEP_i}" "${_STEP_total}" "${name}" "${C_RED}" "${C_NC}" ;;
    esac
}

# run_tool <name> <command...> — run an install command, classify the outcome, count it.
# "skipped" = the tool is already present (nothing to do); "ok" = command succeeded;
# "failed" = command returned non-zero. Never aborts the run (mirrors `try`).
run_tool() {
    local name="$1"; shift
    if command -v "${name}" >/dev/null 2>&1; then
        tool_step "${name}" skipped
        return 0
    fi
    if "$@" >/dev/null 2>&1 && command -v "${name}" >/dev/null 2>&1; then
        tool_step "${name}" ok
    else
        tool_step "${name}" failed
    fi
}

# Network connectivity precheck — one clear "Network OK" / failure line before any install.
network_precheck() {
    phase "Network precheck"
    local host
    for host in github.com raw.githubusercontent.com; do
        if curl -fsS --max-time 8 -o /dev/null "https://${host}" 2>/dev/null; then
            printf '  %sNetwork OK%s (reached %s)\n' "${C_GREEN}" "${C_NC}" "${host}"
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

# Build/version line, ReconFTW-style: "main-v1.0.0-<short-sha>". The sha is best-effort from
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
    # Art in red, tagline in yellow, author dim — same palette as the main Kaalyx banner.
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
    printf '    %s%s%s\n' "${C_YELLOW}" "Automated Recon & Vulnerability Engine" "${C_NC}"
    printf '    %s%s  ·  Author: who0xac%s\n' "${C_DIM}" "$(build_version)" "${C_NC}"
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
        --install       Run the full install (all phases). Default behaviour.
        --all           Alias for --install.

INSTALL A SINGLE PHASE ONLY
        --osint-only        Tools for Part 1 — OSINT.
        --subdomains-only   Tools for Part 2 — Subdomain enumeration.
        --hosts-only        Tools for Part 3 — Host / port / service analysis.
        --web-only          Tools for Part 4 — Web analysis / URL collection.
        --vuln-only         Tools for Part 5 — Vulnerability checks.

    Phase installs still install the shared foundation first (system packages,
    Go, Rust, Docker as needed) so the phase tools can build.

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
#  Argument parsing — decide the run MODE and which PHASES to install
# ============================================================================

MODE="install"            # install | check
declare -a PHASES=()      # empty => all phases

parse_args() {
    if [[ $# -eq 0 ]]; then
        PHASES=(osint subdomains hosts web vuln)
        return
    fi
    case "$1" in
        -h|--help)          print_help; exit 0 ;;
        --check)            MODE="check"; PHASES=(osint subdomains hosts web vuln) ;;
        --install|--all)    PHASES=(osint subdomains hosts web vuln) ;;
        --osint-only)       PHASES=(osint) ;;
        --subdomains-only)  PHASES=(subdomains) ;;
        --hosts-only)       PHASES=(hosts) ;;
        --web-only)         PHASES=(web) ;;
        --vuln-only)        PHASES=(vuln) ;;
        *)                  warn "Unknown option: $1"; print_help; exit 2 ;;
    esac
}

want_phase() {
    local phase="$1"
    local p
    for p in "${PHASES[@]}"; do
        [[ "${p}" == "${phase}" ]] && return 0
    done
    return 1
}

parse_args "$@"

# ============================================================================
#  Phase → tool mapping (for --check and for the per-phase verification report).
#  Kept in sync with the tools each pipeline phase actually invokes.
# ============================================================================

# Part 1 — OSINT (final spec incl. the 5 gap-closing additions).
OSINT_TOOLS=(
    whois dnsx github-subdomains trufflehog cloud_enum s3scanner badsecrets
    retire theHarvester misconfig-mapper h8mail porch-pirate swaggerspy gato
    git-dumper msftrecon spoofy
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
    want_phase osint      && out+=("${OSINT_TOOLS[@]}")
    want_phase subdomains && out+=("${SUBDOMAIN_TOOLS[@]}")
    want_phase hosts      && out+=("${HOST_TOOLS[@]}")
    want_phase web        && out+=("${WEB_TOOLS[@]}")
    want_phase vuln       && out+=("${VULN_TOOLS[@]}")
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
    echo "     phases: ${PHASES[*]}"
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
    echo "Run without --check (or with a phase flag) to install the missing tools."
    exit 0
}

if [[ "${MODE}" == "check" ]]; then
    run_check
fi

# ============================================================================
#  From here down: actual installation.
# ============================================================================

print_banner

phase "Install/Update"
printf '  phases: %s%s%s\n' "${C_CYAN}" "${PHASES[*]}" "${C_NC}"

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

install_system_packages

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

install_go

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

# Rust is only needed to build findomain from source (a subdomain-phase tool).
# Skip it entirely for phase installs that don't need it, to save time.
if want_phase subdomains; then
    install_rust
else
    info "Skipping Rust toolchain (no selected phase needs a cargo build)."
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

install_docker

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
git_venv_tool() {
    local name="$1" repo="$2" entry="$3" req="${4:-}"

    if [[ -x "${BIN_DIR}/${name}" ]]; then
        info "${name} already installed."
        return
    fi

    log "Installing ${name}..."

    local dir="${SRC_DIR}/${name}"
    if [[ -d "${dir}/.git" ]]; then
        git -C "${dir}" pull --ff-only || true
    else
        git clone --depth 1 "${repo}" "${dir}"
    fi

    python3 -m venv "${dir}/.venv"
    "${dir}/.venv/bin/pip" install --upgrade pip setuptools wheel

    if [[ "${req}" == "req" && -f "${dir}/requirements.txt" ]]; then
        "${dir}/.venv/bin/pip" install -r "${dir}/requirements.txt" || true
    elif [[ "${req}" == "self" ]]; then
        "${dir}/.venv/bin/pip" install "${dir}" || true
    elif [[ -n "${req}" ]]; then
        # shellcheck disable=SC2086
        "${dir}/.venv/bin/pip" install ${req} || true
    fi

    cat > "${BIN_DIR}/${name}" <<EOF
#!/usr/bin/env bash
exec "${dir}/.venv/bin/python" "${dir}/${entry}" "\$@"
EOF
    chmod +x "${BIN_DIR}/${name}"
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
#  PHASE 2 — Subdomains
# ============================================================================

install_phase_subdomains() {
    phase "Installing Part 2 — Subdomain tools (15)"
    begin_category "Subdomain tools" 15

    run_tool massdns          install_massdns
    run_tool subfinder        go_install subfinder         github.com/projectdiscovery/subfinder/v2/cmd/subfinder
    run_tool assetfinder      go_install assetfinder       github.com/tomnomnom/assetfinder
    run_tool chaos            go_install chaos             github.com/projectdiscovery/chaos-client/cmd/chaos
    run_tool dnsx             go_install dnsx              github.com/projectdiscovery/dnsx/cmd/dnsx
    run_tool puredns          go_install puredns           github.com/d3mondev/puredns/v2
    run_tool alterx           go_install alterx            github.com/projectdiscovery/alterx/cmd/alterx
    run_tool github-subdomains go_install github-subdomains github.com/gwen001/github-subdomains
    run_tool findomain        install_findomain
    run_tool sublist3r        install_sublist3r
    run_tool crtsh            install_crtsh
    run_tool shodan           install_shodan
    run_tool subdominator     install_subdominator
    run_tool censys           install_censys
    run_tool dnsreaper        install_dnsreaper
}

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

    if [[ -x "${BIN_DIR}/crtsh" ]]; then
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
        return
    fi

    python3 -m venv "${dir}/.venv"
    "${dir}/.venv/bin/pip" install --upgrade pip
    "${dir}/.venv/bin/pip" install requests

    cat > "${BIN_DIR}/crtsh" <<EOF
#!/usr/bin/env bash
exec "${dir}/.venv/bin/python" "${source}" "\$@"
EOF

    chmod +x "${BIN_DIR}/crtsh"
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
#  PHASE 1 — OSINT   (includes the 5 gap-closing tools)
# ============================================================================

install_phase_osint() {
    phase "Installing Part 1 — OSINT tools (14)"
    begin_category "OSINT tools" 14

    # whois + dnsutils come from system packages; dnsx/github-subdomains are Go tools.
    run_tool dnsx              go_install dnsx              github.com/projectdiscovery/dnsx/cmd/dnsx
    run_tool github-subdomains go_install github-subdomains github.com/gwen001/github-subdomains
    run_tool misconfig-mapper  go_install misconfig-mapper  github.com/intigriti/misconfig-mapper/cmd/misconfig-mapper
    run_tool trufflehog        install_trufflehog
    run_tool cloud_enum        install_cloud_enum
    run_tool s3scanner         go_install s3scanner         github.com/sa7mon/s3scanner
    run_tool badsecrets        install_badsecrets
    run_tool retire            install_retirejs
    run_tool theHarvester      install_theharvester
    run_tool h8mail            install_h8mail
    run_tool LeakSearch        install_leaksearch
    run_tool porch-pirate      install_porch_pirate
    run_tool swaggerspy        install_swaggerspy
    run_tool gato              install_gato
}

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

    if command -v gato >/dev/null 2>&1 || [[ -x "${BIN_DIR}/gato" ]]; then
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

    python3 -m venv "${dir}/.venv"
    "${dir}/.venv/bin/pip" install --upgrade pip setuptools wheel
    "${dir}/.venv/bin/pip" install "${dir}" || { warn "gato pip install failed."; return; }

    if [[ -x "${dir}/.venv/bin/gato" ]]; then
        ln -sf "${dir}/.venv/bin/gato" "${BIN_DIR}/gato"
    fi
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
#  PHASE 3 — Hosts
# ============================================================================

install_phase_hosts() {
    phase "Installing Part 3 — Host tools (3)"
    begin_category "Host tools" 3
    # nmap comes from system packages.
    run_tool naabu   go_install naabu github.com/projectdiscovery/naabu/v2/cmd/naabu
    run_tool httpx   go_install httpx github.com/projectdiscovery/httpx/cmd/httpx
    run_tool wafw00f install_wafw00f
}

install_wafw00f() { pipx_install wafw00f wafw00f; }

# ============================================================================
#  PHASE 4 — Web analysis
# ============================================================================

install_phase_web() {
    phase "Installing Part 4 — Web analysis tools (9)"
    begin_category "Web tools" 9

    try install_chromium   # gowitness screenshots (not a counted tool)

    run_tool gowitness    go_install gowitness   github.com/sensepost/gowitness
    run_tool gau          go_install gau         github.com/lc/gau/v2/cmd/gau
    run_tool waybackurls  go_install waybackurls github.com/tomnomnom/waybackurls
    run_tool katana       go_install katana      github.com/projectdiscovery/katana/cmd/katana
    run_tool gospider     go_install gospider    github.com/jaeles-project/gospider
    run_tool gf           go_install gf          github.com/tomnomnom/gf
    run_tool uro          install_uro
    run_tool secretfinder install_secretfinder
    run_tool trufflehog   install_trufflehog     # also used in web JS/secret analysis
    try install_gf_patterns   # gf pattern set (a ~/.gf dir, not a PATH binary — not counted)
}

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
#  PHASE 5 — Vulnerability checks
# ============================================================================

install_phase_vuln() {
    phase "Installing Part 5 — Vulnerability tools (8)"
    begin_category "Vulnerability tools" 8

    run_tool kxss              go_install kxss              github.com/Emoe/kxss
    run_tool dalfox            go_install dalfox            github.com/hahwul/dalfox/v2
    run_tool nuclei            go_install nuclei            github.com/projectdiscovery/nuclei/v3/cmd/nuclei
    run_tool interactsh-client go_install interactsh-client github.com/projectdiscovery/interactsh/cmd/interactsh-client
    run_tool sqlmap           install_sqlmap
    run_tool sstimap          install_sstimap
    run_tool corsy            install_corsy
    run_tool oralyzer         install_oralyzer
    try update_nuclei_templates   # refreshes nuclei's template DB (not a counted tool)
}

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

    if [[ -x "${BIN_DIR}/corsy" ]]; then
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

    python3 -m venv "${dir}/.venv"
    "${dir}/.venv/bin/pip" install --upgrade pip

    if [[ -f "${dir}/requirements.txt" ]]; then
        "${dir}/.venv/bin/pip" install -r "${dir}/requirements.txt"
    else
        "${dir}/.venv/bin/pip" install requests
    fi

    cat > "${BIN_DIR}/corsy" <<EOF
#!/usr/bin/env bash
exec "${dir}/.venv/bin/python" "${dir}/corsy.py" "\$@"
EOF

    chmod +x "${BIN_DIR}/corsy"
}

install_oralyzer() { pipx_install "git+https://github.com/r0075h3ll/Oralyzer.git" oralyzer; }

update_nuclei_templates() {

    export PATH="${GOBIN_DIR}:${BIN_DIR}:${PATH}"

    if command -v nuclei >/dev/null 2>&1; then
        log "Updating Nuclei templates..."
        nuclei -update-templates || warn "Nuclei template update failed."
    fi
}

# ============================================================================
#  Run the selected phases
# ============================================================================

# anew is a shared plumbing tool used across phases; install it up front.
go_install anew github.com/tomnomnom/anew

# Explicit `if` blocks (not `&&`) so a non-selected phase's false `want_phase` does not
# trip `set -e`.
if want_phase subdomains; then install_phase_subdomains; fi
if want_phase osint;      then install_phase_osint;      fi
if want_phase hosts;      then install_phase_hosts;      fi
if want_phase web;        then install_phase_web;        fi
if want_phase vuln;       then install_phase_vuln;       fi

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

if want_phase hosts; then try resolve_httpx_conflict; fi

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
    local cat
    for cat in "OSINT tools" "Subdomain tools" "Host tools" "Web tools" "Vulnerability tools"; do
        [[ -n "${_CAT_TOTAL[${cat}]:-}" ]] || continue   # only categories that actually ran
        printf '  %-20s %s%d OK%s, %s%d skipped%s, %s%d failed%s (of %d)\n' \
            "${cat}:" \
            "${C_GREEN}"  "${_CAT_OK[${cat}]:-0}"   "${C_NC}" \
            "${C_YELLOW}" "${_CAT_SKIP[${cat}]:-0}" "${C_NC}" \
            "${C_RED}"    "${_CAT_FAIL[${cat}]:-0}" "${C_NC}" \
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
