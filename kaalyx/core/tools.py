"""Tool registry — the single source of truth for the external tools Kaalyx drives.

Each tool is declared once as a :class:`ToolSpec`: the executable name (as it appears on
PATH), the pipeline part it belongs to, whether it needs a special runtime (Docker), and
any per-tool timeout override. Stages look tools up by key rather than hard-coding
executable names, which gives us one place to:

* check availability at scan start and warn about missing tools,
* group tools by pipeline part for the pre-flight report,
* record which tools are Docker-based or require an API key.

The registry does **not** hold full argv templates — argument construction is
tool-specific and lives in each stage, close to where the output is parsed. What lives
here is the stable metadata every stage and the pre-flight check share.

Kaalyx never installs these tools; it assumes they are on PATH at runtime.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from enum import Enum


class Part(str, Enum):
    """The pipeline part a tool belongs to (for grouping / reporting)."""

    OSINT = "osint"
    SUBDOMAINS = "subdomains"
    HOSTS = "hosts"
    WEB = "web"
    VULNS = "vulns"
    INFRA = "infra"  # cross-cutting (interactsh-client, docker, etc.)


@dataclass(frozen=True)
class ToolSpec:
    """Metadata describing one external tool.

    Attributes:
        key: Stable identifier used in code (e.g. ``"subfinder"``).
        executable: Name resolved on PATH. Defaults to ``key`` when they match.
        part: Which pipeline part the tool serves.
        description: One-line human description.
        docker: True if the tool runs via Docker (e.g. DNS Reaper).
        requires_secret: Name of the secret/env the tool needs, if any.
        timeout: Per-tool timeout override in seconds (``None`` = use the global default).
    """

    key: str
    part: Part
    description: str = ""
    executable: str | None = None
    docker: bool = False
    requires_secret: str | None = None
    timeout: int | None = None

    @property
    def exe(self) -> str:
        return self.executable or self.key

    def available(self) -> bool:
        """True if the tool's executable (or ``docker`` for Docker tools) is on PATH."""
        target = "docker" if self.docker else self.exe
        return shutil.which(target) is not None


# --------------------------------------------------------------------------------------
# The registry. Grouped by pipeline part.
# --------------------------------------------------------------------------------------

_SPECS: list[ToolSpec] = [
    # --- Part 1: OSINT ---
    ToolSpec("whois", Part.OSINT, "WHOIS registration lookup"),
    ToolSpec("dnsx", Part.OSINT, "DNS record resolution (projectdiscovery)"),
    ToolSpec("github-subdomains", Part.OSINT, "Subdomains from GitHub code search",
             requires_secret="GITHUB_TOKEN"),
    ToolSpec("trufflehog", Part.OSINT, "Secret scanning (GitHub org / filesystem)"),
    ToolSpec("cloud_enum", Part.OSINT, "Multi-cloud resource enumeration"),
    ToolSpec("s3scanner", Part.OSINT, "S3 bucket discovery / misconfig"),
    ToolSpec("badsecrets", Part.OSINT, "Known-secret / crypto misconfig detection"),
    ToolSpec("retire", Part.OSINT, "retire.js — vulnerable JS library detection",
             executable="retire"),
    ToolSpec("theHarvester", Part.OSINT, "Emails / employees / hosts harvesting",
             executable="theHarvester"),
    ToolSpec("misconfig-mapper", Part.OSINT, "Third-party SaaS misconfig checks"),
    ToolSpec("h8mail", Part.OSINT, "Email breach/credential lookup (needs keys)"),
    ToolSpec("leaksearch", Part.OSINT, "Leaked-credential search (ProxyNova/COMB dump)",
             executable="LeakSearch"),
    ToolSpec("porch-pirate", Part.OSINT, "Public Postman workspace/API-leak search"),
    ToolSpec("swaggerspy", Part.OSINT, "Exposed Swagger/OpenAPI discovery",
             executable="swaggerspy"),
    ToolSpec("gato", Part.OSINT, "GitHub Actions security audit",
             requires_secret="GITHUB_TOKEN"),
    # --- Part 2: Subdomains (passive) ---
    ToolSpec("subfinder", Part.SUBDOMAINS, "Passive subdomain enumeration"),
    ToolSpec("findomain", Part.SUBDOMAINS, "Passive subdomain enumeration"),
    ToolSpec("assetfinder", Part.SUBDOMAINS, "Passive subdomain enumeration"),
    ToolSpec("sublist3r", Part.SUBDOMAINS, "Passive subdomain enumeration"),
    ToolSpec("chaos", Part.SUBDOMAINS, "ProjectDiscovery Chaos dataset",
             requires_secret="CHAOS_API_KEY"),
    ToolSpec("subdominator", Part.SUBDOMAINS, "Passive subdomain enumeration"),
    ToolSpec("shodan", Part.SUBDOMAINS, "Shodan CLI (domain-scoped hostname/ssl only)",
             requires_secret="SHODAN_API_KEY"),
    ToolSpec("censys", Part.SUBDOMAINS, "Censys CLI subdomain search",
             requires_secret="CENSYS_API_ID"),
    # --- Part 2: permutation / bruteforce ---
    ToolSpec("alterx", Part.SUBDOMAINS, "Subdomain permutation generation"),
    ToolSpec("puredns", Part.SUBDOMAINS, "Mass DNS resolution / wildcard filtering"),
    # --- Part 2: takeover ---
    ToolSpec("dnsreaper", Part.SUBDOMAINS, "Subdomain takeover detection (Docker)",
             docker=True),
    # --- Part 3: Hosts ---
    ToolSpec("naabu", Part.HOSTS, "Port discovery"),
    ToolSpec("cdncheck", Part.HOSTS, "CDN vs direct classification"),
    ToolSpec("smap", Part.HOSTS, "Passive port scan (Shodan-backed)"),
    ToolSpec("nerva", Part.HOSTS, "Service fingerprinting"),
    ToolSpec("wafw00f", Part.HOSTS, "WAF detection"),
    ToolSpec("nmap", Part.HOSTS, "Deep port/service/OS scan (opt-in --full-nmap)"),
    ToolSpec("brutespray", Part.HOSTS, "Credential spraying (opt-in --brutespray)"),
    # --- Part 4: Web analysis ---
    ToolSpec("gowitness", Part.WEB, "Screenshot capture"),
    ToolSpec("gau", Part.WEB, "URL collection (getallurls)"),
    ToolSpec("waybackurls", Part.WEB, "URL collection (Wayback Machine)"),
    ToolSpec("katana", Part.WEB, "Active crawling / URL collection"),
    ToolSpec("gospider", Part.WEB, "Web spidering / URL collection"),
    ToolSpec("uro", Part.WEB, "URL deduplication / normalisation"),
    ToolSpec("gf", Part.WEB, "Pattern-based URL filtering (gf patterns)"),
    ToolSpec("secretfinder", Part.WEB, "JS secret discovery", executable="SecretFinder"),
    # --- Part 5: Vulnerability checks ---
    ToolSpec("kxss", Part.VULNS, "Reflected-parameter pre-filter for XSS"),
    ToolSpec("dalfox", Part.VULNS, "XSS scanning"),
    ToolSpec("nuclei", Part.VULNS, "Template-based vulnerability scanning"),
    ToolSpec("sqlmap", Part.VULNS, "SQL injection (opt-in --sqlmap)"),
    ToolSpec("sstimap", Part.VULNS, "Server-side template injection", executable="sstimap"),
    ToolSpec("oralyzer", Part.VULNS, "Open-redirect detection"),
    ToolSpec("corsy", Part.VULNS, "CORS misconfiguration detection"),
    # --- Cross-cutting infra ---
    ToolSpec("interactsh-client", Part.INFRA, "OOB interaction listener (SSRF etc.)"),
    ToolSpec("ipinfo", Part.HOSTS, "IP geolocation / WHOIS", requires_secret="IPINFO_TOKEN"),
    ToolSpec("docker", Part.INFRA, "Container runtime (for Docker-based tools)"),
]

# Several sources (crt.sh, email harvesting, M365/Azure tenant mapping, Google-dork
# generation, SPF/DMARC and other DNS-security checks, exposed-.git detection) are
# implemented in-process via HTTP/DNS rather than as external binaries, and so are
# intentionally not in this executable registry.

REGISTRY: dict[str, ToolSpec] = {spec.key: spec for spec in _SPECS}


def get(key: str) -> ToolSpec | None:
    """Return the :class:`ToolSpec` for *key*, or ``None`` if not registered."""
    return REGISTRY.get(key)


def by_part(part: Part) -> list[ToolSpec]:
    """All specs belonging to *part*."""
    return [s for s in _SPECS if s.part is part]


def availability_report() -> dict[str, bool]:
    """Map every registered tool key to whether its executable is currently on PATH."""
    return {spec.key: spec.available() for spec in _SPECS}


def missing_tools() -> list[ToolSpec]:
    """All registered tools whose executable is not on PATH."""
    return [spec for spec in _SPECS if not spec.available()]
