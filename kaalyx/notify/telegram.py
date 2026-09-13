"""Telegram notifications.

Sends: scan start, live subdomain/host counts, the final summary, and immediate alerts
for critical/high findings (plus attaching result files). Info/low findings are saved to
the database but never alerted — the whole point is to surface only what deserves a human
glance.

Design notes:

* If the bot token / chat id are missing (or Telegram is disabled in config), the
  notifier becomes a **no-op**: every method returns immediately and the scan proceeds
  normally. A missing key never breaks a scan.
* Network errors are caught and logged, never raised — a flaky notification must not take
  down a scan.
* Uses the Telegram Bot HTTP API directly via ``httpx`` (async), so no extra Telegram SDK
  dependency is needed.
"""

from __future__ import annotations

from pathlib import Path

import httpx

from ..core.logging import get_logger

logger = get_logger("telegram")

_API_BASE = "https://api.telegram.org"
_MAX_MESSAGE = 4096  # Telegram hard limit for a single text message.


class TelegramNotifier:
    """Async Telegram Bot client with graceful degradation.

    Construct via :meth:`create` so the enabled/disabled decision (config + secrets) lives
    in one place. When disabled, all send methods are cheap no-ops.
    """

    def __init__(
        self, bot_token: str | None, chat_id: str | None, *, enabled: bool = True
    ) -> None:
        self._token = bot_token
        self._chat_id = chat_id
        self.enabled = bool(enabled and bot_token and chat_id)
        if enabled and not self.enabled:
            logger.info("Telegram disabled (missing bot token or chat id).")

    @classmethod
    def create(cls, config, secrets) -> "TelegramNotifier":
        """Build a notifier from the loaded config + secrets."""
        return cls(
            secrets.telegram_bot_token,
            secrets.telegram_chat_id,
            enabled=config.telegram.enabled,
        )

    # -- low-level ---------------------------------------------------------------------

    async def _post(self, method: str, data: dict, files: dict | None = None) -> bool:
        if not self.enabled:
            return False
        url = f"{_API_BASE}/bot{self._token}/{method}"
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(url, data=data, files=files)
            if resp.status_code != 200:
                logger.warning("Telegram %s failed: HTTP %s", method, resp.status_code)
                return False
            return True
        except (httpx.HTTPError, OSError) as exc:
            logger.warning("Telegram %s error: %s", method, exc)
            return False

    async def send_message(self, text: str, *, markdown: bool = True) -> bool:
        """Send a text message, truncating to Telegram's per-message limit."""
        if not self.enabled:
            return False
        if len(text) > _MAX_MESSAGE:
            text = text[: _MAX_MESSAGE - 20] + "\n… (truncated)"
        data = {"chat_id": self._chat_id, "text": text}
        if markdown:
            data["parse_mode"] = "Markdown"
        return await self._post("sendMessage", data)

    async def send_document(self, file_path: str | Path, caption: str = "") -> bool:
        """Upload a result file (e.g. the findings summary) as a document."""
        if not self.enabled:
            return False
        path = Path(file_path)
        if not path.is_file():
            logger.warning("Telegram: file not found, skipping upload: %s", path)
            return False
        try:
            with path.open("rb") as fh:
                files = {"document": (path.name, fh)}
                data = {"chat_id": self._chat_id, "caption": caption[:1024]}
                return await self._post("sendDocument", data, files=files)
        except OSError as exc:
            logger.warning("Telegram: could not read %s: %s", path, exc)
            return False

    # -- high-level event helpers ------------------------------------------------------

    async def scan_started(self, domain: str, target_type: str, options: dict) -> None:
        opts = ", ".join(k for k, v in options.items() if v) or "defaults"
        await self.send_message(
            f"🛰️ *Kaalyx scan started*\n"
            f"Target: `{domain}` ({target_type})\n"
            f"Options: {opts}"
        )

    async def progress(self, domain: str, label: str, counts: dict[str, int]) -> None:
        body = "\n".join(f"• {k}: *{v}*" for k, v in counts.items())
        await self.send_message(f"📊 *{label}* — `{domain}`\n{body}")

    async def finding_alert(
        self, domain: str, title: str, severity: str, target: str, tools: str
    ) -> None:
        icon = "🚨" if severity.lower() == "critical" else "⚠️"
        await self.send_message(
            f"{icon} *{severity.upper()} finding* — `{domain}`\n"
            f"*{title}*\n"
            f"Target: `{target}`\n"
            f"Tools: {tools}"
        )

    async def scan_finished(
        self, domain: str, status: str, counts: dict[str, int]
    ) -> None:
        body = "\n".join(f"• {k}: *{v}*" for k, v in counts.items())
        icon = "✅" if status == "completed" else "❌"
        await self.send_message(
            f"{icon} *Kaalyx scan {status}* — `{domain}`\n{body}"
        )
