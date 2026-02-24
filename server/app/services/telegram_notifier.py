"""
Telegram notification service.

Sends alert messages to a configured Telegram chat via the Bot API.
"""
import logging
from datetime import datetime, timezone

import httpx

from app.config import settings
from app.services.encryption import decrypt_value

logger = logging.getLogger(__name__)

TELEGRAM_API_BASE = "https://api.telegram.org"
REQUEST_TIMEOUT = 15.0

SEVERITY_EMOJI = {
    "critical": "\u26d4\ufe0f",
    "warning": "\u26a0\ufe0f",
    "info": "\u2139\ufe0f",
    "ok": "\u2705",
}


def _get_bot_token() -> str | None:
    """Retrieve and decrypt the Telegram bot token from settings."""
    encrypted = settings.TELEGRAM_BOT_TOKEN_ENCRYPTED
    if not encrypted:
        return None
    try:
        return decrypt_value(encrypted)
    except Exception:
        logger.error("Failed to decrypt Telegram bot token")
        return None


def _format_alert_message(alert, server) -> str:
    """
    Format an alert into a Telegram-friendly HTML message.

    Args:
        alert: AlertHistory instance.
        server: Server instance.

    Returns:
        HTML-formatted message string.
    """
    emoji = SEVERITY_EMOJI.get(alert.severity, "\u2753")
    severity_label = alert.severity.upper()
    timestamp = alert.created_at or datetime.now(timezone.utc)
    ts_str = timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        f"{emoji} <b>RAID Monitor Alert</b> [{severity_label}]",
        "",
        f"<b>Server:</b> {server.hostname}",
        f"<b>IP:</b> {server.ip_address}",
        "",
        f"<b>{alert.title}</b>",
        f"{alert.message}",
        "",
        f"<i>{ts_str}</i>",
    ]

    if alert.context:
        ctx = alert.context
        if ctx.get("controller_id") is not None:
            lines.insert(4, f"<b>Controller:</b> #{ctx['controller_id']}")
        if ctx.get("vd_id") is not None:
            lines.insert(5, f"<b>VD:</b> /{ctx['vd_id']}")
        if ctx.get("pd_slot") is not None:
            enc = ctx.get("pd_enclosure", "?")
            lines.insert(5, f"<b>PD:</b> [{enc}:{ctx['pd_slot']}]")

    return "\n".join(lines)


def _format_resolve_message(alert, server) -> str:
    """Format a resolution notification message."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return (
        f"\u2705 <b>Alert Resolved</b>\n"
        f"\n"
        f"<b>Server:</b> {server.hostname}\n"
        f"<b>{alert.title}</b>\n"
        f"\n"
        f"<i>Resolved at {timestamp}</i>"
    )


async def send_alert(alert, server) -> bool:
    """
    Send an alert notification to the configured Telegram chat.

    Args:
        alert: AlertHistory instance with severity, title, message, context.
        server: Server instance with hostname, ip_address.

    Returns:
        True if the message was sent successfully, False otherwise.
    """
    bot_token = _get_bot_token()
    chat_id = settings.TELEGRAM_CHAT_ID

    if not bot_token or not chat_id:
        logger.debug("Telegram notifications not configured, skipping send")
        return False

    text = _format_alert_message(alert, server)
    return await _send_message(bot_token, chat_id, text)


async def send_resolve_notification(alert, server) -> bool:
    """
    Send a resolution notification when an alert is resolved.

    Args:
        alert: AlertHistory instance.
        server: Server instance.

    Returns:
        True if the message was sent successfully, False otherwise.
    """
    bot_token = _get_bot_token()
    chat_id = settings.TELEGRAM_CHAT_ID

    if not bot_token or not chat_id:
        return False

    text = _format_resolve_message(alert, server)
    return await _send_message(bot_token, chat_id, text)


async def send_test_message(bot_token: str, chat_id: str) -> bool:
    """
    Send a test message to verify Telegram configuration.

    Args:
        bot_token: Plaintext Telegram bot token.
        chat_id: Telegram chat ID.

    Returns:
        True if the test message was sent successfully, False otherwise.
    """
    text = (
        "\u2705 <b>RAID Monitor</b>\n"
        "\n"
        "Test message sent successfully.\n"
        "Telegram notifications are configured correctly."
    )
    return await _send_message(bot_token, chat_id, text)


async def _send_message(bot_token: str, chat_id: str, text: str) -> bool:
    """
    Low-level function to send a message via the Telegram Bot API.

    Args:
        bot_token: The bot API token.
        chat_id: Target chat ID.
        text: HTML-formatted message text.

    Returns:
        True on success, False on failure.
    """
    url = f"{TELEGRAM_API_BASE}/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            response = await client.post(url, json=payload)

        if response.status_code == 200:
            data = response.json()
            if data.get("ok"):
                logger.info("Telegram message sent to chat_id=%s", chat_id)
                return True
            else:
                logger.warning(
                    "Telegram API returned ok=false: %s",
                    data.get("description", "unknown error"),
                )
                return False
        else:
            logger.warning(
                "Telegram API HTTP %d: %s",
                response.status_code,
                response.text[:500],
            )
            return False

    except httpx.TimeoutException:
        logger.error("Telegram API request timed out")
        return False
    except httpx.RequestError as exc:
        logger.error("Telegram API request error: %s", exc)
        return False
    except Exception:
        logger.exception("Unexpected error sending Telegram message")
        return False
