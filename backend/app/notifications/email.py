"""Email notifications.

If SMTP isn't configured, notifications are logged instead of sent — the
platform never silently drops a notification, and it never fails an
agent's task just because email isn't set up yet.
"""
import logging

from app.config import get_settings

logger = logging.getLogger("sentrimesh.notify")


async def send_email(subject: str, body: str, to: str | None = None) -> bool:
    settings = get_settings()
    recipient = to or settings.notify_to_email

    if not settings.smtp_host or not recipient:
        logger.info("[NOTIFY - no SMTP configured] To=%s Subject=%s\n%s", recipient, subject, body)
        return False

    import aiosmtplib
    from email.message import EmailMessage

    message = EmailMessage()
    message["From"] = settings.smtp_from
    message["To"] = recipient
    message["Subject"] = f"[SentriMeshAstra] {subject}"
    message.set_content(body)

    try:
        await aiosmtplib.send(
            message,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_username,
            password=settings.smtp_password,
            start_tls=True,
        )
        return True
    except Exception:
        logger.exception("Failed to send email notification, falling back to log")
        logger.info("[NOTIFY - send failed] To=%s Subject=%s\n%s", recipient, subject, body)
        return False
