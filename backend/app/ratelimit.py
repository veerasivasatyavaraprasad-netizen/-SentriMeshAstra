"""Login brute-force protection.

Two independent Redis-backed sliding-window counters (app/state_store.py,
so this holds correctly across multiple backend replicas): one keyed by
the attempted email, one keyed by the caller's source IP. A failed
attempt increments both; either one crossing its threshold locks out
further attempts on that key for the rest of the window. A successful
login doesn't need to clear anything — the windows decay on their own.

Note: the source IP is read from the direct TCP connection
(request.client.host), not X-Forwarded-For — trusting a proxy header
without knowing you're actually behind a trusted proxy is its own
security bug (trivially spoofable). If SentriMeshAstra is deployed behind
a reverse proxy/load balancer, that proxy needs to be the one setting the
real client IP via a mechanism FastAPI is configured to trust (e.g.
ProxyHeadersMiddleware with a known trusted proxy list) — not something
to bolt on here without that context.
"""
from dataclasses import dataclass

from fastapi import Request

from app.bus import EventBus
from app.config import get_settings
from app.state_store import count_without_recording, record_and_count


@dataclass
class LockoutStatus:
    locked: bool
    retry_after_seconds: int
    reason: str = ""


def _email_key(email: str) -> str:
    return f"login_fail:email:{email.strip().lower()}"


def _ip_key(ip: str) -> str:
    return f"login_fail:ip:{ip}"


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


async def check_lockout(bus: EventBus, *, email: str, ip: str) -> LockoutStatus:
    settings = get_settings()
    window = settings.login_lockout_window_seconds

    email_count = await count_without_recording(bus, _email_key(email), window_seconds=window)
    if email_count >= settings.login_max_attempts_per_email:
        return LockoutStatus(True, window, reason="too many failed attempts for this account")

    ip_count = await count_without_recording(bus, _ip_key(ip), window_seconds=window)
    if ip_count >= settings.login_max_attempts_per_ip:
        return LockoutStatus(True, window, reason="too many failed attempts from this source")

    return LockoutStatus(False, 0)


async def record_failed_attempt(bus: EventBus, *, email: str, ip: str) -> None:
    settings = get_settings()
    window = settings.login_lockout_window_seconds
    await record_and_count(bus, _email_key(email), window_seconds=window)
    await record_and_count(bus, _ip_key(ip), window_seconds=window)
