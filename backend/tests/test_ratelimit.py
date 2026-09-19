import uuid

import pytest

from app.bus import EventBus
from app.config import get_settings
from app.ratelimit import check_lockout, record_failed_attempt


async def _redis_reachable() -> bool:
    try:
        bus = EventBus(get_settings().redis_url)
        await bus.connect()
        await bus.redis.ping()
        await bus.close()
        return True
    except Exception:
        return False


@pytest.fixture
async def bus():
    b = EventBus(get_settings().redis_url)
    await b.connect()
    yield b
    await b.close()


async def test_lockout_trips_after_max_attempts_for_one_email(bus):
    if not await _redis_reachable():
        pytest.skip("Redis not reachable in this environment")
    email = f"{uuid.uuid4().hex}@example.com"
    ip = "203.0.113.9"
    settings = get_settings()

    for _ in range(settings.login_max_attempts_per_email - 1):
        status = await check_lockout(bus, email=email, ip=ip)
        assert status.locked is False
        await record_failed_attempt(bus, email=email, ip=ip)

    # One more failure crosses the threshold.
    await record_failed_attempt(bus, email=email, ip=ip)
    status = await check_lockout(bus, email=email, ip=ip)
    assert status.locked is True
    assert "account" in status.reason


async def test_lockout_does_not_leak_across_different_emails(bus):
    if not await _redis_reachable():
        pytest.skip("Redis not reachable in this environment")
    email_a = f"{uuid.uuid4().hex}@example.com"
    email_b = f"{uuid.uuid4().hex}@example.com"
    ip_a = "203.0.113.10"
    ip_b = "203.0.113.11"
    settings = get_settings()

    for _ in range(settings.login_max_attempts_per_email):
        await record_failed_attempt(bus, email=email_a, ip=ip_a)

    locked_a = await check_lockout(bus, email=email_a, ip=ip_a)
    locked_b = await check_lockout(bus, email=email_b, ip=ip_b)
    assert locked_a.locked is True
    assert locked_b.locked is False
