"""These tests hit a real Redis instance (same one the app uses for the
message bus) — they verify sliding-window counters are actually shared
across separate connections, which is the whole point of moving them out
of process memory. Skipped when Redis isn't reachable (e.g. a sandbox
with no service running) rather than failing CI for an environment gap.
"""
import uuid

import pytest

from app.bus import EventBus
from app.config import get_settings
from app.state_store import count_without_recording, record_and_count


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


async def test_record_and_count_increments_across_calls(bus):
    if not await _redis_reachable():
        pytest.skip("Redis not reachable in this environment")
    key = f"test:{uuid.uuid4().hex}"
    counts = [await record_and_count(bus, key, window_seconds=60) for _ in range(5)]
    assert counts == [1, 2, 3, 4, 5]
    await bus.redis.delete(key)


async def test_count_is_shared_across_separate_connections(bus):
    """The property that actually matters: two independent EventBus
    connections (standing in for two backend replicas) must see the same
    counter, or correlation silently breaks under horizontal scaling."""
    if not await _redis_reachable():
        pytest.skip("Redis not reachable in this environment")
    key = f"test:{uuid.uuid4().hex}"
    other_bus = EventBus(get_settings().redis_url)
    await other_bus.connect()
    try:
        await record_and_count(bus, key, window_seconds=60)
        await record_and_count(bus, key, window_seconds=60)
        count_from_other_instance = await record_and_count(other_bus, key, window_seconds=60)
        assert count_from_other_instance == 3
    finally:
        await other_bus.redis.delete(key)
        await other_bus.close()


async def test_count_without_recording_does_not_add_an_entry(bus):
    if not await _redis_reachable():
        pytest.skip("Redis not reachable in this environment")
    key = f"test:{uuid.uuid4().hex}"
    await record_and_count(bus, key, window_seconds=60)
    first_read = await count_without_recording(bus, key, window_seconds=60)
    second_read = await count_without_recording(bus, key, window_seconds=60)
    assert first_read == second_read == 1
    await bus.redis.delete(key)
