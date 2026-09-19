"""Shared, cross-instance counters backed by Redis sorted sets.

Used anywhere correctness has to hold across multiple backend replicas —
Detection's failed-login sliding window, and the login endpoint's
brute-force counter. Each member is a unique per-call token (so repeated
calls in the same millisecond don't collide and get silently dropped),
scored by its timestamp; membership older than the window is trimmed on
every call, and the key expires on its own if nothing touches it again.
"""
import time
import uuid

from app.bus import EventBus


async def record_and_count(bus: EventBus, key: str, *, window_seconds: int) -> int:
    """Record one event under `key` and return how many have landed in
    the trailing `window_seconds`, across every process sharing this
    Redis instance."""
    redis = bus.redis
    now = time.time()
    cutoff = now - window_seconds
    member = f"{now}:{uuid.uuid4().hex}"

    pipe = redis.pipeline()
    pipe.zadd(key, {member: now})
    pipe.zremrangebyscore(key, 0, cutoff)
    pipe.zcard(key)
    pipe.expire(key, window_seconds)
    _, _, count, _ = await pipe.execute()
    return int(count)


async def count_without_recording(bus: EventBus, key: str, *, window_seconds: int) -> int:
    """Like record_and_count, but doesn't add a new event — used to check
    "how many happened recently" without the check itself counting as one
    (e.g. reading the failed-login count when a login *succeeds*)."""
    redis = bus.redis
    now = time.time()
    cutoff = now - window_seconds
    await redis.zremrangebyscore(key, 0, cutoff)
    return int(await redis.zcard(key))
