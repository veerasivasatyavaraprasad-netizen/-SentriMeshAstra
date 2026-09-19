"""Shared, cross-instance state backed by Redis.

Sliding-window counters (sorted sets) are used anywhere correctness has
to hold across multiple backend replicas — Detection's failed-login
window, and the login endpoint's brute-force counter. Each member is a
unique per-call token (so repeated calls in the same millisecond don't
collide and get silently dropped), scored by its timestamp; membership
older than the window is trimmed on every call, and the key expires on
its own if nothing touches it again.

get_last_value/set_last_value is a second, simpler primitive — one JSON
value per key with a TTL — used for "what did we last see for this
key" state (e.g. a user's last known sign-in country, for impossible-
travel correlation), which needs a single shared value, not a count.
"""
import json
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


async def get_last_value(bus: EventBus, key: str) -> dict | None:
    raw = await bus.redis.get(key)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return None


async def set_last_value(bus: EventBus, key: str, value: dict, *, ttl_seconds: int) -> None:
    await bus.redis.set(key, json.dumps(value), ex=ttl_seconds)
