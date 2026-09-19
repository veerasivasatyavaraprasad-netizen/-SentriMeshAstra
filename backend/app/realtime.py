"""Bridges the Redis agent bus to a browser: a fresh Redis pub/sub
subscription per WebSocket connection, filtered to one tenant.

The main EventBus (app/bus.py) is one shared subscription that agents
attach handlers to; this is deliberately separate because a browser tab
needs its own independent stream it can open/close/reconnect freely
without touching the agents' own subscription lifecycle. At the scale
this MVP is built for (one connection per open dashboard tab), a Redis
subscription per tab is the simplest correct design — see README.md for
the documented tradeoff at larger scale (a dedicated fan-out service).
"""
import json
import logging

import redis.asyncio as redis

logger = logging.getLogger("sentrimesh.realtime")

# Every channel a browser dashboard might care about. Deliberately NOT
# events.raw/events.normalized — those fire once per individual log line
# and would be noise; the console cares about incidents, actions, reports,
# and guardian alerts; everything after correlation, not before it.
DASHBOARD_CHANNELS = [
    "incidents.new",
    "incidents.enriched",
    "incidents.classified",
    "actions.proposed",
    "actions.approved",
    "actions.denied",
    "actions.executed",
    "reports.ready",
    "guardian.alert",
]


async def stream_tenant_events(tenant_id: str, redis_url: str):
    """Yields {"channel": ..., "payload": ...} for every dashboard-relevant
    message published for this tenant, as it happens. Runs until the
    caller stops iterating (e.g. the WebSocket disconnects and cancels
    the task consuming this generator) — cleans up its own Redis
    connection in `finally` either way."""
    client = redis.from_url(redis_url, decode_responses=True)
    pubsub = client.pubsub()
    try:
        await pubsub.subscribe(*DASHBOARD_CHANNELS)
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            try:
                payload = json.loads(message["data"])
            except (TypeError, json.JSONDecodeError):
                continue
            if payload.get("tenant_id") != tenant_id:
                continue
            yield {"channel": message["channel"], "payload": payload}
    finally:
        try:
            await pubsub.aclose()
        except Exception:
            logger.debug("Error closing per-connection pubsub", exc_info=True)
        await client.aclose()
