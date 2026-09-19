"""The agent message bus.

Every agent publishes and subscribes through this single class. Every
publish is also written to the audit_log table before the message is
dispatched, so the Guardian agent (and you) can reconstruct exactly what
every agent said and did, in order, at any time. Nothing gets to skip
the ledger — that is the whole point of this module existing separately
from a raw Redis client.
"""
import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from datetime import datetime

import redis.asyncio as redis

from app.config import get_settings
from app.database import AsyncSessionLocal
from app.models import AuditLogEntry

logger = logging.getLogger("sentrimesh.bus")

Handler = Callable[[dict], Awaitable[None]]


class EventBus:
    def __init__(self, redis_url: str):
        self._redis_url = redis_url
        self._redis: redis.Redis | None = None
        self._pubsub: redis.client.PubSub | None = None
        self._handlers: dict[str, list[Handler]] = {}
        self._listen_task: asyncio.Task | None = None

    async def connect(self) -> None:
        self._redis = redis.from_url(self._redis_url, decode_responses=True)
        self._pubsub = self._redis.pubsub()

    async def close(self) -> None:
        if self._listen_task:
            self._listen_task.cancel()
        if self._pubsub:
            await self._pubsub.close()
        if self._redis:
            await self._redis.close()

    def subscribe(self, channel: str, handler: Handler) -> None:
        self._handlers.setdefault(channel, []).append(handler)

    async def start_listening(self) -> None:
        assert self._pubsub is not None
        await self._pubsub.subscribe(*self._handlers.keys())
        self._listen_task = asyncio.create_task(self._listen_loop())

    async def _listen_loop(self) -> None:
        assert self._pubsub is not None
        async for message in self._pubsub.listen():
            if message["type"] != "message":
                continue
            channel = message["channel"]
            try:
                payload = json.loads(message["data"])
            except (TypeError, json.JSONDecodeError):
                logger.warning("Dropping malformed message on %s", channel)
                continue
            for handler in self._handlers.get(channel, []):
                try:
                    await handler(payload)
                except Exception:
                    logger.exception("Handler failed for channel %s", channel)

    async def publish(self, channel: str, payload: dict, *, actor: str, tenant_id: str | None = None) -> None:
        payload = {**payload, "_published_at": datetime.utcnow().isoformat()}
        await self._audit(actor=actor, action="publish", channel=channel, payload=payload, tenant_id=tenant_id)
        assert self._redis is not None
        await self._redis.publish(channel, json.dumps(payload, default=str))

    @staticmethod
    async def _audit(*, actor: str, action: str, channel: str, payload: dict, tenant_id: str | None) -> None:
        async with AsyncSessionLocal() as session:
            entry = AuditLogEntry(
                tenant_id=tenant_id,
                actor=actor,
                action=action,
                channel=channel,
                payload=payload,
            )
            session.add(entry)
            await session.commit()

    @staticmethod
    async def audit(*, actor: str, action: str, channel: str = "", payload: dict | None = None, tenant_id: str | None = None) -> None:
        """Public helper for agents to log a decision/action that isn't a bus publish
        (e.g. a policy denial, an executed action, a report generated)."""
        await EventBus._audit(actor=actor, action=action, channel=channel, payload=payload or {}, tenant_id=tenant_id)


_bus: EventBus | None = None


async def get_bus() -> EventBus:
    global _bus
    if _bus is None:
        settings = get_settings()
        _bus = EventBus(settings.redis_url)
        await _bus.connect()
    return _bus


# Channel names — the shared vocabulary agents speak over.
CH_RAW_EVENTS = "events.raw"
CH_NORMALIZED_EVENTS = "events.normalized"
CH_INCIDENTS_NEW = "incidents.new"
CH_INCIDENTS_ENRICHED = "incidents.enriched"
CH_INCIDENTS_CLASSIFIED = "incidents.classified"
CH_ACTIONS_PROPOSED = "actions.proposed"
CH_ACTIONS_APPROVED = "actions.approved"
CH_ACTIONS_DENIED = "actions.denied"
CH_ACTIONS_EXECUTED = "actions.executed"
CH_REPORTS_READY = "reports.ready"
CH_GUARDIAN_ALERT = "guardian.alert"
