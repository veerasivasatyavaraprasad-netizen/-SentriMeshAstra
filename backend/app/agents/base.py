import logging

from app.bus import EventBus
from app.database import AsyncSessionLocal

logger = logging.getLogger("sentrimesh.agents")


class Agent:
    """Common base for every agent: a name, a bus connection, and a
    convenience session factory. Agents never talk directly to each other —
    only through the bus — so every interaction is observable and auditable.
    """

    name: str = "agent"

    def __init__(self, bus: EventBus):
        self.bus = bus

    def session(self):
        return AsyncSessionLocal()

    async def publish(self, channel: str, payload: dict, *, tenant_id: str | None = None) -> None:
        await self.bus.publish(channel, payload, actor=self.name, tenant_id=tenant_id)

    async def register(self) -> None:
        """Subscribe to the channels this agent cares about. Overridden by subclasses."""
        raise NotImplementedError

    def log(self, msg: str, *args) -> None:
        logger.info("[%s] " + msg, self.name, *args)
