from datetime import datetime

from sqlalchemy import select

from app.agents.base import Agent
from app.bus import CH_NORMALIZED_EVENTS, CH_RAW_EVENTS
from app.models import ConnectorConfig, LogEvent


def normalize(source: str, event_type: str, data: dict) -> dict:
    """Map connector-specific fields into one common shape.

    A production build would have one mapping per connector (Wazuh,
    CloudTrail, Azure AD sign-in logs, ...). This MVP normalizes the two
    shapes it actually ships: the generic webhook and the synthetic demo
    feed, both of which already send reasonably normalized JSON.
    """
    return {
        "source": source,
        "event_type": event_type,
        "src_ip": data.get("src_ip") or data.get("source_ip"),
        "user": data.get("user") or data.get("username"),
        "outcome": data.get("outcome"),
        "raw": data,
    }


class IntegrationAgent(Agent):
    """Agent 2: connects and normalizes data sources, tracks connector health."""

    name = "integration"

    async def register(self) -> None:
        self.bus.subscribe(CH_RAW_EVENTS, self.on_raw_event)

    async def on_raw_event(self, payload: dict) -> None:
        tenant_id = payload["tenant_id"]
        source = payload["source"]
        event_type = payload["event_type"]
        data = payload["data"]
        occurred_at = payload.get("occurred_at")

        normalized = normalize(source, event_type, data)

        async with self.session() as db:
            event = LogEvent(
                tenant_id=tenant_id,
                connector_id=payload.get("connector_id"),
                source=source,
                event_type=event_type,
                raw=data,
                normalized=normalized,
                occurred_at=datetime.fromisoformat(occurred_at) if occurred_at else datetime.utcnow(),
            )
            db.add(event)

            if payload.get("connector_id"):
                result = await db.execute(
                    select(ConnectorConfig).where(ConnectorConfig.id == payload["connector_id"])
                )
                connector = result.scalar_one_or_none()
                if connector:
                    connector.last_event_at = datetime.utcnow()

            await db.commit()
            await db.refresh(event)

        await self.publish(
            CH_NORMALIZED_EVENTS,
            {"tenant_id": tenant_id, "event_id": event.id, "normalized": normalized},
            tenant_id=tenant_id,
        )
