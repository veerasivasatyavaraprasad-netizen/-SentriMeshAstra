from datetime import datetime

from sqlalchemy import select

from app.agents.base import Agent
from app.bus import CH_NORMALIZED_EVENTS, CH_RAW_EVENTS
from app.connectors.log_formats import normalize_for_connector_type
from app.models import ConnectorConfig, LogEvent


def normalize(connector_type: str, source_label: str, event_type: str | None, data: dict) -> dict:
    """Map a connector's raw payload into one common shape, using the
    real per-vendor field mapping in app/connectors/log_formats.py for a
    known connector_type (Wazuh, CloudTrail, Azure AD sign-in logs), or a
    best-effort generic guess otherwise."""
    result = normalize_for_connector_type(connector_type, event_type, data)
    return {
        "source": source_label,
        "connector_type": connector_type,
        "event_type": result.event_type,
        "src_ip": result.src_ip,
        "user": result.user,
        "outcome": result.outcome,
        "mitre_techniques": result.mitre_techniques,
        "country": result.country,
        "vendor_detail": result.extra,
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
        # connector_type drives which real vendor parser runs (see
        # app/connectors/log_formats.py); it comes from the authenticated
        # connector's own registration, not the free-text `source` label.
        connector_type = payload.get("connector_type") or source
        data = payload["data"]
        occurred_at = payload.get("occurred_at")

        normalized = normalize(connector_type, source, payload.get("event_type"), data)
        # The real, classified event_type (from the vendor parser, or the
        # caller-supplied one for an unrecognized connector_type) — never
        # the possibly-absent raw caller value, which the DB column and
        # every downstream agent expect to always be a real string.
        event_type = normalized["event_type"]

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
