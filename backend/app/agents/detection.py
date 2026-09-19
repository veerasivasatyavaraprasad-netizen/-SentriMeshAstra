from sqlalchemy import select

from app.agents.base import Agent
from app.bus import CH_INCIDENTS_NEW, CH_NORMALIZED_EVENTS
from app.connectors.threat_feed import MITRE_MAP
from app.models import LogEvent
from app.state_store import count_without_recording, record_and_count

FAILED_LOGIN_WINDOW_SECONDS = 10 * 60
FAILED_LOGIN_THRESHOLD = 5


class DetectionAgent(Agent):
    """Agent 3: correlates normalized events, filters noise, opens incidents.

    Failed-login sliding-window counts live in Redis (app/state_store.py),
    not process memory, so correlation is correct even with more than one
    backend replica running behind a load balancer — a burst of failed
    logins spread across replicas by round-robin routing still hits the
    same shared counter. The open-incident dedup cache below stays
    per-process, but it's only a fast-path: `_open_incident` always falls
    back to a database check on a cache miss, which is itself correct
    across replicas since they share one database.
    """

    name = "detection"

    def __init__(self, bus):
        super().__init__(bus)
        # Dedup key (tenant_id, technique_key, src_ip) -> open incident id.
        # Prevents the same ongoing campaign (e.g. one brute-force burst
        # that crosses the failed-login threshold, then succeeds) from
        # spawning a new incident and a new response action per event.
        self._active_incidents: dict[tuple[str, str, str], str] = {}

    async def register(self) -> None:
        self.bus.subscribe(CH_NORMALIZED_EVENTS, self.on_normalized_event)

    async def _record_failed_login(self, tenant_id: str, src_ip: str) -> int:
        return await record_and_count(
            self.bus, f"failed_logins:{tenant_id}:{src_ip}", window_seconds=FAILED_LOGIN_WINDOW_SECONDS
        )

    async def _recent_failed_login_count(self, tenant_id: str, src_ip: str) -> int:
        return await count_without_recording(
            self.bus, f"failed_logins:{tenant_id}:{src_ip}", window_seconds=FAILED_LOGIN_WINDOW_SECONDS
        )

    async def on_normalized_event(self, payload: dict) -> None:
        tenant_id = payload["tenant_id"]
        event_id = payload["event_id"]
        normalized = payload["normalized"]
        event_type = normalized["event_type"]
        src_ip = normalized.get("src_ip")

        if event_type == "login_failed" and src_ip:
            count = await self._record_failed_login(tenant_id, src_ip)
            if count >= FAILED_LOGIN_THRESHOLD:
                await self._open_incident(
                    tenant_id=tenant_id,
                    title=f"Repeated failed logins from {src_ip}",
                    description=(
                        f"{count} failed login attempts from {src_ip} within "
                        f"{FAILED_LOGIN_WINDOW_SECONDS // 60} minutes."
                    ),
                    technique_key="bruteforce_login",
                    related_event_ids=[event_id],
                    context={"src_ip": src_ip, "failed_login_count": count},
                )
        elif event_type == "login_success" and src_ip:
            recent_failures = await self._recent_failed_login_count(tenant_id, src_ip)
            if recent_failures >= FAILED_LOGIN_THRESHOLD:
                await self._open_incident(
                    tenant_id=tenant_id,
                    title=f"Successful login from {src_ip} after repeated failures",
                    description=(
                        f"Login succeeded from {src_ip} after {recent_failures} prior failed "
                        "attempts in the same window — consistent with a successful credential attack."
                    ),
                    technique_key="bruteforce_login",
                    related_event_ids=[event_id],
                    context={"src_ip": src_ip, "failed_login_count": recent_failures},
                )
        elif event_type == "privilege_escalation":
            await self._open_incident(
                tenant_id=tenant_id,
                title="Unexpected privilege escalation detected",
                description=normalized["raw"].get("description", "A user or process gained elevated privileges."),
                technique_key="privilege_escalation",
                related_event_ids=[event_id],
                context={"new_admin_activity": True},
            )

    async def _open_incident(
        self, *, tenant_id: str, title: str, description: str, technique_key: str,
        related_event_ids: list[str], context: dict,
    ) -> None:
        from app.models import Incident, IncidentStatus

        src_ip = context.get("src_ip", "")
        dedup_key = (tenant_id, technique_key, src_ip)
        existing_id = self._active_incidents.get(dedup_key)
        technique_names = MITRE_MAP.get(technique_key, [])

        async with self.session() as db:
            incident = None
            if existing_id:
                result = await db.execute(select(Incident).where(Incident.id == existing_id))
                incident = result.scalar_one_or_none()

            if incident is None:
                # Not in this process's memory (e.g. after a restart) —
                # fall back to checking the database itself before opening
                # a duplicate incident for the same ongoing campaign.
                result = await db.execute(
                    select(Incident).where(
                        Incident.tenant_id == tenant_id,
                        Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING]),
                    )
                )
                for candidate in result.scalars():
                    same_technique = set(candidate.mitre_techniques or []) == set(technique_names)
                    same_ip = candidate.enrichment.get("context", {}).get("src_ip") == src_ip
                    if same_technique and same_ip and src_ip:
                        incident = candidate
                        break

            if incident is not None and incident.status in (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING):
                # Same ongoing campaign — fold into the existing incident
                # instead of re-triggering the whole enrichment/response
                # pipeline (and a duplicate approval request) per event.
                incident.description = description
                incident.related_event_ids = list(incident.related_event_ids) + related_event_ids
                incident.enrichment = {**incident.enrichment, "context": context}
                await db.commit()
                self.log("Folded event into existing incident %s (%s)", incident.id, title)
                return

            incident = Incident(
                tenant_id=tenant_id,
                title=title,
                description=description,
                mitre_techniques=MITRE_MAP.get(technique_key, []),
                related_event_ids=related_event_ids,
                enrichment={"context": context},
            )
            db.add(incident)
            await db.commit()
            await db.refresh(incident)

        self._active_incidents[dedup_key] = incident.id
        self.log("Opened incident %s: %s", incident.id, title)
        await self.publish(
            CH_INCIDENTS_NEW,
            {"tenant_id": tenant_id, "incident_id": incident.id, "context": context},
            tenant_id=tenant_id,
        )
