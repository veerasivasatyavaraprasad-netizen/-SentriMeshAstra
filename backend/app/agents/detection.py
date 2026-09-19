import time
from datetime import datetime, timezone

from sqlalchemy import select

from app.agents.base import Agent
from app.bus import CH_INCIDENTS_NEW, CH_NORMALIZED_EVENTS
from app.connectors.threat_feed import MITRE_MAP
from app.geo import implied_travel_speed_kmh, lookup_country, MAX_PLAUSIBLE_SPEED_KMH
from app.models import LogEvent
from app.state_store import count_without_recording, get_last_value, record_and_count, set_last_value

FAILED_LOGIN_WINDOW_SECONDS = 10 * 60
FAILED_LOGIN_THRESHOLD = 5

# How far back a user's last known sign-in location is still considered a
# meaningful baseline. Past this, a "new" location isn't suspicious — it's
# just a different trip, a VPN change, or someone who moved.
IMPOSSIBLE_TRAVEL_STATE_TTL_SECONDS = 24 * 60 * 60


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
        # Real vendor-supplied MITRE ATT&CK classification (e.g. Wazuh's
        # own rule.mitre.id/technique) takes priority over our own
        # technique_key -> MITRE_MAP heuristic guess when the connector
        # actually supplied one — it's the vendor's own real analysis of
        # this exact event, not an inference from event_type alone.
        vendor_mitre = normalized.get("mitre_techniques") or []

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
                    vendor_mitre_techniques=vendor_mitre,
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
                    vendor_mitre_techniques=vendor_mitre,
                    related_event_ids=[event_id],
                    context={"src_ip": src_ip, "failed_login_count": recent_failures},
                )

        if event_type == "login_success" and normalized.get("user"):
            await self._check_impossible_travel(
                tenant_id=tenant_id, user=normalized["user"], src_ip=src_ip, normalized=normalized, event_id=event_id
            )

        if event_type == "privilege_escalation":
            await self._open_incident(
                tenant_id=tenant_id,
                title="Unexpected privilege escalation detected",
                description=self._vendor_description(normalized, "A user or process gained elevated privileges."),
                technique_key="privilege_escalation",
                vendor_mitre_techniques=vendor_mitre,
                related_event_ids=[event_id],
                context={"new_admin_activity": True, "src_ip": src_ip},
            )

        if event_type == "malware_detected":
            await self._open_incident(
                tenant_id=tenant_id,
                title=f"Malware indicator detected{f' on {src_ip}' if src_ip else ''}",
                description=self._vendor_description(normalized, "A malware/rootkit signature was detected by the connected source."),
                technique_key="malware_signature",
                vendor_mitre_techniques=vendor_mitre,
                related_event_ids=[event_id],
                context={"src_ip": src_ip, "malware_detected": True},
            )

    @staticmethod
    def _vendor_description(normalized: dict, fallback: str) -> str:
        # Wazuh's real rule.description lives under vendor_detail
        # (app/connectors/log_formats.py), not at the raw payload's top
        # level — a generic connector's raw shape is the only thing that
        # might plausibly have a top-level "description" field.
        detail = normalized.get("vendor_detail") or {}
        return detail.get("rule_description") or normalized.get("raw", {}).get("description") or fallback

    async def _resolve_country(self, normalized: dict) -> str | None:
        # A vendor-supplied location (Azure AD sign-in logs carry one
        # directly) is used as-is — it's more accurate than anything we'd
        # get from geolocating the IP ourselves. Only fall back to a real
        # lookup when the source didn't already tell us.
        country = normalized.get("country")
        if country:
            return country
        src_ip = normalized.get("src_ip")
        if not src_ip:
            return None
        return await lookup_country(src_ip)

    async def _check_impossible_travel(
        self, *, tenant_id: str, user: str, src_ip: str | None, normalized: dict, event_id: str
    ) -> None:
        country = await self._resolve_country(normalized)
        if not country:
            return  # no known location for this event — nothing to compare, not a guess

        key = f"last_login_location:{tenant_id}:{user}"
        now = time.time()
        last = await get_last_value(self.bus, key)

        if last is not None:
            speed = implied_travel_speed_kmh(last["country"], country, now - last["timestamp"])
            if speed is not None and speed > MAX_PLAUSIBLE_SPEED_KMH:
                last_seen = datetime.fromtimestamp(last["timestamp"], tz=timezone.utc).isoformat()
                await self._open_incident(
                    tenant_id=tenant_id,
                    title=f"Impossible travel for {user}: {last['country']} → {country}",
                    description=(
                        f"{user} signed in from {last['country']} at {last_seen}, then from {country} "
                        f"{(now - last['timestamp']) / 60:.0f} minutes later — an implied travel speed of "
                        f"~{speed:,.0f} km/h, faster than commercial air travel allows."
                    ),
                    technique_key="impossible_travel",
                    vendor_mitre_techniques=[],
                    related_event_ids=[event_id],
                    context={
                        "src_ip": src_ip,
                        "user": user,
                        "impossible_travel": True,
                        "from_country": last["country"],
                        "to_country": country,
                        "implied_speed_kmh": round(speed),
                    },
                )

        # Always record this sign-in as the new baseline, flagged or not —
        # the next sign-in compares against wherever the user actually is now.
        await set_last_value(
            self.bus, key, {"country": country, "timestamp": now}, ttl_seconds=IMPOSSIBLE_TRAVEL_STATE_TTL_SECONDS
        )

    async def _open_incident(
        self, *, tenant_id: str, title: str, description: str, technique_key: str,
        related_event_ids: list[str], context: dict, vendor_mitre_techniques: list[str] | None = None,
    ) -> None:
        from app.models import Incident, IncidentStatus

        src_ip = context.get("src_ip", "")
        dedup_key = (tenant_id, technique_key, src_ip)
        existing_id = self._active_incidents.get(dedup_key)
        context = {**context, "technique_key": technique_key}

        async with self.session() as db:
            incident = None
            if existing_id:
                result = await db.execute(select(Incident).where(Incident.id == existing_id))
                incident = result.scalar_one_or_none()

            if incident is None:
                # Not in this process's memory (e.g. after a restart) —
                # fall back to checking the database itself before opening
                # a duplicate incident for the same ongoing campaign.
                # Matched on our own stable technique_key (stored in
                # context), not the mitre_techniques list itself — a real
                # vendor's exact technique set can vary event to event for
                # the same underlying campaign.
                result = await db.execute(
                    select(Incident).where(
                        Incident.tenant_id == tenant_id,
                        Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING]),
                    )
                )
                for candidate in result.scalars():
                    candidate_context = candidate.enrichment.get("context", {})
                    same_technique = candidate_context.get("technique_key") == technique_key
                    same_ip = candidate_context.get("src_ip") == src_ip
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
                if vendor_mitre_techniques:
                    incident.mitre_techniques = vendor_mitre_techniques
                await db.commit()
                self.log("Folded event into existing incident %s (%s)", incident.id, title)
                return

            incident = Incident(
                tenant_id=tenant_id,
                title=title,
                description=description,
                mitre_techniques=vendor_mitre_techniques or MITRE_MAP.get(technique_key, []),
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
