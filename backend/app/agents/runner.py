import asyncio
import logging

from sqlalchemy import select

from app.agents.detection import DetectionAgent
from app.agents.exposure import ExposureAgent
from app.agents.guardian import GuardianAgent
from app.agents.integration import IntegrationAgent
from app.agents.orchestrator import OrchestratorAgent
from app.agents.reporting import ReportingAgent
from app.agents.response import ResponseAgent
from app.agents.threat_intel import ThreatIntelAgent
from app.bus import EventBus
from app.database import AsyncSessionLocal
from app.models import Tenant

logger = logging.getLogger("sentrimesh.runner")

GUARDIAN_HEALTH_CHECK_INTERVAL_SECONDS = 15 * 60
DAILY_REPORT_INTERVAL_SECONDS = 24 * 60 * 60


class AgentFleet:
    """Boots all 8 agents on the shared event bus and runs the background
    schedules (connector health checks, daily reports)."""

    def __init__(self, bus: EventBus):
        self.bus = bus
        self.orchestrator = OrchestratorAgent(bus)
        self.integration = IntegrationAgent(bus)
        self.detection = DetectionAgent(bus)
        self.threat_intel = ThreatIntelAgent(bus)
        self.exposure = ExposureAgent(bus)
        self.response = ResponseAgent(bus)
        self.reporting = ReportingAgent(bus)
        self.guardian = GuardianAgent(bus)
        self._background_tasks: list[asyncio.Task] = []

    @property
    def agents(self):
        return [
            self.orchestrator,
            self.integration,
            self.detection,
            self.threat_intel,
            self.exposure,
            self.response,
            self.reporting,
            self.guardian,
        ]

    async def start(self) -> None:
        for agent in self.agents:
            await agent.register()
        await self.bus.start_listening()
        self._background_tasks.append(asyncio.create_task(self._guardian_health_loop()))
        self._background_tasks.append(asyncio.create_task(self._daily_report_loop()))
        logger.info("All 8 agents online.")

    async def stop(self) -> None:
        for task in self._background_tasks:
            task.cancel()

    async def _guardian_health_loop(self) -> None:
        while True:
            try:
                await self.guardian.check_connector_health()
            except Exception:
                logger.exception("Guardian health check failed")
            await asyncio.sleep(GUARDIAN_HEALTH_CHECK_INTERVAL_SECONDS)

    async def _daily_report_loop(self) -> None:
        while True:
            await asyncio.sleep(DAILY_REPORT_INTERVAL_SECONDS)
            try:
                async with AsyncSessionLocal() as db:
                    result = await db.execute(select(Tenant))
                    tenant_ids = [t.id for t in result.scalars()]
                for tenant_id in tenant_ids:
                    await self.reporting.generate_daily_report(tenant_id)
            except Exception:
                logger.exception("Daily report generation failed")
