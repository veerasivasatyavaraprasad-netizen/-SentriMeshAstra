from datetime import datetime, timedelta

from sqlalchemy import select

from app.agents.base import Agent
from app.bus import CH_REPORTS_READY
from app.llm import summarize
from app.models import ActionProposal, Incident, Report, Severity, Tenant
from app.notifications.email import send_email


class ReportingAgent(Agent):
    """Agent 7: compliance mapping and daily/monthly reporting. Triggered
    by the scheduler in app/agents/runner.py or on demand via the API."""

    name = "reporting"

    async def register(self) -> None:
        return  # scheduled, not event-driven

    async def generate_daily_report(self, tenant_id: str) -> Report:
        period_end = datetime.utcnow()
        period_start = period_end - timedelta(days=1)

        async with self.session() as db:
            tenant_result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
            tenant = tenant_result.scalar_one_or_none()

            incidents_result = await db.execute(
                select(Incident).where(
                    Incident.tenant_id == tenant_id,
                    Incident.created_at >= period_start,
                    Incident.created_at <= period_end,
                )
            )
            incidents = list(incidents_result.scalars())

            actions_result = await db.execute(
                select(ActionProposal).where(
                    ActionProposal.tenant_id == tenant_id,
                    ActionProposal.created_at >= period_start,
                    ActionProposal.created_at <= period_end,
                )
            )
            actions = list(actions_result.scalars())

            by_severity = {s.value: 0 for s in Severity}
            for incident in incidents:
                by_severity[incident.severity.value] += 1

            executed_actions = [a for a in actions if a.executed]
            pending_actions = [a for a in actions if not a.executed]

            fallback_summary = (
                f"{len(incidents)} incident(s) detected in the last 24 hours "
                f"({by_severity['critical']} critical, {by_severity['high']} high, "
                f"{by_severity['medium']} medium, {by_severity['low']} low). "
                f"{len(executed_actions)} action(s) executed, {len(pending_actions)} pending approval. "
                f"Kill switch: {'ENGAGED' if tenant and tenant.kill_switch_engaged else 'off'}."
            )

            prompt = (
                "Write a concise 3-4 sentence daily security report for a non-technical business "
                f"owner, based on this data: {len(incidents)} incidents "
                f"(critical={by_severity['critical']}, high={by_severity['high']}, "
                f"medium={by_severity['medium']}, low={by_severity['low']}), "
                f"{len(executed_actions)} automated actions executed, {len(pending_actions)} awaiting their approval. "
                "Plain language, no jargon, end with a clear 'what you need to do' line if anything is pending."
            )
            narrative = await summarize(prompt, fallback=fallback_summary)

            report = Report(
                tenant_id=tenant_id,
                report_type="daily",
                period_start=period_start,
                period_end=period_end,
                summary=narrative,
                body={
                    "incident_count": len(incidents),
                    "by_severity": by_severity,
                    "executed_actions": len(executed_actions),
                    "pending_actions": len(pending_actions),
                    "incident_ids": [i.id for i in incidents],
                },
            )
            db.add(report)
            await db.commit()
            await db.refresh(report)

        sent = await send_email(subject="Daily Security Report", body=report.summary)
        if sent:
            async with self.session() as db:
                result = await db.execute(select(Report).where(Report.id == report.id))
                fresh = result.scalar_one()
                fresh.emailed = True
                await db.commit()

        await self.publish(CH_REPORTS_READY, {"tenant_id": tenant_id, "report_id": report.id}, tenant_id=tenant_id)
        return report
