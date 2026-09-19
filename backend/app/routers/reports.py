from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.database import get_db
from app.models import Report, User, UserRole
from app.schemas import ReportOut

router = APIRouter(prefix="/api/tenants/{tenant_id}/reports", tags=["reports"])


def _check_tenant_access(user: User, tenant_id: str) -> None:
    if user.role != UserRole.ADMIN and user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Not authorized for this tenant")


@router.get("", response_model=list[ReportOut])
async def list_reports(tenant_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    _check_tenant_access(user, tenant_id)
    result = await db.execute(
        select(Report).where(Report.tenant_id == tenant_id).order_by(Report.created_at.desc()).limit(90)
    )
    return list(result.scalars())


@router.post("/generate-now", response_model=ReportOut)
async def generate_now(tenant_id: str, request: Request, user: User = Depends(get_current_user)):
    """Generate a report on demand instead of waiting for the daily schedule."""
    _check_tenant_access(user, tenant_id)
    fleet = request.app.state.fleet
    return await fleet.reporting.generate_daily_report(tenant_id)
