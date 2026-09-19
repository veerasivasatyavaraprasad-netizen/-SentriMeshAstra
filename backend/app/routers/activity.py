from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.database import get_db
from app.models import AuditLogEntry, User, UserRole
from app.schemas import AuditLogOut

router = APIRouter(prefix="/api/tenants/{tenant_id}/activity", tags=["activity"])


def _check_tenant_access(user: User, tenant_id: str) -> None:
    if user.role != UserRole.ADMIN and user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Not authorized for this tenant")


@router.get("", response_model=list[AuditLogOut])
async def list_activity(tenant_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """The full agent conversation and every human decision, in order.
    This is the Guardian's ledger, surfaced to the console."""
    _check_tenant_access(user, tenant_id)
    result = await db.execute(
        select(AuditLogEntry)
        .where(AuditLogEntry.tenant_id == tenant_id)
        .order_by(AuditLogEntry.created_at.desc())
        .limit(500)
    )
    return list(result.scalars())
