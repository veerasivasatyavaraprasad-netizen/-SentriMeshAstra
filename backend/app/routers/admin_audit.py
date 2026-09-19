from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_admin
from app.database import get_db
from app.models import AuditLogEntry, User
from app.schemas import AuditLogOut

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/platform-audit", response_model=list[AuditLogOut])
async def platform_audit(db: AsyncSession = Depends(get_db), _: User = Depends(require_admin)):
    """Platform-level security events not tied to any one tenant — today,
    that's login attempts and lockouts (app/ratelimit.py). Admin-only: a
    security holder has no reason to see login activity against accounts
    that aren't theirs."""
    result = await db.execute(
        select(AuditLogEntry).where(AuditLogEntry.tenant_id.is_(None)).order_by(AuditLogEntry.created_at.desc()).limit(200)
    )
    return list(result.scalars())
