from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.database import get_db
from app.models import ActionProposal, User, UserRole
from app.schemas import ActionProposalOut

router = APIRouter(prefix="/api/tenants/{tenant_id}/actions", tags=["actions"])


def _check_tenant_access(user: User, tenant_id: str) -> None:
    if user.role != UserRole.ADMIN and user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Not authorized for this tenant")


@router.post("/{proposal_id}/rollback")
async def rollback_action(
    tenant_id: str,
    proposal_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Undo an already-executed action. Only a human can trigger this —
    same gate as approving in the first place. Against the default
    DryRunExecutor this just records a simulated rollback; against a real
    executor (e.g. IPTablesExecutor) it actually reverses the change."""
    _check_tenant_access(user, tenant_id)

    result = await db.execute(
        select(ActionProposal).where(ActionProposal.id == proposal_id, ActionProposal.tenant_id == tenant_id)
    )
    proposal = result.scalar_one_or_none()
    if not proposal:
        raise HTTPException(status_code=404, detail="Action not found")
    if not proposal.reversible:
        raise HTTPException(status_code=400, detail="This action was marked irreversible and has no rollback.")

    fleet = request.app.state.fleet
    outcome = await fleet.response.rollback(proposal_id)

    # `proposal` is already in this session's identity map from the SELECT
    # above; re-querying it wouldn't re-populate its attributes (SQLAlchemy
    # returns the cached object as-is). refresh() explicitly re-reads the
    # row that fleet.response.rollback() just committed in its own session.
    await db.refresh(proposal)
    return {"outcome": outcome, "action": ActionProposalOut.model_validate(proposal)}
