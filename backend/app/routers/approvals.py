from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.bus import CH_ACTIONS_APPROVED, CH_ACTIONS_DENIED, get_bus
from app.database import get_db
from app.models import ActionProposal, ApprovalRequest, ApprovalStatus, User, UserRole
from app.schemas import ApprovalDecision, ApprovalOut

router = APIRouter(prefix="/api/tenants/{tenant_id}/approvals", tags=["approvals"])


def _check_tenant_access(user: User, tenant_id: str) -> None:
    if user.role != UserRole.ADMIN and user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Not authorized for this tenant")


@router.get("", response_model=list[ApprovalOut])
async def list_approvals(
    tenant_id: str,
    status_filter: ApprovalStatus | None = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _check_tenant_access(user, tenant_id)
    query = select(ApprovalRequest).where(ApprovalRequest.tenant_id == tenant_id)
    if status_filter:
        query = query.where(ApprovalRequest.status == status_filter)
    result = await db.execute(query.order_by(ApprovalRequest.created_at.desc()))
    approvals = list(result.scalars())

    out = []
    for approval in approvals:
        action_result = await db.execute(
            select(ActionProposal).where(ActionProposal.id == approval.action_proposal_id)
        )
        action = action_result.scalar_one_or_none()
        item = ApprovalOut.model_validate(approval)
        item.action = action
        out.append(item)
    return out


@router.post("/{approval_id}/decide", response_model=ApprovalOut)
async def decide_approval(
    tenant_id: str,
    approval_id: str,
    payload: ApprovalDecision,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Only a human — the platform admin or the company's own security
    holder — can resolve a pending approval. This is the one gate that no
    agent, including the Orchestrator, can move past on its own."""
    _check_tenant_access(user, tenant_id)

    result = await db.execute(
        select(ApprovalRequest).where(ApprovalRequest.id == approval_id, ApprovalRequest.tenant_id == tenant_id)
    )
    approval = result.scalar_one_or_none()
    if not approval:
        raise HTTPException(status_code=404, detail="Approval request not found")
    if approval.status != ApprovalStatus.PENDING:
        raise HTTPException(status_code=400, detail=f"Approval already {approval.status.value}")

    approval.status = ApprovalStatus.APPROVED if payload.approve else ApprovalStatus.REJECTED
    approval.decided_by_user_id = user.id
    approval.decided_at = datetime.utcnow()
    approval.decision_note = payload.note
    await db.commit()
    await db.refresh(approval)

    bus = await get_bus()
    channel = CH_ACTIONS_APPROVED if payload.approve else CH_ACTIONS_DENIED
    await bus.publish(
        channel,
        {"tenant_id": tenant_id, "approval_id": approval.id, "proposal_id": approval.action_proposal_id, "decided_by": user.email},
        actor=user.email,
        tenant_id=tenant_id,
    )

    if payload.approve:
        fleet = request.app.state.fleet
        await fleet.response.execute_approved(approval.action_proposal_id)

    action_result = await db.execute(select(ActionProposal).where(ActionProposal.id == approval.action_proposal_id))
    out = ApprovalOut.model_validate(approval)
    out.action = action_result.scalar_one_or_none()
    return out
