from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import create_access_token, get_current_user, hash_password, require_admin, verify_password
from app.bus import get_bus
from app.database import get_db
from app.models import User, UserRole
from app.ratelimit import check_lockout, client_ip, record_failed_attempt
from app.schemas import LoginRequest, SecurityHolderCreate, Token, UserOut

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=Token)
async def login(payload: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    bus = await get_bus()
    ip = client_ip(request)

    lockout = await check_lockout(bus, email=payload.email, ip=ip)
    if lockout.locked:
        await bus.audit(
            actor=payload.email,
            action="login_locked_out",
            payload={"ip": ip, "reason": lockout.reason},
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts ({lockout.reason}). Try again shortly.",
            headers={"Retry-After": str(lockout.retry_after_seconds)},
        )

    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()
    if user is None or not verify_password(payload.password, user.hashed_password) or not user.is_active:
        await record_failed_attempt(bus, email=payload.email, ip=ip)
        await bus.audit(actor=payload.email, action="login_failed", payload={"ip": ip})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token = create_access_token(user)
    return Token(access_token=token, role=user.role, tenant_id=user.tenant_id)


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(get_current_user)):
    return user


@router.post("/security-holders", response_model=UserOut)
async def create_security_holder(
    payload: SecurityHolderCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
):
    """Only the platform admin creates the company's security-holder login —
    this is the one person per company empowered to approve critical actions."""
    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=UserRole.SECURITY_HOLDER,
        tenant_id=payload.tenant_id,
        full_name=payload.full_name,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user
