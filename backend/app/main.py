import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.agents.runner import AgentFleet
from app.auth import bootstrap_admin
from app.bus import get_bus
from app.config import get_settings
from app.database import AsyncSessionLocal
from app.migrate import run_migrations
from app.routers import (
    actions,
    activity,
    admin_audit,
    approvals,
    auth,
    connectors,
    incidents,
    ingest,
    overview,
    reports,
    tenants,
    ws,
)
from app.security_headers import SecurityHeadersMiddleware

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
settings = get_settings()
logger = logging.getLogger("sentrimesh.main")

_INSECURE_DEFAULTS = {
    "JWT_SECRET": "change-me-in-production-this-is-not-a-real-secret",
    "BOOTSTRAP_ADMIN_PASSWORD": "ChangeMe!12345",
}


def _warn_on_insecure_defaults() -> None:
    """A loud, impossible-to-miss log line beats a silent footgun — this
    is exactly the kind of thing 'our own platform must be secure' means
    in practice: don't let a demo default quietly become a production
    credential because nobody noticed the .env was never edited."""
    if settings.jwt_secret == _INSECURE_DEFAULTS["JWT_SECRET"]:
        logger.warning(
            "!! JWT_SECRET is still the placeholder default. Every token this instance issues is forgeable "
            "by anyone who reads this repo. Set a real JWT_SECRET before this is reachable by anyone but you."
        )
    if settings.bootstrap_admin_password == _INSECURE_DEFAULTS["BOOTSTRAP_ADMIN_PASSWORD"]:
        logger.warning(
            "!! BOOTSTRAP_ADMIN_PASSWORD is still the placeholder default. Change it (and log in and change "
            "it again if this instance already booted with it) before this is reachable by anyone but you."
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    _warn_on_insecure_defaults()
    await run_migrations()
    async with AsyncSessionLocal() as db:
        await bootstrap_admin(db)

    bus = await get_bus()
    fleet = AgentFleet(bus)
    await fleet.start()
    app.state.fleet = fleet
    app.state.bus = bus

    logger.info("SentriMeshAstra online. Bootstrap admin: %s", settings.bootstrap_admin_email)
    yield

    await fleet.stop()
    await bus.close()


app = FastAPI(title="SentriMeshAstra", version="0.1.0", lifespan=lifespan)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(tenants.router)
app.include_router(ingest.router)
app.include_router(incidents.router)
app.include_router(approvals.router)
app.include_router(actions.router)
app.include_router(reports.router)
app.include_router(activity.router)
app.include_router(overview.router)
app.include_router(connectors.router)
app.include_router(admin_audit.router)
app.include_router(ws.router)


@app.get("/api/health")
async def health():
    return {"status": "ok", "app": settings.app_name}
