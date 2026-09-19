import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.agents.runner import AgentFleet
from app.auth import bootstrap_admin
from app.bus import get_bus
from app.config import get_settings
from app.database import AsyncSessionLocal, init_models
from app.routers import activity, approvals, auth, connectors, incidents, ingest, overview, reports, tenants

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_models()
    async with AsyncSessionLocal() as db:
        await bootstrap_admin(db)

    bus = await get_bus()
    fleet = AgentFleet(bus)
    await fleet.start()
    app.state.fleet = fleet
    app.state.bus = bus

    logging.getLogger("sentrimesh.main").info(
        "SentriMeshAstra online. Bootstrap admin: %s", settings.bootstrap_admin_email
    )
    yield

    await fleet.stop()
    await bus.close()


app = FastAPI(title="SentriMeshAstra", version="0.1.0", lifespan=lifespan)

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
app.include_router(reports.router)
app.include_router(activity.router)
app.include_router(overview.router)
app.include_router(connectors.router)


@app.get("/api/health")
async def health():
    return {"status": "ok", "app": settings.app_name}
