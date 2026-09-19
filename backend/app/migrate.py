"""Run Alembic migrations programmatically at startup.

Replaces the old create_all()-on-boot approach: schema changes now go
through versioned migrations in alembic/versions/, while still keeping a
"just run uvicorn and it works" experience for local dev — this runs
`alembic upgrade head` automatically before the app starts serving.

Alembic's `command.upgrade` is synchronous and, via alembic/env.py, calls
asyncio.run() internally. Since this itself runs inside FastAPI's async
lifespan (an already-running event loop), it's dispatched to a worker
thread with run_in_executor — that thread has no running loop of its own,
so alembic's asyncio.run() there is safe.
"""
import asyncio
import logging
from pathlib import Path

from alembic import command
from alembic.config import Config

logger = logging.getLogger("sentrimesh.migrate")

BACKEND_DIR = Path(__file__).resolve().parents[1]


def _upgrade_head() -> None:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    command.upgrade(cfg, "head")


async def run_migrations() -> None:
    logger.info("Running database migrations (alembic upgrade head)...")
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _upgrade_head)
    logger.info("Migrations complete.")
