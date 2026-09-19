from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings

settings = get_settings()

engine = create_async_engine(settings.database_url, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session


async def init_models() -> None:
    """Create tables if they don't exist.

    For an MVP this replaces Alembic migrations. Before any production
    deployment, switch to versioned Alembic migrations instead of
    create_all — this is called out again in README.md's roadmap.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
