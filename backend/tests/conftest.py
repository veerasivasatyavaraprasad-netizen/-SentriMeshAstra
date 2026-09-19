"""Test configuration.

Sets environment variables BEFORE any `app.*` module is imported, since
app/database.py builds its SQLAlchemy engine (and other modules read
settings) at import time via a cached get_settings(). pytest loads
conftest.py ahead of collecting test modules in the same directory, so
this ordering is safe — but it's also why this file must never import
`app.*` above the os.environ block below.

Integration tests run against a real, dedicated `sentrimesh_test`
database (dropped and recreated once per test session) and a separate
Redis logical database (index 1) — never the developer's own dev data.
"""
import os
import urllib.parse

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://sentrimesh:sentrimesh@localhost:5432/sentrimesh_test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/1")
os.environ.setdefault("BOOTSTRAP_ADMIN_EMAIL", "integration-admin@example.com")
os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "IntegrationTestPass123!")
os.environ.setdefault("JWT_SECRET", "test-only-secret-never-use-in-production")
os.environ.setdefault("ENABLE_REAL_RESPONSE_EXECUTION", "false")
os.environ.setdefault("TESTING", "true")

import httpx  # noqa: E402
import psycopg2  # noqa: E402
import pytest  # noqa: E402


def _sync_admin_dsn() -> str:
    """A plain psycopg2 DSN to Postgres's default 'postgres' maintenance
    database, derived from DATABASE_URL, for drop/create DDL that can't
    run inside the app's own async engine (you can't DROP a database
    you're connected to)."""
    parsed = urllib.parse.urlparse(os.environ["DATABASE_URL"].replace("+asyncpg", ""))
    return urllib.parse.urlunparse(parsed._replace(path="/postgres"))


def _test_db_name() -> str:
    return urllib.parse.urlparse(os.environ["DATABASE_URL"]).path.lstrip("/")


@pytest.fixture(scope="session", autouse=True)
def _fresh_test_database():
    """Drop and recreate the integration test database once per test
    session, so tests start from a known-empty state (a stale admin user
    or tenant from a previous run would otherwise silently break
    bootstrap_admin's "only if no admin exists yet" check)."""
    db_name = _test_db_name()
    conn = psycopg2.connect(_sync_admin_dsn())
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(f'DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE)')
        cur.execute(f'CREATE DATABASE "{db_name}"')
    conn.close()
    yield


@pytest.fixture
async def client():
    """A fresh app client per test: runs the real FastAPI lifespan
    (Alembic migrations, admin bootstrap, all 8 agents started on a real
    Redis-backed bus) against the dedicated test database, then tears it
    all down. The module-level bus singleton is reset first — otherwise
    the second test in a session would reuse a bus connection this
    fixture already closed at the end of the first test.
    """
    import app.bus as bus_module
    from app.main import app

    bus_module._bus = None
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac
