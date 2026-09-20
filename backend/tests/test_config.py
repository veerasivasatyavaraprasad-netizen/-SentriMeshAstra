"""Tests app/config.py's database_url normalization — the real
deployment gotcha where managed Postgres providers (Render, Heroku,
Railway, ...) hand out a plain postgres:// or postgresql:// URL, but
SQLAlchemy's async engine needs the asyncpg driver named explicitly."""
from app.config import Settings


def test_plain_postgres_scheme_is_rewritten_to_asyncpg():
    settings = Settings(database_url="postgres://user:pass@host:5432/dbname")
    assert settings.database_url == "postgresql+asyncpg://user:pass@host:5432/dbname"


def test_plain_postgresql_scheme_is_rewritten_to_asyncpg():
    settings = Settings(database_url="postgresql://user:pass@host:5432/dbname")
    assert settings.database_url == "postgresql+asyncpg://user:pass@host:5432/dbname"


def test_already_correct_scheme_is_left_untouched():
    url = "postgresql+asyncpg://user:pass@host:5432/dbname"
    settings = Settings(database_url=url)
    assert settings.database_url == url
