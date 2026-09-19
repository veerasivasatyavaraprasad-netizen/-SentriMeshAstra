"""Central configuration, loaded from environment variables.

Nothing here has a hardcoded secret. Every credential-shaped value has a
non-functional default so the app boots for local/demo use without any
external service configured, and safely no-ops (rather than silently
guessing) when a real integration is missing.
"""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "SentriMeshAstra"
    environment: str = "development"

    database_url: str = "postgresql+asyncpg://sentrimesh:sentrimesh@localhost:5432/sentrimesh"
    redis_url: str = "redis://localhost:6379/0"

    jwt_secret: str = "change-me-in-production-this-is-not-a-real-secret"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60 * 12

    # Bootstrap admin account, created on first startup if no admin exists yet.
    bootstrap_admin_email: str = "admin@sentrimeshastra.local"
    bootstrap_admin_password: str = "ChangeMe!12345"

    # Claude API — used for agent reasoning/narrative generation.
    # Agents fall back to deterministic rule-based logic when this is unset,
    # so the platform is fully functional (if less articulate) without it.
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-sonnet-5"

    # SMTP — used for notifications. When unset, notifications are logged
    # and stored in-app instead of sent, never silently dropped.
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from: str = "alerts@sentrimeshastra.local"
    notify_to_email: str | None = None

    # Global kill switch default. Per-tenant switches live in the DB;
    # this is the platform-wide fallback checked before any Response
    # agent execution.
    global_autonomy_enabled: bool = True

    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]


@lru_cache
def get_settings() -> Settings:
    return Settings()
