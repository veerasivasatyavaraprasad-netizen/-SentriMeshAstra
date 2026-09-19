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

    # Set by tests/conftest.py only. Switches the DB engine to NullPool:
    # pytest-asyncio gives each test function its own event loop, and an
    # asyncpg connection pool built in one loop can't be reused from
    # another — NullPool sidesteps that by never pooling, which is fine
    # for short-lived test runs and irrelevant to the real app (one
    # long-lived loop, pool_pre_ping as normal).
    testing: bool = False

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

    # Off by default. When true, supported actions (currently block_ip)
    # really execute via IPTablesExecutor against the HOST THIS BACKEND
    # RUNS ON — see app/connectors/executor.py. Only enable this where the
    # backend itself is the enforcement point (an edge/gateway host), and
    # only once you understand exactly what it will firewall.
    enable_real_response_execution: bool = False

    # AbuseIPDB — used by the Threat Intelligence agent for real IP
    # reputation when set; enrichment honestly reports "unknown" (never a
    # fabricated verdict) when this is unset or a lookup fails.
    abuseipdb_api_key: str | None = None

    # ipinfo.io — used by Detection's impossible-travel check to resolve
    # an IP to a country when the event's own source didn't already supply
    # one (Azure AD sign-in logs do; Wazuh/CloudTrail don't). Without this
    # set, impossible-travel detection only evaluates events whose source
    # already carries location data — it never guesses one.
    ipinfo_api_key: str | None = None

    # Additional IP reputation sources, aggregated alongside AbuseIPDB in
    # app/connectors/threat_feed.py. Each is entirely optional and
    # independent — set any subset and lookup_ip() queries only the ones
    # configured, in parallel, and folds a source's own failure into an
    # honest "unknown" for that source rather than the whole lookup.
    virustotal_api_key: str | None = None
    otx_api_key: str | None = None  # AlienVault OTX
    greynoise_api_key: str | None = None
    shodan_api_key: str | None = None
    # abuse.ch's shared Auth-Key (https://auth.abuse.ch) — used for the
    # ThreatFox indicator-of-compromise lookup.
    abusech_auth_key: str | None = None

    # SerpAPI — used by the Exposure agent's real-search OSINT step (does
    # the tenant's own domain turn up in Google results alongside
    # exposure-indicating terms — leaked files, breach mentions). Without
    # it, that step is simply skipped, never faked.
    serpapi_api_key: str | None = None

    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Login brute-force protection. Two independent counters: one per
    # email (stops someone hammering a single account) and one per source
    # IP (stops one source from spraying attempts across many accounts).
    # Either tripping locks out further attempts on that key until the
    # window rolls off.
    login_max_attempts_per_email: int = 8
    login_max_attempts_per_ip: int = 30
    login_lockout_window_seconds: int = 5 * 60


@lru_cache
def get_settings() -> Settings:
    return Settings()
