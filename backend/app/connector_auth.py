"""Machine-to-machine auth for connectors (a real SIEM/log forwarder),
separate from the human JWT session auth in app/auth.py.

A connector's secret token is shown exactly once, at creation or
rotation, and only its SHA-256 hash is ever stored — the same principle
as a password, minus the slow KDF, because this is a high-entropy
generated secret (32 random bytes), not a human-chosen one an attacker
could dictionary-guess. A fast hash is the right tradeoff here: it needs
to run on every ingested event without becoming the bottleneck.
"""
import hashlib
import secrets

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ConnectorConfig

TOKEN_PREFIX = "smac_"  # SentriMeshAstra Connector — lets callers and us tell a connector token from a user JWT at a glance


def generate_token() -> tuple[str, str]:
    """Returns (raw_token, sha256_hex_hash). Store only the hash."""
    raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
    return raw, hash_token(raw)


def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()


def is_connector_token(bearer_value: str) -> bool:
    return bearer_value.startswith(TOKEN_PREFIX)


async def authenticate_connector(token: str, tenant_id: str, db: AsyncSession) -> ConnectorConfig | None:
    result = await db.execute(
        select(ConnectorConfig).where(
            ConnectorConfig.tenant_id == tenant_id,
            ConnectorConfig.token_hash == hash_token(token),
            ConnectorConfig.is_active.is_(True),
        )
    )
    return result.scalar_one_or_none()
