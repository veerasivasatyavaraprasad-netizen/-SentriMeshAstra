"""Thin wrapper around the Claude API for agent reasoning.

Used for tasks that benefit from language understanding: summarizing an
incident in plain English, writing the daily report narrative, explaining
why an action was proposed. All *decisions* (severity classification,
autonomy tier, policy allow/deny) are made by deterministic rule-based
logic in app/policy and app/agents — the LLM is only ever used to explain
or narrate, never to unilaterally decide something that a customer's
approval or the policy engine should decide. If no API key is configured,
callers fall back to a plain deterministic template so the platform stays
fully functional without it.
"""
import logging

from app.config import get_settings

logger = logging.getLogger("sentrimesh.llm")

_client = None


def _get_client():
    global _client
    settings = get_settings()
    if not settings.anthropic_api_key:
        return None
    if _client is None:
        import anthropic

        _client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
    return _client


async def summarize(prompt: str, *, max_tokens: int = 400, fallback: str) -> str:
    """Ask Claude to produce a short natural-language summary. Returns
    `fallback` untouched if no API key is configured or the call fails —
    callers should always pass a deterministic fallback so a missing key
    never breaks the pipeline."""
    settings = get_settings()
    client = _get_client()
    if client is None:
        return fallback
    try:
        response = client.messages.create(
            model=settings.anthropic_model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(block.text for block in response.content if hasattr(block, "text"))
        return text.strip() or fallback
    except Exception:
        logger.exception("Claude API call failed, using fallback text")
        return fallback
