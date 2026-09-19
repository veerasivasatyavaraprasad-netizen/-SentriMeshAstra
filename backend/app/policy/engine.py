"""The policy engine: decides which autonomy tier a proposed action gets.

This is the single place that decides whether something runs automatically,
needs one tap of approval, or must go to a human before anything happens.
Keeping it in one small, readable module (rather than scattered across
agents) is deliberate — it's the thing you audit and tune per customer.
"""
from dataclasses import dataclass

from app.models import AutonomyTier, Severity

# Actions considered destructive or hard to reverse are NEVER auto-run or
# one-tap, regardless of severity. This set is intentionally conservative;
# adding to it is safe, removing from it should require the admin's sign-off.
TIER3_ACTIONS = {
    "disable_account",
    "delete_resource",
    "revoke_all_sessions",
    "wipe_endpoint",
    "terminate_instance",
    "delete_user",
}

# Actions that change access/connectivity but are cleanly reversible.
TIER2_ACTIONS = {
    "block_ip",
    "quarantine_endpoint",
    "force_password_reset",
    "disable_forwarding_rule",
    "revoke_api_key",
}

# Read-only / low-blast-radius actions.
TIER1_ACTIONS = {
    "enrich_indicator",
    "tag_incident",
    "notify",
    "open_ticket",
    "rate_limit_ip",
}

ACTION_REVERSIBILITY = {
    "disable_account": (True, "Re-enable the account via the same connector."),
    "delete_resource": (False, "No automatic rollback — this action is irreversible by design."),
    "revoke_all_sessions": (True, "Sessions re-establish on next successful login; no data lost."),
    "wipe_endpoint": (False, "No automatic rollback — this action is irreversible by design."),
    "terminate_instance": (False, "No automatic rollback unless a snapshot/backup exists."),
    "delete_user": (False, "No automatic rollback — this action is irreversible by design."),
    "block_ip": (True, "Remove the IP from the block list."),
    "quarantine_endpoint": (True, "Restore normal network access to the endpoint."),
    "force_password_reset": (True, "No rollback needed; user sets a new password."),
    "disable_forwarding_rule": (True, "Re-enable the forwarding rule."),
    "revoke_api_key": (True, "Issue a new API key."),
    "enrich_indicator": (True, "No system state changes."),
    "tag_incident": (True, "Remove the tag."),
    "notify": (True, "No system state changes."),
    "open_ticket": (True, "Close the ticket."),
    "rate_limit_ip": (True, "Remove the rate limit."),
}


@dataclass
class PolicyDecision:
    tier: AutonomyTier
    reversible: bool
    rollback_plan: str
    reasoning: str


def classify_action(action_type: str, severity: Severity) -> PolicyDecision:
    reversible, rollback_plan = ACTION_REVERSIBILITY.get(
        action_type, (False, "Unknown action type — treated as irreversible until reviewed.")
    )

    if action_type in TIER3_ACTIONS or not reversible:
        tier = AutonomyTier.TIER3_HUMAN_ONLY
        reasoning = f"'{action_type}' is destructive or irreversible — human decision required, no exceptions."
    elif action_type in TIER2_ACTIONS:
        # Even a normally one-tap action escalates to human-only at critical
        # severity, since that's when a wrong automated call costs the most.
        if severity == Severity.CRITICAL:
            tier = AutonomyTier.TIER3_HUMAN_ONLY
            reasoning = f"'{action_type}' is normally one-tap, escalated to human-only due to CRITICAL severity."
        else:
            tier = AutonomyTier.TIER2_ONE_TAP
            reasoning = f"'{action_type}' is reversible but changes access/connectivity — one-tap approval."
    elif action_type in TIER1_ACTIONS:
        tier = AutonomyTier.TIER1_AUTO
        reasoning = f"'{action_type}' is read-only / low blast radius — auto-approved."
    else:
        tier = AutonomyTier.TIER3_HUMAN_ONLY
        reasoning = f"Unrecognized action type '{action_type}' — defaulting to human-only for safety."

    return PolicyDecision(tier=tier, reversible=reversible, rollback_plan=rollback_plan, reasoning=reasoning)


def severity_from_signals(*, failed_login_count: int, malicious_indicator: bool, new_admin_activity: bool) -> Severity:
    """Deterministic severity scoring used by the Orchestrator.

    Kept simple and explainable on purpose: every score is one you can
    justify to a customer in a sentence, which matters more here than
    squeezing out extra detection sensitivity.
    """
    score = 0
    if failed_login_count >= 20:
        score += 2
    elif failed_login_count >= 5:
        score += 1
    if malicious_indicator:
        score += 2
    if new_admin_activity:
        score += 1

    if score >= 4:
        return Severity.CRITICAL
    if score == 3:
        return Severity.HIGH
    if score >= 1:
        return Severity.MEDIUM
    return Severity.LOW
