from app.models import AutonomyTier, Severity
from app.policy.engine import classify_action, severity_from_signals


def test_destructive_action_always_human_only_even_at_low_severity():
    decision = classify_action("disable_account", Severity.LOW)
    assert decision.tier == AutonomyTier.TIER3_HUMAN_ONLY


def test_irreversible_unknown_action_defaults_to_human_only():
    decision = classify_action("something_never_seen_before", Severity.LOW)
    assert decision.tier == AutonomyTier.TIER3_HUMAN_ONLY


def test_reversible_tier2_action_is_one_tap_at_medium_severity():
    decision = classify_action("block_ip", Severity.MEDIUM)
    assert decision.tier == AutonomyTier.TIER2_ONE_TAP
    assert decision.reversible is True


def test_tier2_action_escalates_to_human_only_at_critical_severity():
    decision = classify_action("block_ip", Severity.CRITICAL)
    assert decision.tier == AutonomyTier.TIER3_HUMAN_ONLY


def test_readonly_action_is_auto_tier1():
    decision = classify_action("enrich_indicator", Severity.HIGH)
    assert decision.tier == AutonomyTier.TIER1_AUTO


def test_severity_scoring_thresholds():
    assert severity_from_signals(failed_login_count=0, malicious_indicator=False, new_admin_activity=False) == Severity.LOW
    assert severity_from_signals(failed_login_count=6, malicious_indicator=False, new_admin_activity=False) == Severity.MEDIUM
    assert (
        severity_from_signals(failed_login_count=6, malicious_indicator=True, new_admin_activity=False)
        == Severity.HIGH
    )
    assert (
        severity_from_signals(failed_login_count=25, malicious_indicator=True, new_admin_activity=True)
        == Severity.CRITICAL
    )
