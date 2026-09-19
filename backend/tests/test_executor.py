import os
import shutil

import pytest

from app.connectors.executor import DryRunExecutor, IPTablesExecutor

requires_iptables = pytest.mark.skipif(
    shutil.which("iptables") is None or os.geteuid() != 0,
    reason="iptables integration test needs root and iptables (CI/sandboxes without either skip it)",
)


@pytest.mark.asyncio
async def test_dry_run_executor_never_touches_real_state():
    executor = DryRunExecutor()
    result = await executor.execute("block_ip", {"ip": "203.0.113.5"})
    assert result.simulated is True
    assert result.success is True


@pytest.mark.asyncio
async def test_iptables_executor_rejects_invalid_ip():
    executor = IPTablesExecutor()
    result = await executor.execute("block_ip", {"ip": "not-an-ip; rm -rf /"})
    assert result.success is False
    assert "invalid" in result.detail.lower()


@pytest.mark.asyncio
async def test_iptables_executor_refuses_unsupported_action():
    executor = IPTablesExecutor()
    result = await executor.execute("disable_account", {"user": "bob"})
    assert result.success is False
    assert "does not support" in result.detail.lower()


@requires_iptables
@pytest.mark.asyncio
async def test_iptables_executor_block_then_rollback_round_trip():
    executor = IPTablesExecutor()
    test_ip = "203.0.113.250"  # TEST-NET-3, never a real host

    try:
        assert not await executor._rule_exists(test_ip)

        block_result = await executor.execute("block_ip", {"ip": test_ip})
        assert block_result.success is True
        assert block_result.simulated is False
        assert await executor._rule_exists(test_ip)

        # Executing again should be idempotent, not add a second rule.
        second_block = await executor.execute("block_ip", {"ip": test_ip})
        assert second_block.success is True

        rollback_result = await executor.rollback("block_ip", {"ip": test_ip})
        assert rollback_result.success is True
        assert not await executor._rule_exists(test_ip)
    finally:
        # Best-effort cleanup even if an assertion above failed.
        if await executor._rule_exists(test_ip):
            await executor.rollback("block_ip", {"ip": test_ip})
