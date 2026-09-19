"""Response action execution.

Two executors ship today:

- DryRunExecutor (default): logs and simulates. Changes nothing outside
  SentriMeshAstra's own database. Safe default for pilots before a
  customer wires up real infrastructure credentials.
- IPTablesExecutor: really blocks/unblocks an IP via the host's iptables.
  This is a genuine, working integration — not a mock — but it firewalls
  *the machine this backend runs on*. It is only sensible to enable where
  this backend IS the enforcement point (an edge box, a bastion, a
  customer's own gateway host it's been deployed onto), never a shared
  app server. It is off by default and gated by
  ENABLE_REAL_RESPONSE_EXECUTION, an explicit opt-in.

Wiring a specific customer's cloud infrastructure (AWS Security Groups,
Azure AD, CrowdStrike, etc. — reaching out to *their* environment rather
than firewalling this host) is a per-connector follow-up — see README.md
roadmap. The ActionExecutor interface is the seam: add a new class
implementing execute()/rollback() per integration and select it by tenant
connector config, without touching the Response agent itself.
"""
import asyncio
import ipaddress
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass

from app.config import get_settings

logger = logging.getLogger("sentrimesh.executor")

IPTABLES_COMMENT = "sentrimesh-managed"


@dataclass
class ExecutionResult:
    success: bool
    detail: str
    simulated: bool = True


class ActionExecutor(ABC):
    @abstractmethod
    async def execute(self, action_type: str, parameters: dict) -> ExecutionResult:
        ...

    async def rollback(self, action_type: str, parameters: dict) -> ExecutionResult:
        return ExecutionResult(
            success=False,
            detail=f"This executor does not support rolling back '{action_type}'.",
            simulated=True,
        )


class DryRunExecutor(ActionExecutor):
    """Default executor. Records what *would* happen; changes nothing
    outside SentriMeshAstra's own database. Safe default for pilots
    before a customer wires up real infrastructure credentials."""

    async def execute(self, action_type: str, parameters: dict) -> ExecutionResult:
        return ExecutionResult(
            success=True,
            detail=f"[DRY RUN] Would execute '{action_type}' with parameters={parameters}. "
            "No real infrastructure was modified — connect a live integration to enable real execution.",
            simulated=True,
        )

    async def rollback(self, action_type: str, parameters: dict) -> ExecutionResult:
        return ExecutionResult(
            success=True,
            detail=f"[DRY RUN] Would roll back '{action_type}' with parameters={parameters}.",
            simulated=True,
        )


class IPTablesExecutor(ActionExecutor):
    """Really blocks/unblocks an IP address on this host via iptables.

    Only handles block_ip — every other action type is refused rather than
    silently simulated, so a caller never mistakes "not supported" for
    "done". IP addresses are validated with the stdlib ipaddress module
    before ever reaching a subprocess, and the rule is always invoked as
    an argument list (never through a shell), so there is no command
    injection surface even from a malformed/hostile IP string.
    """

    SUPPORTED_ACTIONS = {"block_ip"}

    async def execute(self, action_type: str, parameters: dict) -> ExecutionResult:
        if action_type not in self.SUPPORTED_ACTIONS:
            return ExecutionResult(
                success=False,
                detail=f"IPTablesExecutor does not support '{action_type}' — only {self.SUPPORTED_ACTIONS}.",
                simulated=True,
            )
        ip = self._validate_ip(parameters.get("ip"))
        if ip is None:
            return ExecutionResult(success=False, detail=f"Refusing to block invalid IP: {parameters.get('ip')!r}", simulated=True)

        if await self._rule_exists(ip):
            return ExecutionResult(success=True, detail=f"{ip} is already blocked (rule already present).", simulated=False)

        code, out = await self._run(["iptables", "-I", "INPUT", "-s", ip, "-m", "comment", "--comment", IPTABLES_COMMENT, "-j", "DROP"])
        if code != 0:
            return ExecutionResult(success=False, detail=f"iptables failed to block {ip}: {out}", simulated=False)
        return ExecutionResult(success=True, detail=f"Blocked {ip} via iptables DROP rule on INPUT.", simulated=False)

    async def rollback(self, action_type: str, parameters: dict) -> ExecutionResult:
        if action_type not in self.SUPPORTED_ACTIONS:
            return ExecutionResult(success=False, detail=f"IPTablesExecutor does not support rolling back '{action_type}'.", simulated=True)
        ip = self._validate_ip(parameters.get("ip"))
        if ip is None:
            return ExecutionResult(success=False, detail=f"Refusing to unblock invalid IP: {parameters.get('ip')!r}", simulated=True)

        if not await self._rule_exists(ip):
            return ExecutionResult(success=True, detail=f"{ip} was not blocked (nothing to roll back).", simulated=False)

        code, out = await self._run(["iptables", "-D", "INPUT", "-s", ip, "-m", "comment", "--comment", IPTABLES_COMMENT, "-j", "DROP"])
        if code != 0:
            return ExecutionResult(success=False, detail=f"iptables failed to unblock {ip}: {out}", simulated=False)
        return ExecutionResult(success=True, detail=f"Unblocked {ip} — removed the iptables DROP rule.", simulated=False)

    @staticmethod
    def _validate_ip(value) -> str | None:
        if not isinstance(value, str):
            return None
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None

    async def _rule_exists(self, ip: str) -> bool:
        code, _ = await self._run(["iptables", "-C", "INPUT", "-s", ip, "-m", "comment", "--comment", IPTABLES_COMMENT, "-j", "DROP"])
        return code == 0

    @staticmethod
    async def _run(args: list[str]) -> tuple[int, str]:
        proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await proc.communicate()
        return proc.returncode, out.decode(errors="replace").strip()


def get_executor(action_type: str | None = None, tenant_connector_config: dict | None = None) -> ActionExecutor:
    settings = get_settings()
    if settings.enable_real_response_execution and action_type in IPTablesExecutor.SUPPORTED_ACTIONS:
        return IPTablesExecutor()
    return DryRunExecutor()
