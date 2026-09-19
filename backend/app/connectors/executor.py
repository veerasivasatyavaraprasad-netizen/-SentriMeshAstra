"""Response action execution.

This MVP ships a dry-run executor: every action is logged, stored, and
its intended effect is simulated, but nothing reaches a real firewall,
IdP, or EDR yet. Wiring a specific customer's actual infrastructure
(AWS Security Groups, Azure AD, CrowdStrike, etc.) is a per-connector
follow-up — see README.md roadmap. The interface below is the seam:
add a new class implementing `execute()` per integration and select it
by tenant connector config, without touching the Response agent itself.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ExecutionResult:
    success: bool
    detail: str
    simulated: bool = True


class ActionExecutor(ABC):
    @abstractmethod
    async def execute(self, action_type: str, parameters: dict) -> ExecutionResult:
        ...


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


def get_executor(tenant_connector_config: dict | None = None) -> ActionExecutor:
    # Placeholder for per-tenant selection once live integrations exist.
    return DryRunExecutor()
