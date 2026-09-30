from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Decision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    HUMAN_APPROVAL = "HUMAN_APPROVAL"


@dataclass
class ActionRequest:
    agent_id: str
    action: str
    resource: str
    parameters: dict[str, Any]


class PolicyEngine:
    """
    External authorization layer for Custos AI.

    The AI proposes an action.
    Custos independently decides whether that action
    is allowed, blocked, or requires human approval.
    """

    def __init__(self) -> None:
        self.always_block = {
            "disable_custos",
            "modify_custos_policy",
            "delete_audit_log",
        }

        self.agent_policies = {
            "research_agent": {
                "allowed_actions": {
                    "read_database",
                    "send_email",
                },
                "allowed_resources": {
                    "research_db",
                    "company_email",
                },
                "human_approval": {
                    "send_email",
                },
            }
        }

    def evaluate(
        self,
        request: ActionRequest,
    ) -> tuple[Decision, str]:

        # Hard-blocked actions are never allowed.
        if request.action in self.always_block:
            return (
                Decision.BLOCK,
                "Action is permanently blocked.",
            )

        # Unknown agents are denied by default.
        policy = self.agent_policies.get(request.agent_id)

        if policy is None:
            return (
                Decision.BLOCK,
                "Unknown agent.",
            )

        # Check whether this agent is allowed to perform the action.
        if request.action not in policy["allowed_actions"]:
            return (
                Decision.BLOCK,
                "Action is not permitted for this agent.",
            )

        # Check whether this agent can access the requested resource.
        if request.resource not in policy["allowed_resources"]:
            return (
                Decision.BLOCK,
                "Resource is not permitted for this agent.",
            )

        # High-impact actions require human approval.
        if request.action in policy["human_approval"]:
            return (
                Decision.HUMAN_APPROVAL,
                "Human approval is required.",
            )

        return (
            Decision.ALLOW,
            "Policy checks passed.",
        )


class CustosGateway:
    """
    Execution gate for autonomous AI actions.

    The agent does not execute tools directly.
    Every action must pass through Custos first.
    """

    def __init__(self) -> None:
        self.policy_engine = PolicyEngine()

    def handle(self, request: ActionRequest) -> dict[str, Any]:

        decision, reason = self.policy_engine.evaluate(request)

        if decision == Decision.BLOCK:
            return {
                "decision": decision.value,
                "reason": reason,
                "executed": False,
            }

        if decision == Decision.HUMAN_APPROVAL:
            return {
                "decision": decision.value,
                "reason": reason,
                "executed": False,
            }

        result = self.execute(request)

        return {
            "decision": decision.value,
            "reason": reason,
            "executed": True,
            "result": result,
        }

    def execute(
        self,
        request: ActionRequest,
    ) -> dict[str, Any]:
        """
        Demo execution layer.

        This does not connect to real external services.
        It demonstrates that only ALLOW reaches execution.
        """

        return {
            "status": "success",
            "agent": request.agent_id,
            "action": request.action,
            "resource": request.resource,
        }


if __name__ == "__main__":

    custos = CustosGateway()

    # TEST 1: Authorized action
    request_1 = ActionRequest(
        agent_id="research_agent",
        action="read_database",
        resource="research_db",
        parameters={
            "query": "market_trends"
        },
    )

    print("TEST 1")
    print(custos.handle(request_1))

    # TEST 2: Action requiring human approval
    request_2 = ActionRequest(
        agent_id="research_agent",
        action="send_email",
        resource="company_email",
        parameters={
            "to": "client@example.com",
            "subject": "Test",
        },
    )

    print("\nTEST 2")
    print(custos.handle(request_2))

    # TEST 3: Permanently blocked action
    request_3 = ActionRequest(
        agent_id="research_agent",
        action="disable_custos",
        resource="custos_core",
        parameters={},
    )

    print("\nTEST 3")
    print(custos.handle(request_3))
