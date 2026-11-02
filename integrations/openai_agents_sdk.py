from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any

from agents import Agent, function_tool
from agents.tool_context import ToolContext

from integrations.custos_client import CustosAPIError, CustosClient, CustosTransportError


def _request_id(context: ToolContext[Any]) -> str:
    """Map the SDK's stable tool-call ID to a valid, bounded Custos idempotency key."""
    call_id = context.tool_call_id
    if not isinstance(call_id, str) or not call_id:
        raise ValueError("The Agents SDK did not supply a tool-call ID.")
    digest = hashlib.sha256(call_id.encode("utf-8")).hexdigest()
    return "oa_" + digest[:48]


def _format_response(response: dict[str, Any]) -> str:
    """Make execution boundaries explicit in the model-visible tool result."""
    safe_response = dict(response)
    decision = safe_response.get("decision")
    if decision == "HUMAN_APPROVAL":
        safe_response["execution_status"] = "pending_human_review"
        safe_response["boundary_note"] = (
            "NOT EXECUTED. A separate human reviewer must approve this exact request. "
            "The agent cannot approve its own request."
        )
    elif decision == "ALLOW" and safe_response.get("executed") is True:
        result = safe_response.get("result")
        if isinstance(result, dict) and result.get("status") == "simulated":
            safe_response["boundary_note"] = (
                "MOCK EXECUTION ONLY. No real database, email system, or external tool was accessed."
            )
    elif decision == "BLOCK":
        safe_response["boundary_note"] = "The request was denied and was not executed."
    return json.dumps(safe_response, ensure_ascii=False, separators=(",", ":"))


def _format_error(exc: Exception, request_id: str) -> str:
    if isinstance(exc, CustosTransportError):
        payload = {
            "decision": "EXECUTION_UNKNOWN",
            "execution_status": "unknown",
            "executed": None,
            "request_id": request_id,
            "message": exc.message,
        }
    elif isinstance(exc, CustosAPIError):
        payload = {
            "decision": "ERROR",
            "http_status": exc.status,
            "message": exc.message,
            "request_id": request_id,
        }
    else:
        payload = {
            "decision": "ERROR",
            "message": "Custos tool invocation failed validation.",
            "request_id": request_id,
        }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def create_custos_tools(client: CustosClient) -> list[Any]:
    """Create the only tool surfaces exposed by the Custos-controlled Agent factory.

    The current policy maps read_research_database to ALLOW (mock execution) and
    request_company_email to HUMAN_APPROVAL (not executed until a reviewer acts).
    """
    if not isinstance(client, CustosClient):
        raise TypeError("client must be a CustosClient instance.")

    @function_tool(timeout=12.0, strict_mode=True)
    async def read_research_database(
        context: ToolContext[Any],
        query: str,
    ) -> str:
        """Request a research-database read through Custos policy authorization.

        This demo is wired to Custos's mock adapter. It does not query a real database.
        """
        request_id = _request_id(context)
        try:
            response = await asyncio.to_thread(
                client.submit,
                "read_database",
                "research_db",
                {"query": query},
                request_id=request_id,
            )
            return _format_response(response)
        except (CustosAPIError, CustosTransportError, ValueError) as exc:
            return _format_error(exc, request_id)

    @function_tool(timeout=12.0, strict_mode=True)
    async def request_company_email(
        context: ToolContext[Any],
        recipient: str,
        subject: str,
        body: str,
    ) -> str:
        """Submit an email action to Custos and wait for a separate human approval.

        This example never sends email. The configured demo policy should return
        HUMAN_APPROVAL, and only a separate reviewer can approve the exact request.
        """
        request_id = _request_id(context)
        try:
            response = await asyncio.to_thread(
                client.submit,
                "send_email",
                "company_email",
                {"recipient": recipient, "subject": subject, "body": body},
                request_id=request_id,
            )
            return _format_response(response)
        except (CustosAPIError, CustosTransportError, ValueError) as exc:
            return _format_error(exc, request_id)

    @function_tool(timeout=12.0, strict_mode=True)
    async def execute_reviewer_approved_request(
        context: ToolContext[Any],
        approval_id: str,
    ) -> str:
        """Ask Custos to execute a request only after a separate reviewer approved it.

        Calling this tool does not approve anything. Custos checks reviewer status,
        request ownership, expiry, and current policy before dispatch.
        """
        request_id = _request_id(context)
        try:
            response = await asyncio.to_thread(client.execute_approved, approval_id)
            return _format_response(response)
        except (CustosAPIError, CustosTransportError, ValueError) as exc:
            return _format_error(exc, request_id)

    return [
        read_research_database,
        request_company_email,
        execute_reviewer_approved_request,
    ]


def create_custos_agent(
    client: CustosClient,
    *,
    name: str = "Custos-controlled research assistant",
    instructions: str = (
        "Use only the Custos-provided tools for actions. Never claim that a request "
        "was executed unless the Custos tool result explicitly confirms it. Treat "
        "HUMAN_APPROVAL as pending, not approved. Never attempt to bypass Custos "
        "through direct network calls, other tools, or code execution. The current "
        "demo adapter is simulated and does not access real systems."
    ),
    model: str | None = None,
) -> Agent[Any]:
    """Create an Agent whose configured function tools all call the Custos API.

    Do not append raw function tools, hosted tools, MCP servers, shell access, or
    other execution surfaces to this Agent and assume Custos will mediate them.
    Those tool types need their own server-side enforcement or separate adapters.
    """
    kwargs: dict[str, Any] = {
        "name": name,
        "instructions": instructions,
        "tools": create_custos_tools(client),
    }
    if model is not None:
        kwargs["model"] = model
    return Agent(**kwargs)


__all__ = ["create_custos_agent", "create_custos_tools"]
