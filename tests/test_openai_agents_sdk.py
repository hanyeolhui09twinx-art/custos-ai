from __future__ import annotations

import asyncio
import importlib.util
import json
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

from audit_log import AuditLog
from custos_api import create_server
from custos_gateway import ApprovalStore, CustosGateway, MockExecutionAdapter
from integrations.custos_client import CustosClient


AGENT_TOKEN = "agent-test-token-" + "a" * 40
REVIEWER_TOKEN = "reviewer-test-token-" + "r" * 40
SDK_AVAILABLE = importlib.util.find_spec("agents") is not None

if SDK_AVAILABLE:
    from agents import Agent, FunctionTool
    from agents.tool_context import ToolContext
    from integrations.openai_agents_sdk import create_custos_agent, create_custos_tools


class CustosClientValidationTests(unittest.TestCase):
    def test_remote_api_origin_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "loopback"):
            CustosClient(AGENT_TOKEN, base_url="http://192.0.2.10:8765")

    def test_short_agent_token_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "32 characters"):
            CustosClient("too-short")


@unittest.skipUnless(SDK_AVAILABLE, "Install requirements-agents.txt to run SDK integration tests.")
class OpenAIAgentsSDKIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.adapter = MockExecutionAdapter()
        self.gateway = CustosGateway(
            store=ApprovalStore(root / "approvals.sqlite3"),
            audit_log=AuditLog(str(root / "audit.jsonl")),
            adapter=self.adapter,
            approval_ttl_seconds=60,
        )
        self.server = create_server(
            agent_tokens={"research_agent": AGENT_TOKEN},
            reviewer_token=REVIEWER_TOKEN,
            db_path=root / "api-approvals.sqlite3",
            audit_path=root / "api-audit.jsonl",
            gateway=self.gateway,
            port=0,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop_server)
        host, port = self.server.server_address
        self.base_url = f"http://{host}:{port}"
        self.client = CustosClient(AGENT_TOKEN, base_url=self.base_url, timeout=3)
        self.agent = create_custos_agent(self.client)
        self.assertIsInstance(self.agent, Agent)
        self.tools = {tool.name: tool for tool in self.agent.tools}

    def _stop_server(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    async def _invoke(self, name: str, arguments: dict, call_id: str) -> dict:
        tool = self.tools[name]
        self.assertIsInstance(tool, FunctionTool)
        encoded = json.dumps(arguments, separators=(",", ":"))
        context = ToolContext(
            context=None,
            tool_name=name,
            tool_call_id=call_id,
            tool_arguments=encoded,
        )
        # Invoke the SDK's FunctionTool entry point so its schema parsing and
        # runtime wrapper execute; do not call the wrapped Python function directly.
        output = await tool.on_invoke_tool(context, encoded)
        self.assertIsInstance(output, str)
        return json.loads(output)

    def invoke(self, name: str, arguments: dict, call_id: str) -> dict:
        return asyncio.run(self._invoke(name, arguments, call_id))

    def _review(self, approval_id: str, decision: str = "approve") -> dict:
        request = urllib.request.Request(
            self.base_url + "/v1/approvals/" + approval_id + "/review",
            data=json.dumps({"decision": decision}).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": "Bearer " + REVIEWER_TOKEN,
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            return json.loads(response.read().decode("utf-8"))

    def test_agent_exposes_only_custos_function_tools(self) -> None:
        self.assertEqual(
            set(self.tools),
            {
                "read_research_database",
                "request_company_email",
                "execute_reviewer_approved_request",
            },
        )
        self.assertTrue(all(isinstance(tool, FunctionTool) for tool in self.agent.tools))

    def test_allow_tool_is_idempotent_for_the_same_sdk_tool_call(self) -> None:
        arguments = {"query": "current market research"}
        first = self.invoke("read_research_database", arguments, "call_read_001")
        second = self.invoke("read_research_database", arguments, "call_read_001")

        self.assertEqual(first["decision"], "ALLOW")
        self.assertTrue(first["executed"])
        self.assertIn("MOCK EXECUTION ONLY", first["boundary_note"])
        self.assertEqual(first, second)
        self.assertEqual(len(self.adapter.executed), 1)

    def test_email_action_cannot_execute_without_separate_human_approval(self) -> None:
        pending = self.invoke(
            "request_company_email",
            {
                "recipient": "research@example.test",
                "subject": "Research summary",
                "body": "Please send the reviewed summary.",
            },
            "call_email_001",
        )
        self.assertEqual(pending["decision"], "HUMAN_APPROVAL")
        self.assertFalse(pending["executed"])
        self.assertEqual(pending["execution_status"], "pending_human_review")
        self.assertIn("NOT EXECUTED", pending["boundary_note"])
        self.assertEqual(len(self.adapter.executed), 0)

        # Agent credentials alone cannot approve or execute a pending request.
        premature = self.invoke(
            "execute_reviewer_approved_request",
            {"approval_id": pending["approval_id"]},
            "call_execute_before_review",
        )
        self.assertEqual(premature["decision"], "ERROR")
        self.assertEqual(premature["http_status"], 409)
        self.assertEqual(len(self.adapter.executed), 0)

        # Only the separate reviewer identity can change the approval state.
        review = self._review(pending["approval_id"], "approve")
        self.assertEqual(review["status"], "approved")
        executed = self.invoke(
            "execute_reviewer_approved_request",
            {"approval_id": pending["approval_id"]},
            "call_execute_after_review",
        )
        self.assertEqual(executed["decision"], "ALLOW")
        self.assertTrue(executed["executed"])
        self.assertEqual(len(self.adapter.executed), 1)
        self.assertEqual(self.adapter.executed[0]["action"], "send_email")
        self.assertEqual(self.adapter.executed[0]["status"], "simulated")


if __name__ == "__main__":
    unittest.main()
