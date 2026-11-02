from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from custos_api import create_server
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
        self.provider_db_path = root / "provider-replay.sqlite3"
        self.provider_audit_path = root / "provider-audit.jsonl"
        self.api_db_path = root / "api-approvals.sqlite3"
        self.api_audit_path = root / "api-audit.jsonl"

        # Run the provider as a distinct process so this integration test covers
        # SDK -> API -> Gateway -> signed HTTP dispatch -> Provider receipt ledger.
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        self.provider_port = probe.getsockname()[1]
        probe.close()
        self.provider_url = f"http://127.0.0.1:{self.provider_port}/v1/dispatch"
        self.dispatch_key_id = "sdk-test"
        self.dispatch_key = bytes.fromhex("51" * 32)
        key_ring_json = json.dumps({self.dispatch_key_id: self.dispatch_key.hex()})

        provider_env = os.environ.copy()
        provider_env.pop("CUSTOS_DISPATCH_SIGNING_KEY", None)
        provider_env["CUSTOS_DISPATCH_KEYS"] = key_ring_json
        provider_env["CUSTOS_ACTIVE_DISPATCH_KEY_ID"] = self.dispatch_key_id
        provider_command = [
            sys.executable,
            str(Path(__file__).resolve().parents[1] / "custos_provider.py"),
            "--host", "127.0.0.1",
            "--port", str(self.provider_port),
            "--db", str(self.provider_db_path),
            "--audit", str(self.provider_audit_path),
        ]
        self.provider_process = subprocess.Popen(
            provider_command,
            cwd=Path(__file__).resolve().parents[1],
            env=provider_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(self._stop_provider)
        self._wait_for_provider()

        with patch.dict(
            os.environ,
            {
                "CUSTOS_TOOL_PROVIDER_URL": self.provider_url,
                "CUSTOS_DISPATCH_KEYS": key_ring_json,
                "CUSTOS_ACTIVE_DISPATCH_KEY_ID": self.dispatch_key_id,
                "CUSTOS_PROVIDER_DB": str(self.provider_db_path),
                "CUSTOS_PROVIDER_AUDIT_LOG": str(self.provider_audit_path),
            },
        ):
            self.server = create_server(
                agent_tokens={"research_agent": AGENT_TOKEN},
                reviewer_token=REVIEWER_TOKEN,
                db_path=self.api_db_path,
                audit_path=self.api_audit_path,
                provider_db_path=self.provider_db_path,
                provider_audit_path=self.provider_audit_path,
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

    def _stop_provider(self) -> None:
        process = getattr(self, "provider_process", None)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

    def _wait_for_provider(self) -> None:
        health_url = f"http://127.0.0.1:{self.provider_port}/health"
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.provider_process.poll() is not None:
                self.fail("The separate mock provider exited during startup.")
            try:
                with urllib.request.urlopen(health_url, timeout=0.25) as response:
                    if response.status == 200:
                        return
            except (urllib.error.URLError, TimeoutError, OSError):
                time.sleep(0.05)
        self.fail("The separate mock provider did not become healthy.")

    def _provider_receipts(self, request_id: str | None = None) -> list[dict]:
        with sqlite3.connect(self.provider_db_path) as connection:
            if request_id is None:
                rows = connection.execute(
                    "SELECT agent_id, request_id, request_digest, status, result_json FROM execution_receipts ORDER BY created_at"
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT agent_id, request_id, request_digest, status, result_json FROM execution_receipts WHERE request_id=?",
                    (request_id,),
                ).fetchall()
        return [
            {
                "agent_id": row[0],
                "request_id": row[1],
                "request_digest": row[2],
                "status": row[3],
                "result": json.loads(row[4]) if row[4] else None,
            }
            for row in rows
        ]

    @staticmethod
    def _custos_request_id(call_id: str) -> str:
        return "oa_" + hashlib.sha256(call_id.encode("utf-8")).hexdigest()[:48]

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
        self.assertEqual(
            {key: value for key, value in first.items() if key != "replayed"},
            {key: value for key, value in second.items() if key != "replayed"},
        )
        self.assertTrue(second.get("replayed"))
        receipt = self._provider_receipts(self._custos_request_id("call_read_001"))
        self.assertEqual(len(receipt), 1)
        self.assertEqual(receipt[0]["agent_id"], "research_agent")
        self.assertEqual(receipt[0]["status"], "completed")
        self.assertEqual(receipt[0]["result"]["action"], "read_database")
        self.assertEqual(receipt[0]["result"]["status"], "simulated")

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
        self.assertEqual(self._provider_receipts(), [])

        # Replaying the same SDK tool-call ID must recover the same pending approval,
        # not create a second approval record.
        pending_replay = self.invoke(
            "request_company_email",
            {
                "recipient": "research@example.test",
                "subject": "Research summary",
                "body": "Please send the reviewed summary.",
            },
            "call_email_001",
        )
        self.assertEqual(pending_replay["approval_id"], pending["approval_id"])
        self.assertTrue(pending_replay.get("replayed"))

        # Agent credentials alone cannot approve or execute a pending request.
        premature = self.invoke(
            "execute_reviewer_approved_request",
            {"approval_id": pending["approval_id"]},
            "call_execute_before_review",
        )
        self.assertEqual(premature["decision"], "ERROR")
        self.assertEqual(premature["http_status"], 409)
        self.assertEqual(self._provider_receipts(), [])

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
        receipts = self._provider_receipts()
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["status"], "completed")
        self.assertEqual(receipts[0]["result"]["action"], "send_email")
        self.assertEqual(receipts[0]["result"]["status"], "simulated")


if __name__ == "__main__":
    unittest.main()
