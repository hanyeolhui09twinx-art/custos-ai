from __future__ import annotations

import json
import math
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from audit_log import AuditLog
from custos_api import create_server
from custos_gateway import (
    ActionRequest,
    ApprovalConflict,
    ApprovalExpired,
    ApprovalForbidden,
    ApprovalStore,
    CustosGateway,
    Decision,
    MockExecutionAdapter,
)


class GatewayTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.now = [1_800_000_000.0]
        self.store = ApprovalStore(root / "approvals.sqlite3")
        self.audit = AuditLog(str(root / "audit.jsonl"))
        self.adapter = MockExecutionAdapter()
        self.gateway = CustosGateway(
            store=self.store,
            audit_log=self.audit,
            adapter=self.adapter,
            approval_ttl_seconds=60,
            clock=lambda: self.now[0],
        )

    def request(self, action: str = "read_database", resource: str = "research_db") -> ActionRequest:
        return ActionRequest.from_payload(
            "research_agent",
            {"action": action, "resource": resource, "parameters": {"query": "market_trends"}},
        )

    def test_allow_reaches_only_mock_adapter(self) -> None:
        result = self.gateway.submit(self.request())
        self.assertEqual(result["decision"], Decision.ALLOW.value)
        self.assertTrue(result["executed"])
        self.assertEqual(len(self.adapter.executed), 1)
        self.assertEqual(self.adapter.executed[0]["status"], "simulated")

    def test_unknown_action_and_resource_fail_closed(self) -> None:
        result = self.gateway.submit(self.request("delete_database", "research_db"))
        self.assertEqual(result["decision"], Decision.BLOCK.value)
        self.assertFalse(result["executed"])
        self.assertEqual(self.adapter.executed, [])

        result = self.gateway.submit(self.request("read_database", "payroll_db"))
        self.assertEqual(result["decision"], Decision.BLOCK.value)
        self.assertEqual(self.adapter.executed, [])

    def test_protected_action_is_hard_blocked(self) -> None:
        result = self.gateway.submit(self.request("disable_custos", "custos_core"))
        self.assertEqual(result["decision"], Decision.BLOCK.value)
        self.assertEqual(self.adapter.executed, [])

    def test_human_approval_is_durable_and_single_use(self) -> None:
        result = self.gateway.submit(self.request("send_email", "company_email"))
        self.assertEqual(result["decision"], Decision.HUMAN_APPROVAL.value)
        self.assertFalse(result["executed"])
        self.assertEqual(self.adapter.executed, [])

        approval_id = result["approval_id"]
        self.assertEqual(len(self.gateway.pending_approvals()), 1)
        review = self.gateway.review_approval(approval_id, "reviewer-1", True)
        self.assertEqual(review["status"], "approved")

        executed = self.gateway.execute_approved(approval_id, "research_agent")
        self.assertTrue(executed["executed"])
        self.assertEqual(len(self.adapter.executed), 1)
        self.assertEqual(self.store.get(approval_id)["status"], "executed")

        with self.assertRaises(ApprovalConflict):
            self.gateway.execute_approved(approval_id, "research_agent")
        self.assertEqual(len(self.adapter.executed), 1)

    def test_denial_never_executes(self) -> None:
        result = self.gateway.submit(self.request("send_email", "company_email"))
        self.gateway.review_approval(result["approval_id"], "reviewer-1", False)
        self.assertEqual(self.store.get(result["approval_id"])["status"], "denied")
        with self.assertRaises(ApprovalConflict):
            self.gateway.execute_approved(result["approval_id"], "research_agent")
        self.assertEqual(self.adapter.executed, [])

    def test_expired_approval_cannot_be_reviewed_or_executed(self) -> None:
        result = self.gateway.submit(self.request("send_email", "company_email"))
        approval_id = result["approval_id"]
        self.now[0] += 61
        with self.assertRaises(ApprovalExpired):
            self.gateway.review_approval(approval_id, "reviewer-1", True)
        self.assertEqual(self.store.get(approval_id)["status"], "expired")
        self.assertEqual(self.adapter.executed, [])

    def test_approval_cannot_be_used_by_another_agent(self) -> None:
        result = self.gateway.submit(self.request("send_email", "company_email"))
        self.gateway.review_approval(result["approval_id"], "reviewer-1", True)
        with self.assertRaises(ApprovalForbidden):
            self.gateway.execute_approved(result["approval_id"], "different_agent")
        self.assertEqual(self.adapter.executed, [])

    def test_policy_revocation_is_checked_again_at_dispatch(self) -> None:
        result = self.gateway.submit(self.request("send_email", "company_email"))
        approval_id = result["approval_id"]
        self.gateway.review_approval(approval_id, "reviewer-1", True)
        self.gateway.policy_engine.policies = {}
        execution = self.gateway.execute_approved(approval_id, "research_agent")
        self.assertEqual(execution["decision"], Decision.BLOCK.value)
        self.assertFalse(execution["executed"])
        self.assertEqual(self.store.get(approval_id)["status"], "blocked")
        self.assertEqual(self.adapter.executed, [])

    def test_pending_approval_survives_store_restart(self) -> None:
        result = self.gateway.submit(self.request("send_email", "company_email"))
        restarted_store = ApprovalStore(Path(self.temp.name) / "approvals.sqlite3")
        pending = restarted_store.get(result["approval_id"])
        self.assertIsNotNone(pending)
        self.assertEqual(pending["status"], "pending")

    def test_request_validation_rejects_unknown_fields_and_non_json_values(self) -> None:
        with self.assertRaises(ValueError):
            ActionRequest.from_payload(
                "research_agent",
                {"agent_id": "admin", "action": "read_database", "resource": "research_db"},
            )
        with self.assertRaises(ValueError):
            ActionRequest.from_payload(
                "research_agent",
                {"action": "read_database", "resource": "research_db", "parameters": {"n": math.nan}},
            )
        with self.assertRaises(ValueError):
            ActionRequest.from_payload(
                "research_agent",
                {"action": "read_database", "resource": "research_db", "parameters": {"blob": "x" * 20_000}},
            )

    def test_audit_log_detects_modified_entry(self) -> None:
        path = Path(self.temp.name) / "tamper.jsonl"
        log = AuditLog(str(path))
        log.record("TEST_EVENT", {"value": 1})
        content = path.read_text(encoding="utf-8").replace('"value": 1', '"value": 2')
        path.write_text(content, encoding="utf-8")
        self.assertFalse(log.verify())
        with self.assertRaises(ValueError):
            AuditLog(str(path))


class APITestCase(unittest.TestCase):
    AGENT_TOKEN = "agent-token-" + ("a" * 40)
    OTHER_TOKEN = "other-token-" + ("b" * 40)
    REVIEWER_TOKEN = "reviewer-token-" + ("c" * 40)

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.server = create_server(
            agent_tokens={
                "research_agent": self.AGENT_TOKEN,
                "other_agent": self.OTHER_TOKEN,
            },
            reviewer_token=self.REVIEWER_TOKEN,
            db_path=root / "approvals.sqlite3",
            audit_path=root / "audit.jsonl",
            port=0,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop_server)
        host, port = self.server.server_address
        self.base_url = f"http://{host}:{port}"

    def _stop_server(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method: str, path: str, body: dict | None = None, token: str | None = None):
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(self.base_url + path, data=data, method=method)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        if token:
            request.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_health_and_authentication(self) -> None:
        status, payload = self.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")

        status, payload = self.request(
            "POST",
            "/v1/requests",
            {"action": "read_database", "resource": "research_db"},
        )
        self.assertEqual(status, 401)
        self.assertIn("error", payload)

    def test_request_identity_is_derived_from_bearer_token(self) -> None:
        status, payload = self.request(
            "POST",
            "/v1/requests",
            {
                "agent_id": "other_agent",
                "action": "read_database",
                "resource": "research_db",
            },
            self.AGENT_TOKEN,
        )
        self.assertEqual(status, 400)
        self.assertIn("Unknown request field", payload["error"])

    def test_approval_api_requires_reviewer_and_agent_bound_to_request(self) -> None:
        status, created = self.request(
            "POST",
            "/v1/requests",
            {"action": "send_email", "resource": "company_email", "parameters": {"to": "demo@example.test"}},
            self.AGENT_TOKEN,
        )
        self.assertEqual(status, 200)
        self.assertEqual(created["decision"], Decision.HUMAN_APPROVAL.value)
        approval_id = created["approval_id"]

        status, _ = self.request("GET", "/v1/approvals")
        self.assertEqual(status, 401)

        status, pending = self.request("GET", "/v1/approvals", token=self.REVIEWER_TOKEN)
        self.assertEqual(status, 200)
        self.assertEqual(len(pending["approvals"]), 1)

        status, _ = self.request(
            "POST",
            f"/v1/approvals/{approval_id}/review",
            {"decision": "approve"},
            self.REVIEWER_TOKEN,
        )
        self.assertEqual(status, 200)

        status, _ = self.request(
            "POST",
            f"/v1/approvals/{approval_id}/execute",
            {},
            self.OTHER_TOKEN,
        )
        self.assertEqual(status, 403)

        status, executed = self.request(
            "POST",
            f"/v1/approvals/{approval_id}/execute",
            {},
            self.AGENT_TOKEN,
        )
        self.assertEqual(status, 200)
        self.assertTrue(executed["executed"])

        status, _ = self.request(
            "POST",
            f"/v1/approvals/{approval_id}/execute",
            {},
            self.AGENT_TOKEN,
        )
        self.assertEqual(status, 409)

    def test_remote_binding_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            create_server(
                agent_tokens={"research_agent": self.AGENT_TOKEN},
                reviewer_token=self.REVIEWER_TOKEN,
                host="0.0.0.0",
                port=0,
            )


if __name__ == "__main__":
    unittest.main()
