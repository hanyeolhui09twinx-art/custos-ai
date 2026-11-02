from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from audit_log import AuditLog
from custos_gateway import (
    ActionRequest, ApprovalStore, CustosGateway, DispatchAuthority, DispatchOutcomeUnknown,
)
from custos_provider import HttpToolProviderAdapter

ROOT = Path(__file__).resolve().parents[1]
SIGNING_KEY = bytes.fromhex("ab" * 32)


class IsolatedToolProviderProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        cls.port = probe.getsockname()[1]
        probe.close()
        cls.db_path = cls.root / "provider-replay.sqlite3"
        cls.endpoint = f"http://127.0.0.1:{cls.port}/v1/dispatch"
        cls._start_provider()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._stop_provider()
        cls.temp.cleanup()

    @classmethod
    def _start_provider(cls) -> None:
        env = os.environ.copy()
        env["CUSTOS_DISPATCH_SIGNING_KEY"] = SIGNING_KEY.hex()
        cls.process = subprocess.Popen(
            [
                sys.executable, str(ROOT / "custos_provider.py"),
                "--host", "127.0.0.1", "--port", str(cls.port),
                "--db", str(cls.db_path),
            ],
            cwd=ROOT,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if cls.process.poll() is not None:
                raise RuntimeError("Provider process exited during startup.")
            try:
                with urlopen(f"http://127.0.0.1:{cls.port}/health", timeout=0.25) as response:
                    if response.status == 200:
                        return
            except OSError:
                time.sleep(0.05)
        cls._stop_provider()
        raise RuntimeError("Provider process did not become healthy.")

    @classmethod
    def _stop_provider(cls) -> None:
        process = getattr(cls, "process", None)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

    @staticmethod
    def _request(request_id: str = "provider-request-1") -> ActionRequest:
        return ActionRequest.from_payload(
            "research_agent",
            {
                "action": "read_database",
                "resource": "research_db",
                "parameters": {"query": "bounded-provider-test"},
                "request_id": request_id,
            },
        )

    @staticmethod
    def _permit(request: ActionRequest):
        authority = DispatchAuthority(signing_key=SIGNING_KEY)
        return authority.issue(request, mode="ALLOW")

    @classmethod
    def _post(cls, payload: dict) -> tuple[int, dict]:
        body = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")
        req = Request(
            cls.endpoint,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlopen(req, timeout=3) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    @classmethod
    def _get_receipt(cls, agent_id: str, request_id: str) -> tuple[int, dict]:
        url = f"http://127.0.0.1:{cls.port}/v1/receipts/{agent_id}/{request_id}"
        try:
            with urlopen(url, timeout=3) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_gateway_dispatches_through_a_separate_provider_process(self) -> None:
        request = self._request("gateway-provider-001")
        gateway = CustosGateway(
            store=ApprovalStore(self.root / "gateway-approvals.sqlite3"),
            audit_log=AuditLog(str(self.root / "gateway-audit.jsonl")),
            adapter=HttpToolProviderAdapter(self.endpoint),
            dispatch_signing_key=SIGNING_KEY,
        )
        result = gateway.submit(request)
        self.assertEqual(result["decision"], "ALLOW")
        self.assertTrue(result["executed"])
        self.assertEqual(result["result"]["status"], "simulated")

    def test_human_approved_dispatch_uses_the_separate_provider(self) -> None:
        request = ActionRequest.from_payload(
            "research_agent",
            {
                "action": "send_email",
                "resource": "company_email",
                "parameters": {"to": "demo@example.test"},
                "request_id": "provider-approved-001",
            },
        )
        gateway = CustosGateway(
            store=ApprovalStore(self.root / "approved-approvals.sqlite3"),
            audit_log=AuditLog(str(self.root / "approved-audit.jsonl")),
            adapter=HttpToolProviderAdapter(self.endpoint),
            dispatch_signing_key=SIGNING_KEY,
        )
        pending = gateway.submit(request)
        self.assertEqual(pending["decision"], "HUMAN_APPROVAL")
        approval_id = pending["approval_id"]
        gateway.review_approval(approval_id, reviewer_id="integration-reviewer", approve=True)
        result = gateway.execute_approved(approval_id, request.agent_id)
        self.assertEqual(result["decision"], "ALLOW")
        self.assertTrue(result["executed"])
        self.assertEqual(result["result"]["action"], "send_email")

    def test_approved_gateway_reconciles_a_lost_provider_response(self) -> None:
        request = ActionRequest.from_payload(
            "research_agent",
            {
                "action": "send_email",
                "resource": "company_email",
                "parameters": {"to": "reconcile@example.test"},
                "request_id": "approved-reconcile-001",
            },
        )
        delegate = HttpToolProviderAdapter(self.endpoint)

        class DropApprovedResponse:
            def execute(self, candidate):
                return delegate.execute(candidate)

            def execute_with_permit(self, candidate, permit):
                delegate.execute_with_permit(candidate, permit)
                raise DispatchOutcomeUnknown("Simulated lost response after provider completion.")

            def get_receipt(self, agent_id, request_id):
                return delegate.get_receipt(agent_id, request_id)

        gateway = CustosGateway(
            store=ApprovalStore(self.root / "approved-reconcile-approvals.sqlite3"),
            audit_log=AuditLog(str(self.root / "approved-reconcile-audit.jsonl")),
            adapter=DropApprovedResponse(),
            dispatch_signing_key=SIGNING_KEY,
        )
        pending = gateway.submit(request)
        approval_id = pending["approval_id"]
        gateway.review_approval(approval_id, reviewer_id="reconcile-reviewer", approve=True)
        first = gateway.execute_approved(approval_id, request.agent_id)
        self.assertEqual(first["decision"], "EXECUTION_UNKNOWN")
        self.assertIsNone(first["executed"])
        second = gateway.execute_approved(approval_id, request.agent_id)
        self.assertEqual(second["decision"], "ALLOW")
        self.assertTrue(second["reconciled"])
        self.assertEqual(gateway.store.get(approval_id)["status"], "executed")

    def test_provider_rejects_missing_forged_and_request_substituted_permits(self) -> None:
        request = self._request("provider-invalid-001")
        self.assertEqual(self._post({"request": request.to_dict()})[0], 403)

        permit = self._permit(request)
        forged = dict(permit.__dict__)
        forged["signature"] = "0" * 64
        self.assertEqual(
            self._post({"request": request.to_dict(), "permit": forged})[0],
            403,
        )

        changed = ActionRequest.from_payload(
            request.agent_id,
            {
                "action": request.action,
                "resource": request.resource,
                "parameters": {"query": "substituted"},
                "request_id": request.request_id,
            },
        )
        self.assertEqual(
            self._post({"request": changed.to_dict(), "permit": permit.__dict__})[0],
            403,
        )

    def test_provider_permit_is_single_use_under_concurrent_replay(self) -> None:
        request = self._request("provider-race-001")
        permit = self._permit(request)
        payload = {"request": request.to_dict(), "permit": permit.__dict__}
        with ThreadPoolExecutor(max_workers=8) as pool:
            statuses = list(pool.map(lambda _: self._post(payload)[0], range(8)))
        self.assertEqual(statuses.count(200), 1)
        self.assertEqual(statuses.count(403), 7)

    def test_provider_replay_record_survives_process_restart(self) -> None:
        request = self._request("provider-restart-001")
        permit = self._permit(request)
        payload = {"request": request.to_dict(), "permit": permit.__dict__}
        first_status, _ = self._post(payload)
        self.assertEqual(first_status, 200)

        self._stop_provider()
        self._start_provider()
        second_status, _ = self._post(payload)
        self.assertEqual(second_status, 403)

    def test_same_request_id_returns_persisted_result_without_second_execution(self) -> None:
        request = self._request("provider-idempotent-001")
        first_status, first = self._post({
            "request": request.to_dict(), "permit": self._permit(request).__dict__,
        })
        second_status, second = self._post({
            "request": request.to_dict(), "permit": self._permit(request).__dict__,
        })
        self.assertEqual(first_status, 200)
        self.assertEqual(second_status, 200)
        self.assertEqual(first["result"], second["result"])
        receipt_status, receipt = self._get_receipt(request.agent_id, request.request_id)
        self.assertEqual(receipt_status, 200)
        self.assertEqual(receipt["receipt"]["status"], "completed")
        self.assertEqual(receipt["receipt"]["request_digest"], request.digest)

    def test_same_request_id_with_different_digest_is_rejected(self) -> None:
        original = self._request("provider-idempotency-conflict-001")
        first_status, _ = self._post({
            "request": original.to_dict(), "permit": self._permit(original).__dict__,
        })
        self.assertEqual(first_status, 200)
        changed = ActionRequest.from_payload(
            original.agent_id,
            {
                "action": original.action,
                "resource": original.resource,
                "parameters": {"query": "different"},
                "request_id": original.request_id,
            },
        )
        status, payload = self._post({
            "request": changed.to_dict(), "permit": self._permit(changed).__dict__,
        })
        self.assertEqual(status, 409)
        self.assertEqual(payload.get("code"), "idempotency_conflict")

    def test_interrupted_execution_becomes_indeterminate_after_restart(self) -> None:
        request = self._request("provider-interrupted-001")
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO execution_receipts
                   (agent_id, request_id, request_digest, status, result_json, created_at, updated_at)
                   VALUES (?, ?, ?, 'executing', NULL, ?, ?)""",
                (request.agent_id, request.request_id, request.digest, now, now),
            )
        self._stop_provider()
        self._start_provider()
        receipt_status, receipt = self._get_receipt(request.agent_id, request.request_id)
        self.assertEqual(receipt_status, 200)
        self.assertEqual(receipt["receipt"]["status"], "indeterminate")
        status, payload = self._post({
            "request": request.to_dict(), "permit": self._permit(request).__dict__,
        })
        self.assertEqual(status, 409)
        self.assertEqual(payload.get("code"), "execution_outcome_unknown")

    def _insert_gateway_processing_receipt(self, db_path: Path, request: ActionRequest) -> None:
        store = ApprovalStore(db_path)
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                """INSERT INTO request_receipts
                   (agent_id, request_id, request_digest, status, response_json, created_at)
                   VALUES (?, ?, ?, 'processing', NULL, ?)""",
                (request.agent_id, request.request_id, request.digest, time.time()),
            )
        self.assertIsNotNone(store.get_request_result(request.agent_id, request.request_id))

    def test_gateway_restart_reconciles_provider_completion_before_request_receipt_commit(self) -> None:
        request = self._request("gateway-restart-completed-001")
        delegate = HttpToolProviderAdapter(self.endpoint)
        permit = DispatchAuthority(signing_key=SIGNING_KEY).issue(request, mode="ALLOW")
        provider_result = delegate.execute_with_permit(request, permit)

        db_path = self.root / "gateway-crash-after-provider.sqlite3"
        self._insert_gateway_processing_receipt(db_path, request)
        restarted_store = ApprovalStore(db_path)
        gateway = CustosGateway(
            store=restarted_store,
            audit_log=AuditLog(str(self.root / "gateway-crash-after-provider-audit.jsonl")),
            adapter=delegate,
            dispatch_signing_key=SIGNING_KEY,
        )
        result = gateway.submit(request)
        self.assertEqual(result["decision"], "ALLOW")
        self.assertTrue(result["executed"])
        self.assertTrue(result["reconciled"])
        self.assertTrue(result["recovered"])
        self.assertEqual(result["result"], provider_result)
        self.assertEqual(
            restarted_store.get_request_result(request.agent_id, request.request_id)["status"],
            "completed",
        )

    def test_gateway_restart_without_provider_receipt_stays_unknown_and_never_redispatches(self) -> None:
        request = self._request("gateway-restart-no-provider-receipt-001")
        db_path = self.root / "gateway-crash-no-provider.sqlite3"
        self._insert_gateway_processing_receipt(db_path, request)
        gateway = CustosGateway(
            store=ApprovalStore(db_path),
            audit_log=AuditLog(str(self.root / "gateway-crash-no-provider-audit.jsonl")),
            adapter=HttpToolProviderAdapter(self.endpoint),
            dispatch_signing_key=SIGNING_KEY,
        )
        first = gateway.submit(request)
        second = gateway.submit(request)
        self.assertEqual(first["decision"], "EXECUTION_UNKNOWN")
        self.assertEqual(second["decision"], "EXECUTION_UNKNOWN")
        self.assertIsNone(first["executed"])
        self.assertEqual(first["reconciliation_status"], "receipt_not_found")
        self.assertEqual(self._get_receipt(request.agent_id, request.request_id)[0], 404)
        self.assertEqual(
            gateway.store.get_request_result(request.agent_id, request.request_id)["status"],
            "indeterminate",
        )

    def test_gateway_restart_recovers_existing_pending_approval_without_duplicate(self) -> None:
        request = ActionRequest.from_payload(
            "research_agent",
            {
                "action": "send_email",
                "resource": "company_email",
                "parameters": {"to": "pending-recovery@example.test"},
                "request_id": "gateway-restart-pending-approval-001",
            },
        )
        db_path = self.root / "gateway-pending-approval.sqlite3"
        store = ApprovalStore(db_path)
        approval_id = store.create(request, 300, time.time())
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                """INSERT INTO request_receipts
                   (agent_id, request_id, request_digest, status, response_json, created_at)
                   VALUES (?, ?, ?, 'processing', NULL, ?)""",
                (request.agent_id, request.request_id, request.digest, time.time()),
            )
        gateway = CustosGateway(
            store=ApprovalStore(db_path),
            audit_log=AuditLog(str(self.root / "gateway-pending-approval-audit.jsonl")),
            adapter=HttpToolProviderAdapter(self.endpoint),
            dispatch_signing_key=SIGNING_KEY,
        )
        recovered = gateway.submit(request)
        self.assertEqual(recovered["decision"], "HUMAN_APPROVAL")
        self.assertEqual(recovered["approval_id"], approval_id)
        self.assertEqual(recovered["status"], "pending")
        with sqlite3.connect(db_path) as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM approvals WHERE request_digest=?",
                (request.digest,),
            ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_approved_execution_restart_reconciles_provider_receipt(self) -> None:
        request = ActionRequest.from_payload(
            "research_agent",
            {
                "action": "send_email",
                "resource": "company_email",
                "parameters": {"to": "approved-recovery@example.test"},
                "request_id": "gateway-restart-approved-execution-001",
            },
        )
        db_path = self.root / "gateway-approved-recovery.sqlite3"
        store = ApprovalStore(db_path)
        delegate = HttpToolProviderAdapter(self.endpoint)
        original_gateway = CustosGateway(
            store=store,
            audit_log=AuditLog(str(self.root / "gateway-approved-before-crash-audit.jsonl")),
            adapter=delegate,
            dispatch_signing_key=SIGNING_KEY,
        )
        pending = original_gateway.submit(request)
        approval_id = pending["approval_id"]
        original_gateway.review_approval(approval_id, "recovery-reviewer", True)
        claimed_request = store.claim_for_execution(approval_id, request.agent_id)
        permit = DispatchAuthority(signing_key=SIGNING_KEY).issue(
            claimed_request, mode="APPROVED", approval_id=approval_id,
        )
        provider_result = delegate.execute_with_permit(claimed_request, permit)

        restarted = CustosGateway(
            store=ApprovalStore(db_path),
            audit_log=AuditLog(str(self.root / "gateway-approved-after-crash-audit.jsonl")),
            adapter=delegate,
            dispatch_signing_key=SIGNING_KEY,
        )
        recovered = restarted.execute_approved(approval_id, request.agent_id)
        self.assertEqual(recovered["decision"], "ALLOW")
        self.assertTrue(recovered["executed"])
        self.assertTrue(recovered["reconciled"])
        self.assertEqual(recovered["result"], provider_result)
        self.assertEqual(restarted.store.get(approval_id)["status"], "executed")

    def test_gateway_reconciles_a_lost_response_from_provider_receipt(self) -> None:
        request = self._request("gateway-reconcile-001")
        delegate = HttpToolProviderAdapter(self.endpoint)

        class DropFirstResponse:
            def execute(self, candidate):
                return delegate.execute(candidate)

            def execute_with_permit(self, candidate, permit):
                delegate.execute_with_permit(candidate, permit)
                raise DispatchOutcomeUnknown("Simulated response loss after provider completion.")

            def get_receipt(self, agent_id, request_id):
                return delegate.get_receipt(agent_id, request_id)

        gateway = CustosGateway(
            store=ApprovalStore(self.root / "reconcile-approvals.sqlite3"),
            audit_log=AuditLog(str(self.root / "reconcile-audit.jsonl")),
            adapter=DropFirstResponse(),
            dispatch_signing_key=SIGNING_KEY,
        )
        first = gateway.submit(request)
        self.assertEqual(first["decision"], "EXECUTION_UNKNOWN")
        self.assertIsNone(first["executed"])
        second = gateway.submit(request)
        self.assertEqual(second["decision"], "ALLOW")
        self.assertTrue(second["executed"])
        self.assertTrue(second["reconciled"])
        self.assertEqual(second["result"]["request_id"], request.request_id)

    def test_gateway_fails_closed_when_provider_is_unavailable(self) -> None:
        self._stop_provider()
        request = self._request("provider-offline-001")
        gateway = CustosGateway(
            store=ApprovalStore(self.root / "offline-approvals.sqlite3"),
            audit_log=AuditLog(str(self.root / "offline-audit.jsonl")),
            adapter=HttpToolProviderAdapter(self.endpoint, timeout_seconds=0.25),
            dispatch_signing_key=SIGNING_KEY,
        )
        result = gateway.submit(request)
        self.assertEqual(result["decision"], "EXECUTION_UNKNOWN")
        self.assertIsNone(result["executed"])
        self.assertEqual(result["execution_status"], "unknown")
        self._start_provider()

    def test_provider_endpoint_rejects_non_loopback_addresses(self) -> None:
        with self.assertRaises(ValueError):
            HttpToolProviderAdapter("http://192.0.2.10:8766/v1/dispatch")


if __name__ == "__main__":
    unittest.main()
