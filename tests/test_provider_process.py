from __future__ import annotations

import json
import os
import socket
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
    ActionRequest, ApprovalStore, CustosGateway, DispatchAuthority,
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
        self.assertEqual(result["decision"], "BLOCK")
        self.assertFalse(result["executed"])
        self._start_provider()

    def test_provider_endpoint_rejects_non_loopback_addresses(self) -> None:
        with self.assertRaises(ValueError):
            HttpToolProviderAdapter("http://192.0.2.10:8766/v1/dispatch")


if __name__ == "__main__":
    unittest.main()
