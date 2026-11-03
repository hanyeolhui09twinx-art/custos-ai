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
from custos_provider import (
    HttpToolProviderAdapter, ProviderToolContract, ProviderToolRegistry, ReadOnlyResearchFixture,
    RECEIPT_KEY_ID_HEADER, RECEIPT_SIGNATURE_HEADER, receipt_lookup_signature,
    validate_json_schema,
)

ROOT = Path(__file__).resolve().parents[1]
SIGNING_KEY = bytes.fromhex("ab" * 32)
LEGACY_KEY = bytes.fromhex("cd" * 32)
V2_KEY = bytes.fromhex("ef" * 32)
KEY_RING = {"default": SIGNING_KEY, "legacy": LEGACY_KEY}
ACTIVE_KEY_ID = "default"


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
        cls.research_fixture_db_path = cls.root / "research-fixture.sqlite3"
        cls.endpoint = f"http://127.0.0.1:{cls.port}/v1/dispatch"
        cls._start_provider()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._stop_provider()
        cls.temp.cleanup()

    @classmethod
    def _start_provider(
        cls,
        signing_keys: dict[str, bytes] | None = None,
        active_key_id: str = ACTIVE_KEY_ID,
        legacy_single_key: bytes | None = None,
    ) -> None:
        env = os.environ.copy()
        if legacy_single_key is not None:
            env.pop("CUSTOS_DISPATCH_KEYS", None)
            env.pop("CUSTOS_ACTIVE_DISPATCH_KEY_ID", None)
            env["CUSTOS_DISPATCH_SIGNING_KEY"] = legacy_single_key.hex()
        else:
            configured_keys = signing_keys or KEY_RING
            env.pop("CUSTOS_DISPATCH_SIGNING_KEY", None)
            env["CUSTOS_DISPATCH_KEYS"] = json.dumps({
                key_id: key_value.hex() for key_id, key_value in configured_keys.items()
            })
            env["CUSTOS_ACTIVE_DISPATCH_KEY_ID"] = active_key_id
        cls.process = subprocess.Popen(
            [
                sys.executable, str(ROOT / "custos_provider.py"),
                "--host", "127.0.0.1", "--port", str(cls.port),
                "--db", str(cls.db_path),
                "--research-fixture-db", str(cls.research_fixture_db_path),
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
    def _permit(request: ActionRequest, mode: str = "ALLOW"):
        authority = DispatchAuthority(signing_key=SIGNING_KEY)
        approval_id = "provider-registry-test-approval" if mode == "APPROVED" else None
        return authority.issue(request, mode=mode, approval_id=approval_id)

    @staticmethod
    def _permit_with_key(request: ActionRequest, key_id: str, key: bytes):
        authority = DispatchAuthority(
            signing_keys={key_id: key},
            active_key_id=key_id,
        )
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
        path = f"/v1/receipts/{agent_id}/{request_id}"
        url = f"http://127.0.0.1:{cls.port}{path}"
        headers = {
            RECEIPT_KEY_ID_HEADER: ACTIVE_KEY_ID,
            RECEIPT_SIGNATURE_HEADER: receipt_lookup_signature(SIGNING_KEY, path, ACTIVE_KEY_ID),
        }
        req = Request(url, headers=headers, method="GET")
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
            adapter=HttpToolProviderAdapter(self.endpoint, receipt_signing_key=SIGNING_KEY),
            dispatch_signing_key=SIGNING_KEY,
        )
        result = gateway.submit(request)
        self.assertEqual(result["decision"], "ALLOW")
        self.assertTrue(result["executed"])
        self.assertEqual(result["result"]["status"], "read_only")

    def test_human_approved_dispatch_uses_the_separate_provider(self) -> None:
        request = ActionRequest.from_payload(
            "research_agent",
            {
                "action": "send_email",
                "resource": "company_email",
                "parameters": {"recipient": "demo@example.test", "subject": "Demo notice", "body": "Test-only email payload."},
                "request_id": "provider-approved-001",
            },
        )
        gateway = CustosGateway(
            store=ApprovalStore(self.root / "approved-approvals.sqlite3"),
            audit_log=AuditLog(str(self.root / "approved-audit.jsonl")),
            adapter=HttpToolProviderAdapter(self.endpoint, receipt_signing_key=SIGNING_KEY),
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
        self.assertEqual(result["result"]["contract_version"], "1.0.0")

    def test_approved_gateway_reconciles_a_lost_provider_response(self) -> None:
        request = ActionRequest.from_payload(
            "research_agent",
            {
                "action": "send_email",
                "resource": "company_email",
                "parameters": {"recipient": "reconcile@example.test", "subject": "Reconciliation notice", "body": "Test-only reconciliation payload."},
                "request_id": "approved-reconcile-001",
            },
        )
        delegate = HttpToolProviderAdapter(self.endpoint, receipt_signing_key=SIGNING_KEY)

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

    def test_gateway_uses_configured_active_key_id_and_key_ring(self) -> None:
        rotation_ring = {"legacy": LEGACY_KEY, "v2": V2_KEY}
        self._stop_provider()
        try:
            self._start_provider(signing_keys=rotation_ring, active_key_id="v2")
            request = self._request("gateway-active-key-ring-001")
            gateway = CustosGateway(
                store=ApprovalStore(self.root / "gateway-keyring-approvals.sqlite3"),
                audit_log=AuditLog(str(self.root / "gateway-keyring-audit.jsonl")),
                adapter=HttpToolProviderAdapter(
                    self.endpoint,
                    receipt_signing_keys=rotation_ring,
                    receipt_signing_key_id="v2",
                ),
                dispatch_signing_keys=rotation_ring,
                active_dispatch_key_id="v2",
            )
            permit = gateway._dispatch_authority.issue(request, mode="ALLOW")
            self.assertEqual(permit.key_id, "v2")
            result = gateway.submit(request)
            self.assertEqual(result["decision"], "ALLOW")
            self.assertTrue(result["executed"])
            receipt = gateway.adapter.get_receipt(request.agent_id, request.request_id)
            self.assertIsNotNone(receipt)
            self.assertEqual(receipt["request_digest"], request.digest)
        finally:
            self._stop_provider()
            self._start_provider(signing_keys=KEY_RING, active_key_id="default")

    def test_provider_accepts_previous_receipt_lookup_key_during_rotation(self) -> None:
        rotation_ring = {"legacy": LEGACY_KEY, "v2": V2_KEY}
        self._stop_provider()
        try:
            self._start_provider(signing_keys=rotation_ring, active_key_id="v2")
            request = self._request("provider-receipt-key-rotation-001")
            status, _ = self._post({
                "request": request.to_dict(),
                "permit": self._permit_with_key(request, "v2", V2_KEY).__dict__,
            })
            self.assertEqual(status, 200)
            path = f"/v1/receipts/{request.agent_id}/{request.request_id}"
            url = f"http://127.0.0.1:{self.port}{path}"
            req = Request(
                url,
                method="GET",
                headers={
                    RECEIPT_KEY_ID_HEADER: "legacy",
                    RECEIPT_SIGNATURE_HEADER: receipt_lookup_signature(LEGACY_KEY, path, "legacy"),
                },
            )
            with urlopen(req, timeout=3) as response:
                payload = json.loads(response.read().decode("utf-8"))
            self.assertEqual(payload["receipt"]["request_digest"], request.digest)
        finally:
            self._stop_provider()
            self._start_provider(signing_keys=KEY_RING, active_key_id="default")

    def test_provider_accepts_previous_and_active_keys_during_rotation(self) -> None:
        rotation_ring = {"legacy": LEGACY_KEY, "v2": V2_KEY}
        self._stop_provider()
        try:
            self._start_provider(signing_keys=rotation_ring, active_key_id="v2")
            previous_request = self._request("provider-key-rotation-previous-001")
            active_request = self._request("provider-key-rotation-active-001")
            previous_permit = self._permit_with_key(previous_request, "legacy", LEGACY_KEY)
            active_permit = self._permit_with_key(active_request, "v2", V2_KEY)

            previous_status, previous = self._post({
                "request": previous_request.to_dict(),
                "permit": previous_permit.__dict__,
            })
            active_status, active = self._post({
                "request": active_request.to_dict(),
                "permit": active_permit.__dict__,
            })

            self.assertEqual(previous_status, 200)
            self.assertEqual(active_status, 200)
            self.assertEqual(previous["result"]["request_id"], previous_request.request_id)
            self.assertEqual(active["result"]["request_id"], active_request.request_id)
        finally:
            self._stop_provider()
            self._start_provider(signing_keys=KEY_RING, active_key_id="default")

    def test_provider_rejects_retired_key_after_rotation_window(self) -> None:
        request = self._request("provider-key-retired-001")
        old_permit = self._permit_with_key(request, "legacy", LEGACY_KEY)
        payload = {"request": request.to_dict(), "permit": old_permit.__dict__}

        self._stop_provider()
        try:
            self._start_provider(signing_keys={"v2": V2_KEY}, active_key_id="v2")
            status, body = self._post(payload)
            self.assertEqual(status, 403)
            self.assertEqual(body.get("code"), "dispatch_denied")

            receipt_request = self._request("provider-retired-receipt-key-001")
            accepted, _ = self._post({
                "request": receipt_request.to_dict(),
                "permit": self._permit_with_key(receipt_request, "v2", V2_KEY).__dict__,
            })
            self.assertEqual(accepted, 200)
            receipt_path = f"/v1/receipts/{receipt_request.agent_id}/{receipt_request.request_id}"
            receipt_url = f"http://127.0.0.1:{self.port}{receipt_path}"
            retired_lookup = Request(
                receipt_url,
                method="GET",
                headers={
                    RECEIPT_KEY_ID_HEADER: "legacy",
                    RECEIPT_SIGNATURE_HEADER: receipt_lookup_signature(LEGACY_KEY, receipt_path, "legacy"),
                },
            )
            with self.assertRaises(HTTPError) as retired:
                urlopen(retired_lookup, timeout=3)
            self.assertEqual(retired.exception.code, 403)
        finally:
            self._stop_provider()
            self._start_provider(signing_keys=KEY_RING, active_key_id="default")

    def test_provider_rejects_permit_key_id_substitution(self) -> None:
        request = self._request("provider-key-id-substitution-001")
        permit = self._permit(request)
        changed = dict(permit.__dict__)
        changed["key_id"] = "legacy"
        status, body = self._post({
            "request": request.to_dict(),
            "permit": changed,
        })
        self.assertEqual(status, 403)
        self.assertEqual(body.get("code"), "dispatch_denied")

    def test_provider_receipt_lookup_requires_a_valid_hmac_signature(self) -> None:
        request = self._request("provider-receipt-auth-001")
        status, _ = self._post({
            "request": request.to_dict(),
            "permit": self._permit(request).__dict__,
        })
        self.assertEqual(status, 200)

        path = f"/v1/receipts/{request.agent_id}/{request.request_id}"
        url = f"http://127.0.0.1:{self.port}{path}"
        unauthenticated = Request(url, method="GET")
        with self.assertRaises(HTTPError) as missing:
            urlopen(unauthenticated, timeout=3)
        self.assertEqual(missing.exception.code, 401)

        forged = Request(
            url,
            method="GET",
            headers={
                RECEIPT_KEY_ID_HEADER: ACTIVE_KEY_ID,
                RECEIPT_SIGNATURE_HEADER: "0" * 64,
            },
        )
        with self.assertRaises(HTTPError) as invalid:
            urlopen(forged, timeout=3)
        self.assertEqual(invalid.exception.code, 403)

        verified_status, verified = self._get_receipt(request.agent_id, request.request_id)
        self.assertEqual(verified_status, 200)
        self.assertEqual(verified["receipt"]["request_digest"], request.digest)

    def test_provider_supports_legacy_single_key_environment_configuration(self) -> None:
        self._stop_provider()
        try:
            self._start_provider(legacy_single_key=SIGNING_KEY)
            request = self._request("provider-legacy-single-key-001")
            permit = self._permit(request)
            status, response = self._post({
                "request": request.to_dict(),
                "permit": permit.__dict__,
            })
            self.assertEqual(status, 200)
            adapter = HttpToolProviderAdapter(
                self.endpoint,
                receipt_signing_key=SIGNING_KEY,
            )
            receipt = adapter.get_receipt(request.agent_id, request.request_id)
            self.assertEqual(receipt["request_digest"], request.digest)
            self.assertEqual(response["result"]["request_id"], request.request_id)
        finally:
            self._stop_provider()
            self._start_provider(signing_keys=KEY_RING, active_key_id="default")

    def test_provider_startup_audits_emergency_key_revocation(self) -> None:
        self._stop_provider()
        try:
            self._start_provider(signing_keys=KEY_RING, active_key_id="default")
            request = self._request("provider-emergency-revoke-001")
            compromised_permit = self._permit_with_key(request, "legacy", LEGACY_KEY)

            self._stop_provider()
            self._start_provider(
                signing_keys={"default": SIGNING_KEY},
                active_key_id="default",
            )
            status, body = self._post({
                "request": request.to_dict(),
                "permit": compromised_permit.__dict__,
            })
            self.assertEqual(status, 403)
            self.assertEqual(body.get("code"), "dispatch_denied")

            audit_path = self.db_path.with_suffix(".audit.jsonl")
            with audit_path.open("r", encoding="utf-8") as handle:
                entries = [json.loads(line) for line in handle if line.strip()]
            revoked = [
                entry for entry in entries
                if entry.get("event") == "DISPATCH_KEY_REVOKED"
                and entry.get("data", {}).get("component") == "provider"
                and entry.get("data", {}).get("key_id") == "legacy"
            ]
            self.assertTrue(revoked)
            self.assertTrue(AuditLog(str(audit_path)).verify())
            self.assertNotIn(LEGACY_KEY.hex(), audit_path.read_text(encoding="utf-8"))
        finally:
            self._stop_provider()
            self._start_provider(signing_keys=KEY_RING, active_key_id="default")

    def test_provider_reads_synthetic_records_with_parameterized_read_only_queries(self) -> None:
        request = ActionRequest.from_payload(
            "research_agent",
            {
                "action": "read_database",
                "resource": "research_db",
                "parameters": {"query": "current market research"},
                "request_id": "provider-fixture-read-001",
            },
        )
        status, body = self._post({
            "request": request.to_dict(),
            "permit": self._permit(request).__dict__,
        })
        self.assertEqual(status, 200)
        result = body["result"]
        self.assertEqual(result["status"], "read_only")
        self.assertEqual(result["storage"], "local_synthetic_sqlite_fixture")
        self.assertEqual(result["row_count"], 1)
        self.assertEqual(result["records"][0]["id"], "market-001")
        self.assertEqual(result["records"][0]["source"], "synthetic-fixture")
        self.assertEqual(result["contract_version"], "1.0.0")

        # A SQL-shaped query remains plain bound text and cannot turn the WHERE
        # clause into a tautology or expose the remaining fixture rows.
        injection = ActionRequest.from_payload(
            "research_agent",
            {
                "action": "read_database",
                "resource": "research_db",
                "parameters": {"query": "market%' OR 1=1 --"},
                "request_id": "provider-fixture-injection-001",
            },
        )
        injected_status, injected_body = self._post({
            "request": injection.to_dict(),
            "permit": self._permit(injection).__dict__,
        })
        self.assertEqual(injected_status, 200)
        self.assertEqual(injected_body["result"]["records"], [])
        with sqlite3.connect(self.research_fixture_db_path) as connection:
            total = connection.execute("SELECT COUNT(*) FROM research_records").fetchone()[0]
        self.assertEqual(total, 3)

    def test_provider_fixture_runtime_connection_rejects_writes(self) -> None:
        fixture = ReadOnlyResearchFixture(self.research_fixture_db_path)
        connection = fixture._connect_readonly()
        try:
            with self.assertRaises(sqlite3.OperationalError):
                connection.execute(
                    "INSERT INTO research_records (id, title, content, source) VALUES (?, ?, ?, ?)",
                    ("runtime-write", "Injected", "Must not persist", "test"),
                )
            self.assertTrue(connection.execute("PRAGMA query_only").fetchone()[0])
        finally:
            connection.close()

    def test_provider_contract_rejects_legacy_email_shape_and_versions_valid_results(self) -> None:
        valid = ActionRequest.from_payload(
            "research_agent",
            {
                "action": "send_email",
                "resource": "company_email",
                "parameters": {
                    "recipient": "contract@example.test",
                    "subject": "Contract test",
                    "body": "This email is never sent.",
                },
                "request_id": "provider-contract-email-valid-001",
            },
        )
        valid_status, valid_body = self._post({
            "request": valid.to_dict(),
            "permit": self._permit(valid, mode="APPROVED").__dict__,
        })
        self.assertEqual(valid_status, 200)
        self.assertEqual(valid_body["result"]["status"], "simulated")
        self.assertEqual(valid_body["result"]["contract_version"], "1.0.0")

        legacy = ActionRequest.from_payload(
            "research_agent",
            {
                "action": "send_email",
                "resource": "company_email",
                "parameters": {"to": "legacy@example.test"},
                "request_id": "provider-contract-email-legacy-001",
            },
        )
        legacy_status, _ = self._post({
            "request": legacy.to_dict(),
            "permit": self._permit(legacy, mode="APPROVED").__dict__,
        })
        self.assertEqual(legacy_status, 400)
        receipt_status, _ = self._get_receipt(legacy.agent_id, legacy.request_id)
        self.assertEqual(receipt_status, 404)

    def test_provider_json_schema_patterns_reject_whitespace_and_email_spoofing(self) -> None:
        registry = ProviderToolRegistry()
        catalog = registry.to_catalog_document()
        research_schema = catalog["contracts"][0]["input_schema"]
        email_schema = catalog["contracts"][1]["input_schema"]

        self.assertEqual(research_schema["properties"]["query"]["pattern"], r"\S")
        self.assertEqual(email_schema["properties"]["subject"]["pattern"], r"\S")

        for query in (" ", "   ", "\\t\\n"):
            with self.subTest(query=repr(query)):
                with self.assertRaises(ValueError):
                    validate_json_schema({"query": query}, research_schema)

        for recipient in ("name @example.test", "name@ example.test", "name\\nBcc:evil@example.test"):
            with self.subTest(recipient=repr(recipient)):
                with self.assertRaises(ValueError):
                    validate_json_schema(
                        {
                            "recipient": recipient,
                            "subject": "A bounded subject",
                            "body": "A bounded body",
                        },
                        email_schema,
                    )

        validate_json_schema(
            {
                "recipient": "research@example.test",
                "subject": "A bounded subject",
                "body": "A bounded body",
            },
            email_schema,
        )

    def test_provider_contract_catalog_matches_the_runtime_registry(self) -> None:
        catalog_path = ROOT / ProviderToolRegistry.CATALOG_RELATIVE_PATH
        with catalog_path.open("r", encoding="utf-8") as handle:
            published_catalog = json.load(handle)
        registry = ProviderToolRegistry()
        self.assertEqual(registry.to_catalog_document(), published_catalog)
        self.assertEqual(published_catalog["schema_dialect"], ProviderToolRegistry.SCHEMA_DIALECT)
        self.assertEqual(published_catalog["catalog_version"], "1.0.0")
        self.assertEqual(len(published_catalog["contracts"]), 2)
        for contract in published_catalog["contracts"]:
            self.assertEqual(contract["contract_version"], "1.0.0")
            self.assertEqual(contract["input_schema"]["$schema"], ProviderToolRegistry.SCHEMA_DIALECT)
            self.assertEqual(contract["output_schema"]["$schema"], ProviderToolRegistry.SCHEMA_DIALECT)
            self.assertFalse(contract["input_schema"]["additionalProperties"])
            self.assertFalse(contract["output_schema"]["additionalProperties"])

    def test_provider_contract_validates_email_address_and_semver(self) -> None:
        for index, recipient in enumerate(("not-an-email", "bad address@example.test", "x@example.test\nBcc:evil@example.test"), start=1):
            with self.subTest(recipient=recipient):
                request = ActionRequest.from_payload(
                    "research_agent",
                    {
                        "action": "send_email",
                        "resource": "company_email",
                        "parameters": {
                            "recipient": recipient,
                            "subject": "Contract validation",
                            "body": "Must be rejected before a receipt is claimed.",
                        },
                        "request_id": f"provider-contract-bad-email-{index:03d}",
                    },
                )
                status, _ = self._post({
                    "request": request.to_dict(),
                    "permit": self._permit(request, mode="APPROVED").__dict__,
                })
                self.assertEqual(status, 400)
                receipt_status, _ = self._get_receipt(request.agent_id, request.request_id)
                self.assertEqual(receipt_status, 404)

        with self.assertRaisesRegex(ValueError, "semantic version"):
            ProviderToolRegistry(bindings={
                ("research_agent", "read_database", "research_db"): ProviderToolContract(
                    version="version-one",
                    required_mode="ALLOW",
                    input_kind="research_query_v1",
                    input_schema={"$schema": ProviderToolRegistry.SCHEMA_DIALECT, "type": "object"},
                    output_schema={"$schema": ProviderToolRegistry.SCHEMA_DIALECT, "type": "object"},
                )
            })

    def test_provider_rejects_invalid_research_schema_before_claiming_execution(self) -> None:
        request = ActionRequest.from_payload(
            "research_agent",
            {
                "action": "read_database",
                "resource": "research_db",
                "parameters": {"query": "market", "limit": 100},
                "request_id": "provider-fixture-extra-param-001",
            },
        )
        status, body = self._post({
            "request": request.to_dict(),
            "permit": self._permit(request).__dict__,
        })
        self.assertEqual(status, 400)
        receipt_status, _ = self._get_receipt(request.agent_id, request.request_id)
        self.assertEqual(receipt_status, 404)

    def test_provider_registry_denies_unregistered_bindings_and_wrong_permit_modes(self) -> None:
        cases = [
            ("research_agent", "send_email", "company_email", "ALLOW"),
            ("research_agent", "read_database", "research_db", "APPROVED"),
            ("research_agent", "read_database", "payroll_db", "ALLOW"),
            ("unregistered_agent", "read_database", "research_db", "ALLOW"),
            ("research_agent", "delete_audit_log", "audit_log", "ALLOW"),
        ]
        for index, (agent_id, action, resource, mode) in enumerate(cases, start=1):
            with self.subTest(agent_id=agent_id, action=action, resource=resource, mode=mode):
                if action == "read_database":
                    parameters = {"query": "bounded-provider-test"}
                elif action == "send_email":
                    parameters = {
                        "recipient": "denied@example.test",
                        "subject": "Denied request",
                        "body": "This must not execute.",
                    }
                else:
                    parameters = {}
                request = ActionRequest.from_payload(
                    agent_id,
                    {
                        "action": action,
                        "resource": resource,
                        "parameters": parameters,
                        "request_id": f"provider-registry-deny-{index:03d}",
                    },
                )
                status, body = self._post({
                    "request": request.to_dict(),
                    "permit": self._permit(request, mode=mode).__dict__,
                })
                self.assertEqual(status, 403)
                self.assertEqual(body.get("code"), "dispatch_denied")
                receipt_status, _ = self._get_receipt(agent_id, request.request_id)
                self.assertEqual(receipt_status, 404)

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
        delegate = HttpToolProviderAdapter(self.endpoint, receipt_signing_key=SIGNING_KEY)
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
            adapter=HttpToolProviderAdapter(self.endpoint, receipt_signing_key=SIGNING_KEY),
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
                "parameters": {"recipient": "pending-recovery@example.test", "subject": "Pending recovery", "body": "Test-only pending recovery payload."},
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
            adapter=HttpToolProviderAdapter(self.endpoint, receipt_signing_key=SIGNING_KEY),
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
                "parameters": {"recipient": "approved-recovery@example.test", "subject": "Approved recovery", "body": "Test-only approved recovery payload."},
                "request_id": "gateway-restart-approved-execution-001",
            },
        )
        db_path = self.root / "gateway-approved-recovery.sqlite3"
        store = ApprovalStore(db_path)
        delegate = HttpToolProviderAdapter(self.endpoint, receipt_signing_key=SIGNING_KEY)
        original_gateway = CustosGateway(
            store=store,
            audit_log=AuditLog(str(self.root / "gateway-approved-before-crash-audit.jsonl")),
            adapter=delegate,
            dispatch_signing_key=SIGNING_KEY,
        )
        pending = original_gateway.submit(request)
        approval_id = pending["approval_id"]
        original_gateway.review_approval(approval_id, "recovery-reviewer", True)
        claimed_request = store.claim_for_execution(approval_id, request.agent_id, time.time())
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
        delegate = HttpToolProviderAdapter(self.endpoint, receipt_signing_key=SIGNING_KEY)

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
            adapter=HttpToolProviderAdapter(self.endpoint, timeout_seconds=0.25, receipt_signing_key=SIGNING_KEY),
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
