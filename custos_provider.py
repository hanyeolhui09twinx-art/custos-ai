from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import os
import re
import sqlite3
import time
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlsplit
from urllib.request import Request, urlopen

from audit_log import AuditLog
from keyring_audit import KeyRingLifecycle
from custos_gateway import (
    ActionRequest, DispatchAuthorizationError, DispatchAuthority, IDENTIFIER_RE,
    REQUEST_ID_RE, DispatchPermit, MockExecutionAdapter, canonical_json,
)

MAX_BODY_BYTES = 65_536
PROVIDER_PATH = "/v1/dispatch"
RECEIPT_SIGNATURE_HEADER = "X-Custos-Receipt-Signature"
RECEIPT_KEY_ID_HEADER = "X-Custos-Receipt-Key-Id"


def receipt_lookup_signature(
    signing_key: bytes,
    request_path: str,
    key_id: str = "default",
) -> str:
    """Sign a GET receipt path with a key-specific, domain-separated derived key."""
    if not isinstance(signing_key, bytes) or len(signing_key) < 32:
        raise ValueError("Receipt lookup signing key must be at least 32 bytes.")
    if not isinstance(key_id, str) or not IDENTIFIER_RE.fullmatch(key_id):
        raise ValueError("Receipt lookup key ID is invalid.")
    if not isinstance(request_path, str) or not request_path.startswith("/v1/receipts/") or "?" in request_path:
        raise ValueError("Receipt lookup path is invalid.")
    receipt_key = hmac.new(
        signing_key, b"custos-ai/provider-receipt-lookup/v1/" + key_id.encode("ascii"), hashlib.sha256
    ).digest()
    message = b"GET" + bytes([10]) + key_id.encode("ascii") + bytes([10]) + request_path.encode("utf-8")
    return hmac.new(receipt_key, message, hashlib.sha256).hexdigest()


class DurableDispatchPermitVerifier:
    """Verify gateway-issued permits and persist nonce consumption in SQLite."""

    def __init__(
        self,
        db_path: str | Path,
        signing_key: bytes | None = None,
        clock: Callable[[], float] = time.time,
        max_ttl_seconds: float = 15.0,
        signing_keys: dict[str, bytes] | None = None,
        active_key_id: str = "default",
    ) -> None:
        if (
            isinstance(max_ttl_seconds, bool)
            or not isinstance(max_ttl_seconds, (int, float))
            or not math.isfinite(max_ttl_seconds)
            or max_ttl_seconds <= 0
        ):
            raise ValueError("Provider TTL must be finite and positive.")
        if not isinstance(active_key_id, str) or not IDENTIFIER_RE.fullmatch(active_key_id):
            raise ValueError("Active provider key ID is invalid.")
        keys: dict[str, bytes] = {}
        if signing_keys is not None:
            if not isinstance(signing_keys, dict) or not signing_keys:
                raise ValueError("Provider key ring must be a non-empty mapping.")
            for key_id, key_value in signing_keys.items():
                if not isinstance(key_id, str) or not IDENTIFIER_RE.fullmatch(key_id):
                    raise ValueError("Provider key IDs must be valid identifiers.")
                if not isinstance(key_value, bytes) or len(key_value) < 32:
                    raise ValueError("Every provider signing key must be at least 32 bytes.")
                keys[key_id] = key_value
        if signing_key is not None:
            if not isinstance(signing_key, bytes) or len(signing_key) < 32:
                raise ValueError("Provider signing key must be at least 32 bytes.")
            prior = keys.get(active_key_id)
            if prior is not None and not hmac.compare_digest(prior, signing_key):
                raise ValueError("Provider active key conflicts with key-ring entry.")
            keys[active_key_id] = signing_key
        if not keys:
            raise ValueError("At least one provider signing key is required.")
        if active_key_id not in keys:
            raise ValueError("Active provider key ID is not present in the key ring.")
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._keys = keys
        self._active_key_id = active_key_id
        self._key_fingerprints = {
            key_id: hashlib.sha256(key_value).hexdigest()
            for key_id, key_value in keys.items()
        }
        self._clock = clock
        self._ttl = float(max_ttl_seconds)
        with self._connect() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS consumed_permits (
                nonce TEXT PRIMARY KEY, request_digest TEXT NOT NULL,
                expires_at REAL NOT NULL, consumed_at REAL NOT NULL)""")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_consumed_permits_expiry ON consumed_permits(expires_at)")

    @property
    def key_fingerprints(self) -> dict[str, str]:
        return dict(self._key_fingerprints)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def verify_receipt_lookup(self, request_path: str, key_id: str, signature: str) -> bool:
        if not isinstance(key_id, str) or not IDENTIFIER_RE.fullmatch(key_id):
            return False
        key = self._keys.get(key_id)
        if key is None:
            return False
        if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{64}", signature):
            return False
        try:
            expected = receipt_lookup_signature(key, request_path, key_id)
        except (TypeError, ValueError, UnicodeEncodeError):
            return False
        return hmac.compare_digest(expected, signature)

    def consume(self, request: ActionRequest, data: Any) -> DispatchPermit:
        fields = set(DispatchPermit.__dataclass_fields__)
        if not isinstance(data, dict) or set(data) != fields:
            raise DispatchAuthorizationError("A complete signed permit is required.")
        try:
            permit = DispatchPermit(**data)
        except (TypeError, ValueError) as exc:
            raise DispatchAuthorizationError("Malformed provider permit.") from exc
        if not isinstance(permit.request_digest, str) or not hmac.compare_digest(permit.request_digest, request.digest):
            raise DispatchAuthorizationError("Permit does not match this request.")
        if permit.mode not in {"ALLOW", "APPROVED"}:
            raise DispatchAuthorizationError("Invalid permit mode.")
        if permit.mode == "ALLOW" and permit.approval_id is not None:
            raise DispatchAuthorizationError("ALLOW permit cannot contain an approval ID.")
        if permit.mode == "APPROVED" and (not isinstance(permit.approval_id, str) or not permit.approval_id):
            raise DispatchAuthorizationError("APPROVED permit requires an approval ID.")
        if not isinstance(permit.key_id, str) or not IDENTIFIER_RE.fullmatch(permit.key_id):
            raise DispatchAuthorizationError("Invalid permit key ID.")
        signing_key = self._keys.get(permit.key_id)
        if signing_key is None:
            raise DispatchAuthorizationError("Permit key ID is not trusted by this provider.")
        if not isinstance(permit.nonce, str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", permit.nonce):
            raise DispatchAuthorizationError("Invalid permit nonce.")
        if not isinstance(permit.signature, str) or not re.fullmatch(r"[0-9a-f]{64}", permit.signature):
            raise DispatchAuthorizationError("Invalid permit signature.")
        for value in (permit.issued_at, permit.expires_at):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise DispatchAuthorizationError("Invalid permit timestamp.")
        try:
            expected = hmac.new(
                signing_key, canonical_json(DispatchAuthority._claims(permit)).encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
        except (TypeError, ValueError, RecursionError) as exc:
            raise DispatchAuthorizationError("Invalid permit claims.") from exc
        if not hmac.compare_digest(expected, permit.signature):
            raise DispatchAuthorizationError("Permit signature is invalid.")
        now = self._clock()
        lifetime = permit.expires_at - permit.issued_at
        if permit.issued_at > now or permit.expires_at <= now or lifetime <= 0 or lifetime > self._ttl:
            raise DispatchAuthorizationError("Permit expired or outside its validity window.")

        # A transaction and a unique nonce key make consumption atomic across
        # provider workers and durable across a provider restart.
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM consumed_permits WHERE expires_at <= ?", (now,))
            try:
                conn.execute(
                    "INSERT INTO consumed_permits VALUES (?, ?, ?, ?)",
                    (permit.nonce, request.digest, permit.expires_at, now),
                )
            except sqlite3.IntegrityError as exc:
                conn.rollback()
                raise DispatchAuthorizationError("Permit has already been consumed.") from exc
            conn.commit()
        return permit


class ExecutionReceiptConflict(Exception):
    pass


class ExecutionReceiptInProgress(Exception):
    pass


class ExecutionReceiptIndeterminate(Exception):
    pass


class ExecutionReceiptStore:
    """Durable at-most-once dispatch ledger keyed by authenticated agent and request ID."""

    def __init__(self, db_path: str | Path, clock: Callable[[], float] = time.time) -> None:
        self.db_path = str(db_path)
        self._clock = clock
        with self._connect() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS execution_receipts (
                agent_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('executing','completed','indeterminate')),
                result_json TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                PRIMARY KEY(agent_id, request_id)
            )""")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_execution_receipts_status ON execution_receipts(status, updated_at)")
        self.recover_interrupted()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def recover_interrupted(self) -> int:
        """Never replay an operation whose side-effect outcome may be unknown."""
        now = self._clock()
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE execution_receipts SET status='indeterminate', updated_at=? WHERE status='executing'",
                (now,),
            )
            return cursor.rowcount

    def get(self, agent_id: str, request_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM execution_receipts WHERE agent_id=? AND request_id=?",
                (agent_id, request_id),
            ).fetchone()
        if row is None:
            return None
        record = dict(row)
        if record.get("result_json"):
            record["result"] = json.loads(record.pop("result_json"))
        else:
            record.pop("result_json", None)
        return record

    def execute_once(
        self,
        request: ActionRequest,
        executor: Callable[[ActionRequest], dict[str, Any]],
    ) -> dict[str, Any]:
        now = self._clock()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM execution_receipts WHERE agent_id=? AND request_id=?",
                (request.agent_id, request.request_id),
            ).fetchone()
            if row is not None:
                conn.rollback()
                if row["request_digest"] != request.digest:
                    raise ExecutionReceiptConflict("request_id was already used with a different request digest.")
                if row["status"] == "completed" and row["result_json"]:
                    return json.loads(row["result_json"])
                if row["status"] == "executing":
                    raise ExecutionReceiptInProgress("This request is already being executed.")
                raise ExecutionReceiptIndeterminate("The previous execution outcome is indeterminate; automatic replay is forbidden.")
            conn.execute(
                """INSERT INTO execution_receipts
                   (agent_id, request_id, request_digest, status, created_at, updated_at)
                   VALUES (?, ?, ?, 'executing', ?, ?)""",
                (request.agent_id, request.request_id, request.digest, now, now),
            )
            conn.commit()

        try:
            result = executor(request)
            if not isinstance(result, dict):
                raise TypeError("Tool result must be a JSON object.")
            result_json = canonical_json(result)
        except Exception:
            with self._connect() as conn:
                conn.execute(
                    """UPDATE execution_receipts SET status='indeterminate', updated_at=?
                       WHERE agent_id=? AND request_id=? AND status='executing'""",
                    (self._clock(), request.agent_id, request.request_id),
                )
            raise

        with self._connect() as conn:
            cursor = conn.execute(
                """UPDATE execution_receipts SET status='completed', result_json=?, updated_at=?
                   WHERE agent_id=? AND request_id=? AND status='executing'""",
                (result_json, self._clock(), request.agent_id, request.request_id),
            )
            if cursor.rowcount != 1:
                raise ExecutionReceiptIndeterminate("Execution result could not be committed; outcome is indeterminate.")
        return result


def validate_json_schema(value: Any, schema: dict[str, Any], path: str = "$") -> None:
    """Validate the deliberately small JSON Schema subset used by Provider contracts."""
    if not isinstance(schema, dict):
        raise TypeError("Provider JSON Schema definition must be an object.")

    expected_type = schema.get("type")
    if expected_type == "object":
        if not isinstance(value, dict):
            raise ValueError(f"{path} must be an object.")
        required = schema.get("required", [])
        if not isinstance(required, list) or not all(isinstance(item, str) for item in required):
            raise TypeError("JSON Schema required must be a list of strings.")
        missing = set(required) - set(value)
        if missing:
            raise ValueError(f"{path} is missing required fields.")
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            raise TypeError("JSON Schema properties must be an object.")
        if schema.get("additionalProperties") is False:
            extra = set(value) - set(properties)
            if extra:
                raise ValueError(f"{path} contains unregistered fields.")
        for key, item in value.items():
            if key in properties:
                validate_json_schema(item, properties[key], f"{path}.{key}")
            elif isinstance(schema.get("additionalProperties"), dict):
                validate_json_schema(item, schema["additionalProperties"], f"{path}.{key}")
    elif expected_type == "string":
        if not isinstance(value, str):
            raise ValueError(f"{path} must be a string.")
        if len(value) < schema.get("minLength", 0):
            raise ValueError(f"{path} is shorter than the minimum length.")
        if len(value) > schema.get("maxLength", float("inf")):
            raise ValueError(f"{path} exceeds the maximum length.")
        pattern = schema.get("pattern")
        if pattern is not None and re.search(pattern, value) is None:
            raise ValueError(f"{path} does not match its required pattern.")
        if schema.get("format") == "email" and not re.fullmatch(r"[^@\s]+@[^@\s]+", value):
            raise ValueError(f"{path} must use the email format.")
    elif expected_type == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{path} must be an integer.")
        if value < schema.get("minimum", float("-inf")) or value > schema.get("maximum", float("inf")):
            raise ValueError(f"{path} is outside the allowed integer range.")
    elif expected_type == "array":
        if not isinstance(value, list):
            raise ValueError(f"{path} must be an array.")
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", float("inf")):
            raise ValueError(f"{path} has an invalid number of items.")
        item_schema = schema.get("items")
        if not isinstance(item_schema, dict):
            raise TypeError("JSON Schema array items must define an object schema.")
        for index, item in enumerate(value):
            validate_json_schema(item, item_schema, f"{path}[{index}]")
    elif expected_type is not None:
        raise ValueError(f"Unsupported JSON Schema type: {expected_type}")

    if "const" in schema and value != schema["const"]:
        raise ValueError(f"{path} does not match its required constant.")


@dataclass(frozen=True)
class ProviderToolContract:
    """Versioned input/output contract whose JSON Schema is the source of truth."""

    version: str
    required_mode: str
    input_kind: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]

    @property
    def result_status(self) -> str:
        status_schema = self.output_schema.get("properties", {}).get("status", {})
        status = status_schema.get("const")
        if not isinstance(status, str):
            raise ValueError("Provider output schema must declare a constant status.")
        return status

    @property
    def parameter_fields(self) -> frozenset[str]:
        properties = self.input_schema.get("properties", {})
        if not isinstance(properties, dict):
            raise ValueError("Provider input schema must define object properties.")
        return frozenset(properties)

    def validate_parameters(self, parameters: Any, research_fixture: "ReadOnlyResearchFixture") -> None:
        validate_json_schema(parameters, self.input_schema, "$.parameters")
        if self.input_kind == "research_query_v1":
            research_fixture.validate_parameters(parameters)
        elif self.input_kind != "email_request_v1":
            raise ValueError("Provider tool contract input kind is not supported.")

    def validate_result(self, request: ActionRequest, result: Any) -> dict[str, Any]:
        validate_json_schema(result, self.output_schema, "$.result")
        common = {
            "agent_id": request.agent_id,
            "action": request.action,
            "resource": request.resource,
            "request_id": request.request_id,
            "contract_version": self.version,
            "status": self.result_status,
        }
        for key, expected in common.items():
            if result.get(key) != expected:
                raise TypeError("Provider tool result does not match its registered contract.")
        if self.input_kind == "research_query_v1":
            if (
                result.get("query") != request.parameters["query"].strip()
                or result.get("row_count") != len(result.get("records", []))
            ):
                raise TypeError("Research result values do not match the registered contract.")
        return result

    def to_document(
        self,
        agent_id: str,
        action: str,
        resource: str,
    ) -> dict[str, Any]:
        return {
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            "contract_version": self.version,
            "required_permit_mode": self.required_mode,
            "input_kind": self.input_kind,
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
        }


class ProviderToolRegistry:
    """Provider-side deny-by-default registry loaded from the published schema catalog."""

    SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
    CATALOG_RELATIVE_PATH = Path("contracts") / "provider-tool-contracts.v1.0.0.json"

    def __init__(
        self,
        bindings: dict[tuple[str, str, str], ProviderToolContract] | None = None,
        catalog_path: str | Path | None = None,
    ) -> None:
        if bindings is None:
            path = Path(catalog_path) if catalog_path is not None else Path(__file__).resolve().parent / self.CATALOG_RELATIVE_PATH
            document = json.loads(path.read_text(encoding="utf-8"))
            if (
                not isinstance(document, dict)
                or set(document) != {"catalog_version", "schema_dialect", "contracts"}
                or document.get("schema_dialect") != self.SCHEMA_DIALECT
                or not isinstance(document.get("contracts"), list)
            ):
                raise ValueError("Provider contract catalog metadata is invalid.")
            if not re.fullmatch(r"\d+\.\d+\.\d+", document["catalog_version"]):
                raise ValueError("Provider catalog version must use semantic version notation.")
            configured: dict[tuple[str, str, str], ProviderToolContract] = {}
            for entry in document["contracts"]:
                expected_fields = {
                    "agent_id", "action", "resource", "contract_version",
                    "required_permit_mode", "input_kind", "input_schema", "output_schema",
                }
                if not isinstance(entry, dict) or set(entry) != expected_fields:
                    raise ValueError("Provider contract catalog entry has an invalid shape.")
                binding = (entry["agent_id"], entry["action"], entry["resource"])
                if binding in configured:
                    raise ValueError("Provider contract catalog contains a duplicate binding.")
                configured[binding] = ProviderToolContract(
                    version=entry["contract_version"],
                    required_mode=entry["required_permit_mode"],
                    input_kind=entry["input_kind"],
                    input_schema=entry["input_schema"],
                    output_schema=entry["output_schema"],
                )
            self.catalog_version = document["catalog_version"]
            self.schema_dialect = document["schema_dialect"]
        else:
            configured = bindings
            self.catalog_version = "1.0.0"
            self.schema_dialect = self.SCHEMA_DIALECT

        if not isinstance(configured, dict) or not configured:
            raise ValueError("Provider tool contracts must be a non-empty mapping.")
        self._bindings: dict[tuple[str, str, str], ProviderToolContract] = {}
        for binding, contract in configured.items():
            if (
                not isinstance(binding, tuple)
                or len(binding) != 3
                or not all(isinstance(part, str) and IDENTIFIER_RE.fullmatch(part) for part in binding)
            ):
                raise ValueError("Provider contracts must bind exact (agent, action, resource) identifier triples.")
            if not isinstance(contract, ProviderToolContract):
                raise ValueError("Every Provider binding must contain a versioned tool contract.")
            if contract.required_mode not in {"ALLOW", "APPROVED"}:
                raise ValueError("Provider contracts must require ALLOW or APPROVED permits.")
            if not re.fullmatch(r"\d+\.\d+\.\d+", contract.version):
                raise ValueError("Provider contract versions must use semantic version notation.")
            if not isinstance(contract.input_schema, dict) or not isinstance(contract.output_schema, dict):
                raise ValueError("Provider contracts must contain input and output JSON Schemas.")
            if contract.input_schema.get("type") != "object" or contract.output_schema.get("type") != "object":
                raise ValueError("Provider tool input and output schemas must be JSON objects.")
            if contract.input_schema.get("$schema") != self.SCHEMA_DIALECT or contract.output_schema.get("$schema") != self.SCHEMA_DIALECT:
                raise ValueError("Provider tool schemas must declare JSON Schema Draft 2020-12.")
            self._bindings[binding] = contract

        self._catalog_document = {
            "catalog_version": self.catalog_version,
            "schema_dialect": self.schema_dialect,
            "contracts": [
                contract.to_document(*binding)
                for binding, contract in sorted(self._bindings.items())
            ],
        }

    def to_catalog_document(self) -> dict[str, Any]:
        return json.loads(json.dumps(self._catalog_document, ensure_ascii=False))

    def contract_for(self, request: ActionRequest) -> ProviderToolContract:
        binding = (request.agent_id, request.action, request.resource)
        contract = self._bindings.get(binding)
        if contract is None:
            raise DispatchAuthorizationError(
                "No Provider tool contract exists for this agent/action/resource tuple."
            )
        return contract

    def required_mode(self, request: ActionRequest) -> str:
        return self.contract_for(request).required_mode

    def authorize(self, request: ActionRequest, permit: DispatchPermit) -> None:
        contract = self.contract_for(request)
        if permit.mode != contract.required_mode:
            raise DispatchAuthorizationError(
                "The signed permit mode does not satisfy the Provider tool contract."
            )

class ReadOnlyResearchFixture:
    """Small synthetic SQLite dataset: initialized locally, queried read-only at runtime."""

    _SEED_ROWS = (
        (
            "market-001",
            "Current market research: AI adoption patterns",
            "Synthetic fixture record. Research note on enterprise AI market adoption, bounded permissions, and human decision review.",
            "synthetic-fixture",
        ),
        (
            "agency-001",
            "Human agency and AI authorization",
            "Synthetic fixture record. Research note on human review, delegated authority, and intervention boundaries.",
            "synthetic-fixture",
        ),
        (
            "registry-001",
            "Provider tool registry validation",
            "Synthetic fixture record. Research note on exact tool bindings, signed permissions, and replay protection.",
            "synthetic-fixture",
        ),
    )

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_fixture()

    def _initialize_fixture(self) -> None:
        # Creates a clearly synthetic local fixture. Runtime queries never use
        # this writable setup connection.
        with sqlite3.connect(self.db_path, timeout=5) as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS research_records (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    source TEXT NOT NULL
                )"""
            )
            connection.executemany(
                "INSERT OR IGNORE INTO research_records (id, title, content, source) VALUES (?, ?, ?, ?)",
                self._SEED_ROWS,
            )
            connection.commit()

    def _connect_readonly(self) -> sqlite3.Connection:
        uri = self.db_path.resolve().as_uri() + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        return connection

    @staticmethod
    def _validated_query(parameters: Any) -> tuple[str, list[str]]:
        if not isinstance(parameters, dict) or set(parameters) != {"query"}:
            raise ValueError("Research fixture accepts only one query parameter.")
        query = parameters.get("query")
        if not isinstance(query, str):
            raise ValueError("Research query must be text.")
        query = query.strip()
        if not query or len(query) > 160:
            raise ValueError("Research query must contain 1 to 160 characters.")
        tokens = list(dict.fromkeys(re.findall(r"[a-z]{2,32}|[가-힣]{2,16}", query.casefold())))
        if not tokens or len(tokens) > 8:
            raise ValueError("Research query must contain 1 to 8 searchable terms.")
        return query, tokens

    def validate_parameters(self, parameters: Any) -> None:
        self._validated_query(parameters)

    def search(self, parameters: Any) -> dict[str, Any]:
        # SQL structure is constant apart from the number of placeholders;
        # untrusted query text is always supplied as bound values.
        query, tokens = self._validated_query(parameters)
        clauses = ["lower(title || ' ' || content) LIKE ?" for _ in tokens]
        statement = (
            "SELECT id, title, content, source FROM research_records "
            "WHERE " + " AND ".join(clauses) + " ORDER BY id LIMIT 5"
        )
        connection = self._connect_readonly()
        try:
            rows = connection.execute(statement, [f"%{token}%" for token in tokens]).fetchall()
        finally:
            connection.close()

        records = []
        for row in rows:
            record = dict(row)
            # Enforce whole-token matching after the bounded SQL pre-filter.
            # This avoids substring surprises such as "or" matching "record".
            text_tokens = set(
                re.findall(r"[a-z]{2,32}|[가-힣]{2,16}", (record["title"] + " " + record["content"]).casefold())
            )
            if all(token in text_tokens for token in tokens):
                records.append(record)
        return {
            "status": "read_only",
            "storage": "local_synthetic_sqlite_fixture",
            "resource": "research_db",
            "query": query,
            "row_count": len(records),
            "records": records,
        }


class ProviderExecutionAdapter:
    """Exact provider-side adapter split: fixture reads and mock-only email."""

    def __init__(self, research_fixture_db_path: str | Path) -> None:
        self.research_fixture = ReadOnlyResearchFixture(research_fixture_db_path)
        self.mock_adapter = MockExecutionAdapter()

    def validate(self, request: ActionRequest, contract: ProviderToolContract) -> None:
        contract.validate_parameters(request.parameters, self.research_fixture)

    def execute(self, request: ActionRequest, contract: ProviderToolContract) -> dict[str, Any]:
        binding = (request.action, request.resource)
        if binding == ("read_database", "research_db"):
            result = self.research_fixture.search(request.parameters)
        elif binding == ("send_email", "company_email"):
            result = self.mock_adapter.execute(request)
        else:
            raise DispatchAuthorizationError("No Provider execution adapter exists for this action/resource pair.")

        result.update({
            "agent_id": request.agent_id,
            "action": request.action,
            "resource": request.resource,
            "request_id": request.request_id,
            "contract_version": contract.version,
        })
        return contract.validate_result(request, result)


class ToolProviderService:
    """The provider owns its tool registry; the calling agent receives no tool client."""

    def __init__(
        self,
        verifier: DurableDispatchPermitVerifier,
        research_fixture_db_path: str | Path | None = None,
    ) -> None:
        self.verifier = verifier
        self.receipts = ExecutionReceiptStore(verifier.db_path)
        self.registry = ProviderToolRegistry()
        fixture_path = research_fixture_db_path or Path(verifier.db_path).with_name("research-fixture.sqlite3")
        self.adapter = ProviderExecutionAdapter(fixture_path)

    def get_receipt(self, agent_id: str, request_id: str) -> dict[str, Any] | None:
        return self.receipts.get(agent_id, request_id)

    def verify_receipt_lookup(self, request_path: str, key_id: str, signature: str) -> bool:
        return self.verifier.verify_receipt_lookup(request_path, key_id, signature)

    def dispatch(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict) or set(payload) != {"request", "permit"}:
            raise DispatchAuthorizationError("Only a request with a signed permit is accepted.")
        data = payload["request"]
        if not isinstance(data, dict) or set(data) != {
            "agent_id", "action", "resource", "parameters", "request_id"
        }:
            raise ValueError("Invalid provider request schema.")
        request = ActionRequest.from_payload(data["agent_id"], {
            "action": data["action"], "resource": data["resource"],
            "parameters": data["parameters"], "request_id": data["request_id"],
        })
        # Resolve the versioned tool contract and validate its exact input schema
        # before consuming a signed permit or claiming an execution receipt.
        contract = self.registry.contract_for(request)
        self.adapter.validate(request, contract)
        permit = self.verifier.consume(request, payload["permit"])
        self.registry.authorize(request, permit)

        def execute_with_contract(candidate: ActionRequest) -> dict[str, Any]:
            return self.adapter.execute(candidate, contract)

        # The durable receipt stores only a result that passed the same versioned
        # output contract. An interrupted execution is never replayed automatically.
        return self.receipts.execute_once(request, execute_with_contract)


class ToolProviderHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], service: ToolProviderService) -> None:
        self.service = service
        super().__init__(address, self._handler())

    @staticmethod
    def _handler() -> type[BaseHTTPRequestHandler]:
        class Handler(BaseHTTPRequestHandler):
            server_version = "CustosToolProvider/0.1"
            sys_version = ""

            def _send(self, status: int, payload: dict[str, Any]) -> None:
                body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                path = urlsplit(self.path).path
                if path == "/health":
                    self._send(200, {"status": "ok", "service": "custos-tool-provider", "mode": "mock"})
                    return
                parts = path.split("/")
                if len(parts) == 5 and parts[1:3] == ["v1", "receipts"]:
                    if urlsplit(self.path).query:
                        self._send(400, {"error": "Receipt lookup does not accept query parameters."})
                        return
                    key_id = self.headers.get(RECEIPT_KEY_ID_HEADER, "")
                    signature = self.headers.get(RECEIPT_SIGNATURE_HEADER, "")
                    if not key_id or not signature:
                        self._send(401, {"error": "Receipt lookup authentication is required."})
                        return
                    if not self.server.service.verify_receipt_lookup(path, key_id, signature):  # type: ignore[attr-defined]
                        self._send(403, {"error": "Receipt lookup authentication failed."})
                        return
                    agent_id, request_id = unquote(parts[3]), unquote(parts[4])
                    if not IDENTIFIER_RE.fullmatch(agent_id) or not REQUEST_ID_RE.fullmatch(request_id):
                        self._send(400, {"error": "Invalid receipt identifier."})
                        return
                    receipt = self.server.service.get_receipt(agent_id, request_id)  # type: ignore[attr-defined]
                    if receipt is None:
                        self._send(404, {"error": "Execution receipt not found."})
                    else:
                        self._send(200, {"receipt": receipt})
                    return
                self._send(404, {"error": "Not found."})

            def do_POST(self) -> None:
                if urlsplit(self.path).path != PROVIDER_PATH:
                    self._send(404, {"error": "Not found."})
                    return
                try:
                    length = int(self.headers.get("Content-Length", ""))
                except ValueError:
                    self._send(400, {"error": "Invalid Content-Length."})
                    return
                if length < 1 or length > MAX_BODY_BYTES:
                    self._send(413 if length > MAX_BODY_BYTES else 400, {"error": "Invalid request size."})
                    return
                try:
                    raw = self.rfile.read(length)
                    payload = json.loads(raw.decode("utf-8"))
                    result = self.server.service.dispatch(payload)  # type: ignore[attr-defined]
                    self._send(200, {"result": result})
                except DispatchAuthorizationError:
                    self._send(403, {"error": "Dispatch authorization rejected.", "code": "dispatch_denied"})
                except ExecutionReceiptConflict:
                    self._send(409, {"error": "Request ID conflicts with a different request digest.", "code": "idempotency_conflict"})
                except (ExecutionReceiptInProgress, ExecutionReceiptIndeterminate):
                    self._send(409, {"error": "Execution outcome is not yet safely repeatable.", "code": "execution_outcome_unknown"})
                except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
                    self._send(400, {"error": "Malformed or unsupported provider request."})
                except Exception:
                    self._send(500, {"error": "Provider execution failed."})

            def log_message(self, format: str, *args: Any) -> None:
                # Default access logs contain method/path only, never the request body.
                super().log_message(format, *args)
        return Handler


def create_provider_server(
    signing_key: bytes | None = None,
    db_path: str | Path = ".custos-data/provider-replay.sqlite3",
    host: str = "127.0.0.1",
    port: int = 8766,
    signing_keys: dict[str, bytes] | None = None,
    active_key_id: str = "default",
    audit_path: str | Path | None = None,
    research_fixture_db_path: str | Path | None = None,
) -> ToolProviderHTTPServer:
    if host != "127.0.0.1":
        raise ValueError("The mock provider only binds to loopback.")
    verifier = DurableDispatchPermitVerifier(
        db_path,
        signing_key=signing_key,
        signing_keys=signing_keys,
        active_key_id=active_key_id,
    )
    resolved_audit_path = Path(audit_path) if audit_path is not None else Path(db_path).with_suffix(".audit.jsonl")
    KeyRingLifecycle(db_path, AuditLog(str(resolved_audit_path)), component="provider").observe(
        verifier.key_fingerprints, active_key_id
    )
    service = ToolProviderService(verifier, research_fixture_db_path=research_fixture_db_path)
    return ToolProviderHTTPServer((host, port), service)


class HttpToolProviderAdapter:
    """Gateway-side client that forwards a permit, never a raw tool client or credential."""

    def __init__(
        self,
        endpoint: str,
        timeout_seconds: float = 3.0,
        receipt_signing_key: bytes | None = None,
        receipt_signing_keys: dict[str, bytes] | None = None,
        receipt_signing_key_id: str = "default",
    ) -> None:
        if not isinstance(receipt_signing_key_id, str) or not IDENTIFIER_RE.fullmatch(receipt_signing_key_id):
            raise ValueError("Receipt signing key ID is invalid.")
        receipt_keys: dict[str, bytes] = {}
        if receipt_signing_keys is not None:
            if not isinstance(receipt_signing_keys, dict) or not receipt_signing_keys:
                raise ValueError("Receipt signing key ring must be a non-empty mapping.")
            for key_id, key_value in receipt_signing_keys.items():
                if not isinstance(key_id, str) or not IDENTIFIER_RE.fullmatch(key_id):
                    raise ValueError("Receipt key IDs must be valid identifiers.")
                if not isinstance(key_value, bytes) or len(key_value) < 32:
                    raise ValueError("Every receipt signing key must be at least 32 bytes.")
                receipt_keys[key_id] = key_value
        if receipt_signing_key is not None:
            if not isinstance(receipt_signing_key, bytes) or len(receipt_signing_key) < 32:
                raise ValueError("Receipt signing key must be at least 32 bytes.")
            prior = receipt_keys.get(receipt_signing_key_id)
            if prior is not None and not hmac.compare_digest(prior, receipt_signing_key):
                raise ValueError("Receipt active key conflicts with key-ring entry.")
            receipt_keys[receipt_signing_key_id] = receipt_signing_key
        if receipt_keys and receipt_signing_key_id not in receipt_keys:
            raise ValueError("Active receipt key ID is not present in the key ring.")
        parsed = urlsplit(endpoint)
        if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
                or parsed.username is not None or parsed.password is not None
                or parsed.path != PROVIDER_PATH or parsed.query or parsed.fragment):
            raise ValueError("Endpoint must be the loopback HTTP /v1/dispatch route.")
        if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
                or not math.isfinite(timeout_seconds) or timeout_seconds <= 0):
            raise ValueError("Provider timeout must be finite and positive.")
        self.endpoint = endpoint
        self.timeout_seconds = float(timeout_seconds)
        self.receipt_signing_keys = receipt_keys
        self.receipt_signing_key_id = receipt_signing_key_id

    def execute(self, request: ActionRequest) -> dict[str, Any]:
        raise DispatchAuthorizationError("The provider requires a gateway-issued permit.")

    def execute_with_permit(self, request: ActionRequest, permit: DispatchPermit) -> dict[str, Any]:
        body = json.dumps(
            {"request": request.to_dict(), "permit": asdict(permit)},
            ensure_ascii=False, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
        outbound = Request(self.endpoint, data=body, method="POST",
                           headers={"Content-Type": "application/json", "Accept": "application/json"})
        try:
            with urlopen(outbound, timeout=self.timeout_seconds) as response:
                result = json.loads(response.read(MAX_BODY_BYTES + 1).decode("utf-8"))
        except HTTPError as exc:
            try:
                error_payload = json.loads(exc.read(MAX_BODY_BYTES + 1).decode("utf-8"))
            except Exception:
                error_payload = {}
            if exc.code == 409 and isinstance(error_payload, dict) and error_payload.get("code") == "execution_outcome_unknown":
                from custos_gateway import DispatchOutcomeUnknown
                raise DispatchOutcomeUnknown("Provider reports an in-progress or indeterminate execution.") from exc
            if 400 <= exc.code < 500:
                raise DispatchAuthorizationError("Provider rejected dispatch.") from exc
            from custos_gateway import DispatchOutcomeUnknown
            raise DispatchOutcomeUnknown("Provider returned a server error after dispatch was submitted.") from exc
        except (URLError, TimeoutError, OSError) as exc:
            from custos_gateway import DispatchOutcomeUnknown
            raise DispatchOutcomeUnknown("Provider response was lost; execution outcome is unknown.") from exc
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            from custos_gateway import DispatchOutcomeUnknown
            raise DispatchOutcomeUnknown("Provider response could not be interpreted; execution outcome is unknown.") from exc
        if not isinstance(result, dict) or set(result) != {"result"} or not isinstance(result["result"], dict):
            from custos_gateway import DispatchOutcomeUnknown
            raise DispatchOutcomeUnknown("Provider returned an invalid response after dispatch.")
        return result["result"]

    def get_receipt(self, agent_id: str, request_id: str) -> dict[str, Any] | None:
        key_id = self.receipt_signing_key_id
        signing_key = self.receipt_signing_keys.get(key_id)
        if signing_key is None:
            raise RuntimeError("Authenticated provider receipt lookup requires the active dispatch signing key.")
        if not isinstance(agent_id, str) or not IDENTIFIER_RE.fullmatch(agent_id):
            raise ValueError("Receipt Agent ID is invalid.")
        if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
            raise ValueError("Receipt request ID is invalid.")
        path = "/v1/receipts/" + quote(agent_id, safe="") + "/" + quote(request_id, safe="")
        url = self.endpoint.rsplit(PROVIDER_PATH, 1)[0] + path
        signature = receipt_lookup_signature(signing_key, path, key_id)
        outbound = Request(
            url,
            method="GET",
            headers={
                RECEIPT_KEY_ID_HEADER: key_id,
                RECEIPT_SIGNATURE_HEADER: signature,
                "Accept": "application/json",
            },
        )
        try:
            with urlopen(outbound, timeout=self.timeout_seconds) as response:
                payload = json.loads(response.read(MAX_BODY_BYTES + 1).decode("utf-8"))
        except HTTPError as exc:
            if exc.code == 404:
                return None
            raise RuntimeError("Provider receipt lookup failed.") from exc
        except (URLError, TimeoutError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("Provider receipt lookup is unavailable.") from exc
        if not isinstance(payload, dict) or set(payload) != {"receipt"} or not isinstance(payload["receipt"], dict):
            raise RuntimeError("Provider returned an invalid receipt response.")
        return payload["receipt"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local Custos mock tool provider.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--db", default=".custos-data/provider-replay.sqlite3")
    parser.add_argument("--audit", default=None, help="Provider key-lifecycle audit JSONL path")
    parser.add_argument("--research-fixture-db", default=None, help="Local synthetic SQLite fixture path; runtime reads are read-only")
    args = parser.parse_args()
    active_key_id = os.environ.get("CUSTOS_ACTIVE_DISPATCH_KEY_ID", "default")
    raw_key_ring = os.environ.get("CUSTOS_DISPATCH_KEYS", "")
    if raw_key_ring:
        try:
            encoded_keys = json.loads(raw_key_ring)
        except json.JSONDecodeError as exc:
            raise SystemExit("CUSTOS_DISPATCH_KEYS must be a JSON object.") from exc
        if not isinstance(encoded_keys, dict) or not encoded_keys:
            raise SystemExit("CUSTOS_DISPATCH_KEYS must be a non-empty JSON object.")
        key_ring: dict[str, bytes] = {}
        for key_id, key_hex in encoded_keys.items():
            if not isinstance(key_id, str) or not IDENTIFIER_RE.fullmatch(key_id):
                raise SystemExit("CUSTOS_DISPATCH_KEYS contains an invalid key ID.")
            if not isinstance(key_hex, str):
                raise SystemExit("Every CUSTOS_DISPATCH_KEYS value must be hexadecimal.")
            try:
                key_value = bytes.fromhex(key_hex)
            except ValueError as exc:
                raise SystemExit(f"Dispatch key {key_id!r} must be hexadecimal.") from exc
            if len(key_value) < 32:
                raise SystemExit(f"Dispatch key {key_id!r} must encode at least 32 bytes.")
            key_ring[key_id] = key_value
        if active_key_id not in key_ring:
            raise SystemExit("CUSTOS_ACTIVE_DISPATCH_KEY_ID must exist in CUSTOS_DISPATCH_KEYS.")
        server = create_provider_server(
            db_path=args.db, host=args.host, port=args.port,
            signing_keys=key_ring, active_key_id=active_key_id, audit_path=args.audit,
            research_fixture_db_path=args.research_fixture_db,
        )
    else:
        try:
            key = bytes.fromhex(os.environ.get("CUSTOS_DISPATCH_SIGNING_KEY", ""))
        except ValueError as exc:
            raise SystemExit("CUSTOS_DISPATCH_SIGNING_KEY must be hexadecimal.") from exc
        if len(key) < 32:
            raise SystemExit("CUSTOS_DISPATCH_SIGNING_KEY must encode at least 32 bytes.")
        server = create_provider_server(
            key, db_path=args.db, host=args.host, port=args.port,
            active_key_id=active_key_id, audit_path=args.audit,
            research_fixture_db_path=args.research_fixture_db,
        )
    print(f"Custos mock tool provider listening on {args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
