from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import secrets
import sqlite3
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Protocol

from audit_log import AuditLog

IDENTIFIER_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.:-]{0,127}$")
REQUEST_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$")
MAX_PARAMETERS_BYTES = 16_384


class Decision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    HUMAN_APPROVAL = "HUMAN_APPROVAL"


class ApprovalError(Exception):
    """Base error for human-approval lifecycle failures."""


class ApprovalNotFound(ApprovalError):
    pass


class ApprovalConflict(ApprovalError):
    pass


class ApprovalExpired(ApprovalError):
    pass


class ApprovalForbidden(ApprovalError):
    pass


class DispatchAuthorizationError(ApprovalError):
    """A dispatch permit is absent, invalid, expired, replayed, or no longer authorized."""


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def reject_raw_secrets(value: Any, path: str = "parameters") -> None:
    """Reject raw credential fields and excessively deep structures iteratively."""
    sensitive_parts = (
        "password",
        "passwd",
        "secret",
        "apikey",
        "authorization",
        "accesstoken",
        "refreshtoken",
        "privatekey",
        "bearertoken",
        "credential",
    )
    stack: list[tuple[Any, str, int]] = [(value, path, 0)]
    while stack:
        current, current_path, depth = stack.pop()
        if depth > 64:
            raise ValueError("parameters nesting exceeds the 64-level limit.")
        if isinstance(current, dict):
            for key, child in current.items():
                normalized = re.sub(r"[^a-z0-9]", "", str(key).casefold())
                is_reference = normalized.endswith(("ref", "reference"))
                if not is_reference and (
                    normalized == "token"
                    or any(part in normalized for part in sensitive_parts)
                ):
                    raise ValueError(
                        f"Raw credential field rejected at {current_path}.{key}; "
                        "use a managed credential reference."
                    )
                stack.append((child, f"{current_path}.{key}", depth + 1))
        elif isinstance(current, list):
            for index, child in enumerate(current):
                stack.append((child, f"{current_path}[{index}]", depth + 1))

@dataclass(frozen=True)
class ActionRequest:
    agent_id: str
    action: str
    resource: str
    parameters: dict[str, Any]
    request_id: str

    @classmethod
    def from_payload(cls, agent_id: str, payload: dict[str, Any]) -> "ActionRequest":
        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object.")

        allowed = {"action", "resource", "parameters", "request_id"}
        unknown = set(payload) - allowed
        if unknown:
            raise ValueError("Unknown request field(s): " + ", ".join(sorted(unknown)))

        if not isinstance(agent_id, str) or not IDENTIFIER_RE.fullmatch(agent_id):
            raise ValueError("Authenticated agent identity is invalid.")

        action = payload.get("action")
        resource = payload.get("resource")
        parameters = payload.get("parameters", {})
        request_id = payload.get("request_id") or str(uuid.uuid4())

        for label, value in (("action", action), ("resource", resource), ("request_id", request_id)):
            validator = REQUEST_ID_RE if label == "request_id" else IDENTIFIER_RE
            if not isinstance(value, str) or not validator.fullmatch(value):
                raise ValueError(f"{label} must be a valid identifier.")

        if not isinstance(parameters, dict):
            raise ValueError("parameters must be a JSON object.")

        try:
            copied_parameters = json.loads(canonical_json(parameters))
            encoded = canonical_json(copied_parameters).encode("utf-8")
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("parameters must contain finite, bounded JSON-compatible values.") from exc

        if len(encoded) > MAX_PARAMETERS_BYTES:
            raise ValueError(f"parameters exceed the {MAX_PARAMETERS_BYTES}-byte limit.")
        reject_raw_secrets(copied_parameters)

        return cls(
            agent_id=agent_id,
            action=action,
            resource=resource,
            parameters=copied_parameters,
            request_id=request_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json(self.to_dict()).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AgentPolicy:
    action_resources: dict[str, frozenset[str]]
    human_approval_actions: frozenset[str] = frozenset()


class PolicyEngine:
    """Deny-by-default policy evaluator. Policies are intentionally code-defined in v0.2."""

    def __init__(self, policies: dict[str, AgentPolicy] | None = None) -> None:
        self.hard_blocked_actions = frozenset({
            "disable_custos",
            "modify_custos_policy",
            "delete_audit_log",
        })
        self.policies = policies or {
            "research_agent": AgentPolicy(
                action_resources={
                    "read_database": frozenset({"research_db"}),
                    "send_email": frozenset({"company_email"}),
                },
                human_approval_actions=frozenset({"send_email"}),
            )
        }

    def evaluate(self, request: ActionRequest) -> tuple[Decision, str]:
        if request.action in self.hard_blocked_actions:
            return Decision.BLOCK, "Action is protected by a hard-deny rule."

        policy = self.policies.get(request.agent_id)
        if policy is None:
            return Decision.BLOCK, "No policy exists for this agent."

        allowed_resources = policy.action_resources.get(request.action)
        if allowed_resources is None:
            return Decision.BLOCK, "Action is not permitted for this agent."

        if request.resource not in allowed_resources:
            return Decision.BLOCK, "Resource is outside the action's permitted scope."

        if request.action in policy.human_approval_actions:
            return Decision.HUMAN_APPROVAL, "This action requires explicit human approval."

        return Decision.ALLOW, "Policy checks passed."


class ExecutionAdapter(Protocol):
    def execute(self, request: ActionRequest) -> dict[str, Any]:
        ...


@dataclass(frozen=True)
class DispatchPermit:
    """Short-lived, request-bound capability minted only by the local gateway."""

    request_digest: str
    mode: str
    approval_id: str | None
    issued_at: float
    expires_at: float
    nonce: str
    signature: str


class DispatchAuthority:
    """Issues and consumes one-time HMAC-authenticated dispatch capabilities."""

    def __init__(
        self,
        clock: Callable[[], float] = time.time,
        ttl_seconds: float = 15.0,
        signing_key: bytes | None = None,
    ) -> None:
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, (int, float))
            or not math.isfinite(ttl_seconds)
            or ttl_seconds <= 0
        ):
            raise ValueError("Dispatch permit TTL must be a finite positive number.")
        if signing_key is not None and (not isinstance(signing_key, bytes) or len(signing_key) < 32):
            raise ValueError("Dispatch signing key must be at least 32 bytes.")
        self._clock = clock
        self._ttl_seconds = float(ttl_seconds)
        self._signing_key = signing_key if signing_key is not None else secrets.token_bytes(32)
        self._used_nonces: dict[str, float] = {}
        self._max_active_nonces = 100_000
        self._lock = threading.Lock()

    @staticmethod
    def _claims(permit: DispatchPermit) -> dict[str, Any]:
        return {
            "request_digest": permit.request_digest,
            "mode": permit.mode,
            "approval_id": permit.approval_id,
            "issued_at": permit.issued_at,
            "expires_at": permit.expires_at,
            "nonce": permit.nonce,
        }

    def issue(
        self,
        request: ActionRequest,
        *,
        mode: str,
        approval_id: str | None = None,
    ) -> DispatchPermit:
        if mode not in {"ALLOW", "APPROVED"}:
            raise ValueError("Dispatch permit mode must be ALLOW or APPROVED.")
        if mode == "ALLOW" and approval_id is not None:
            raise ValueError("An ALLOW permit cannot carry a human approval ID.")
        if mode == "APPROVED" and (not isinstance(approval_id, str) or not approval_id):
            raise ValueError("An APPROVED permit must be bound to an approval ID.")

        issued_at = self._clock()
        unsigned = DispatchPermit(
            request_digest=request.digest,
            mode=mode,
            approval_id=approval_id,
            issued_at=issued_at,
            expires_at=issued_at + self._ttl_seconds,
            nonce=secrets.token_urlsafe(24),
            signature="",
        )
        signature = hmac.new(
            self._signing_key,
            canonical_json(self._claims(unsigned)).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return DispatchPermit(
            request_digest=unsigned.request_digest,
            mode=unsigned.mode,
            approval_id=unsigned.approval_id,
            issued_at=unsigned.issued_at,
            expires_at=unsigned.expires_at,
            nonce=unsigned.nonce,
            signature=signature,
        )

    def consume(self, request: ActionRequest, permit: DispatchPermit) -> None:
        if not isinstance(permit, DispatchPermit):
            raise DispatchAuthorizationError("A valid dispatch permit is required.")
        if not isinstance(permit.request_digest, str) or permit.request_digest != request.digest:
            raise DispatchAuthorizationError("Dispatch permit does not match this exact request.")
        if not isinstance(permit.mode, str) or permit.mode not in {"ALLOW", "APPROVED"}:
            raise DispatchAuthorizationError("Dispatch permit mode is invalid.")
        if permit.mode == "ALLOW" and permit.approval_id is not None:
            raise DispatchAuthorizationError("ALLOW permits cannot carry approval IDs.")
        if permit.mode == "APPROVED" and (
            not isinstance(permit.approval_id, str) or not permit.approval_id
        ):
            raise DispatchAuthorizationError("APPROVED permits must be bound to an approval ID.")
        if not isinstance(permit.nonce, str) or not permit.nonce or len(permit.nonce) > 128:
            raise DispatchAuthorizationError("Dispatch permit nonce is invalid.")
        if not isinstance(permit.signature, str) or not re.fullmatch(r"[0-9a-f]{64}", permit.signature):
            raise DispatchAuthorizationError("Dispatch permit signature is malformed.")
        for timestamp in (permit.issued_at, permit.expires_at):
            if (
                isinstance(timestamp, bool)
                or not isinstance(timestamp, (int, float))
                or not math.isfinite(timestamp)
            ):
                raise DispatchAuthorizationError("Dispatch permit timestamps are invalid.")

        try:
            expected = hmac.new(
                self._signing_key,
                canonical_json(self._claims(permit)).encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
        except (TypeError, ValueError, RecursionError) as exc:
            raise DispatchAuthorizationError("Dispatch permit claims are malformed.") from exc
        if not hmac.compare_digest(expected, permit.signature):
            raise DispatchAuthorizationError("Dispatch permit signature is invalid.")

        now = self._clock()
        lifetime = permit.expires_at - permit.issued_at
        if permit.issued_at > now or permit.expires_at <= now or lifetime <= 0 or lifetime > self._ttl_seconds:
            raise DispatchAuthorizationError("Dispatch permit is expired or outside its validity window.")

        # The replay claim is atomic within this process. A distributed deployment
        # must replace this in-memory set with a shared durable nonce store.
        with self._lock:
            expired_nonces = [
                nonce for nonce, expires_at in self._used_nonces.items()
                if expires_at <= now
            ]
            for nonce in expired_nonces:
                self._used_nonces.pop(nonce, None)
            if permit.nonce in self._used_nonces:
                raise DispatchAuthorizationError("Dispatch permit has already been consumed.")
            if len(self._used_nonces) >= self._max_active_nonces:
                raise DispatchAuthorizationError("Dispatch replay cache is at capacity; dispatch fails closed.")
            self._used_nonces[permit.nonce] = permit.expires_at


class GuardedExecutionAdapter:
    """The only adapter exposed to CustosGateway; it checks the actual dispatch boundary."""

    def __init__(
        self,
        delegate: ExecutionAdapter,
        policy_engine: PolicyEngine,
        dispatch_authority: DispatchAuthority,
        approval_claim_verifier: Callable[[str, ActionRequest], bool],
    ) -> None:
        self._delegate = delegate
        self._policy_engine = policy_engine
        self._dispatch_authority = dispatch_authority
        self._approval_claim_verifier = approval_claim_verifier

    def execute(self, request: ActionRequest, permit: DispatchPermit) -> dict[str, Any]:
        self._dispatch_authority.consume(request, permit)
        decision, _ = self._policy_engine.evaluate(request)
        if permit.mode == "ALLOW" and decision is not Decision.ALLOW:
            raise DispatchAuthorizationError("Current policy no longer permits this dispatch.")
        if permit.mode == "APPROVED":
            if decision is Decision.BLOCK:
                raise DispatchAuthorizationError("Current policy blocks this previously approved dispatch.")
            if not self._approval_claim_verifier(permit.approval_id or "", request):
                raise DispatchAuthorizationError("The approval is not in a valid, request-bound execution state.")
        return self._delegate.execute(request)


class RegisteredToolAdapter:
    """Dispatch only to an explicitly registered (action, resource) handler."""

    def __init__(
        self,
        handlers: dict[tuple[str, str], Callable[[ActionRequest], dict[str, Any]]],
    ) -> None:
        if not handlers:
            raise ValueError("At least one exact tool binding must be registered.")
        self._handlers: dict[tuple[str, str], Callable[[ActionRequest], dict[str, Any]]] = {}
        for binding, handler in handlers.items():
            if (
                not isinstance(binding, tuple)
                or len(binding) != 2
                or not all(isinstance(part, str) and IDENTIFIER_RE.fullmatch(part) for part in binding)
            ):
                raise ValueError("Tool bindings must be exact (action, resource) identifier pairs.")
            if not callable(handler):
                raise ValueError("Every registered tool binding must have a callable handler.")
            if binding in self._handlers:
                raise ValueError("Duplicate tool binding.")
            self._handlers[binding] = handler

    def execute(self, request: ActionRequest) -> dict[str, Any]:
        handler = self._handlers.get((request.action, request.resource))
        if handler is None:
            raise ValueError("No tool is registered for this exact action/resource pair.")
        result = handler(request)
        if not isinstance(result, dict):
            raise TypeError("Registered tool handlers must return a JSON object.")
        return result


class MockExecutionAdapter:
    """Safe demonstration adapter with an exact action/resource registry and no external effects."""

    def __init__(self) -> None:
        self.executed: list[dict[str, Any]] = []
        self._registry = RegisteredToolAdapter({
            ("read_database", "research_db"): self._simulate,
            ("send_email", "company_email"): self._simulate,
        })

    def _simulate(self, request: ActionRequest) -> dict[str, Any]:
        result = {
            "status": "simulated",
            "agent_id": request.agent_id,
            "action": request.action,
            "resource": request.resource,
            "request_id": request.request_id,
        }
        self.executed.append(result)
        return result

    def execute(self, request: ActionRequest) -> dict[str, Any]:
        return self._registry.execute(request)


class ApprovalStore:
    """SQLite-backed approval state with atomic, single-use execution claims."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY,
                    request_json TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    reviewer_id TEXT,
                    reviewed_at REAL,
                    result_json TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status, created_at)")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS request_receipts (
                    agent_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    response_json TEXT,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (agent_id, request_id)
                )
            """)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @staticmethod
    def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        result = dict(row)
        result["request"] = json.loads(result.pop("request_json"))
        if result.get("result_json"):
            result["result"] = json.loads(result.pop("result_json"))
        else:
            result.pop("result_json", None)
        return result

    def claim_request(self, request: ActionRequest, now: float) -> dict[str, Any] | None:
        """Claim an idempotency key or return the cached result for an exact retry."""
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM request_receipts WHERE agent_id=? AND request_id=?",
                (request.agent_id, request.request_id),
            ).fetchone()
            if row is not None:
                conn.rollback()
                if row["request_digest"] != request.digest:
                    raise ApprovalConflict("request_id was already used with a different payload.")
                if row["status"] == "completed" and row["response_json"]:
                    cached = json.loads(row["response_json"])
                    cached["replayed"] = True
                    return cached
                raise ApprovalConflict("This request_id is already processing or has failed.")
            conn.execute(
                """INSERT INTO request_receipts
                   (agent_id, request_id, request_digest, status, created_at)
                   VALUES (?, ?, ?, 'processing', ?)""",
                (request.agent_id, request.request_id, request.digest, now),
            )
            conn.commit()
        return None

    def complete_request(self, request: ActionRequest, response: dict[str, Any]) -> None:
        with self._connect() as conn:
            cursor = conn.execute(
                """UPDATE request_receipts SET status='completed', response_json=?
                   WHERE agent_id=? AND request_id=? AND status='processing'""",
                (canonical_json(response), request.agent_id, request.request_id),
            )
            if cursor.rowcount != 1:
                raise ApprovalConflict("Request receipt could not be finalized.")

    def fail_request(self, request: ActionRequest) -> None:
        with self._connect() as conn:
            conn.execute(
                """UPDATE request_receipts SET status='failed'
                   WHERE agent_id=? AND request_id=? AND status='processing'""",
                (request.agent_id, request.request_id),
            )

    def update_request_result(self, request: ActionRequest, response: dict[str, Any]) -> None:
        with self._connect() as conn:
            cursor = conn.execute(
                """UPDATE request_receipts SET response_json=?
                   WHERE agent_id=? AND request_id=? AND status='completed'""",
                (canonical_json(response), request.agent_id, request.request_id),
            )
            if cursor.rowcount != 1:
                raise ApprovalConflict("Completed request receipt was not found.")

    def create(self, request: ActionRequest, ttl_seconds: int, now: float) -> str:
        approval_id = str(uuid.uuid4())
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO approvals
                   (approval_id, request_json, request_digest, status, created_at, expires_at)
                   VALUES (?, ?, ?, 'pending', ?, ?)""",
                (approval_id, canonical_json(request.to_dict()), request.digest, now, now + ttl_seconds),
            )
        return approval_id

    def get(self, approval_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)).fetchone()
        return self._row_to_dict(row)

    def list_pending(self, now: float) -> list[dict[str, Any]]:
        with self._connect() as conn:
            conn.execute(
                "UPDATE approvals SET status='expired' WHERE status='pending' AND expires_at <= ?",
                (now,),
            )
            rows = conn.execute(
                "SELECT * FROM approvals WHERE status='pending' ORDER BY created_at ASC"
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def review(self, approval_id: str, reviewer_id: str, approve: bool, now: float) -> dict[str, Any]:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)).fetchone()
            if row is None:
                conn.rollback()
                raise ApprovalNotFound("Approval request was not found.")
            if row["status"] != "pending":
                conn.rollback()
                raise ApprovalConflict(f"Approval is already {row['status']}.")
            if row["expires_at"] <= now:
                conn.execute(
                    "UPDATE approvals SET status='expired' WHERE approval_id=? AND status='pending'",
                    (approval_id,),
                )
                conn.commit()
                raise ApprovalExpired("Approval request has expired.")
            new_status = "approved" if approve else "denied"
            conn.execute(
                """UPDATE approvals SET status=?, reviewer_id=?, reviewed_at=?
                   WHERE approval_id=? AND status='pending'""",
                (new_status, reviewer_id, now, approval_id),
            )
            updated = conn.execute("SELECT * FROM approvals WHERE approval_id=?", (approval_id,)).fetchone()
            conn.commit()
        return self._row_to_dict(updated)  # type: ignore[return-value]

    def claim_for_execution(self, approval_id: str, agent_id: str, now: float) -> ActionRequest:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM approvals WHERE approval_id=?", (approval_id,)).fetchone()
            if row is None:
                conn.rollback()
                raise ApprovalNotFound("Approval request was not found.")
            request_data = json.loads(row["request_json"])
            if request_data["agent_id"] != agent_id:
                conn.rollback()
                raise ApprovalForbidden("Only the requesting agent may execute this approval.")
            request = ActionRequest.from_payload(
                request_data["agent_id"],
                {
                    "action": request_data["action"],
                    "resource": request_data["resource"],
                    "parameters": request_data["parameters"],
                    "request_id": request_data["request_id"],
                },
            )
            if request.digest != row["request_digest"]:
                conn.rollback()
                raise ApprovalConflict("Stored approval payload failed its integrity check.")
            if row["expires_at"] <= now:
                conn.execute(
                    "UPDATE approvals SET status='expired' WHERE approval_id=? AND status IN ('pending','approved')",
                    (approval_id,),
                )
                conn.commit()
                raise ApprovalExpired("Approval request has expired.")
            if row["status"] != "approved":
                conn.rollback()
                raise ApprovalConflict(f"Approval is not executable; current state is {row['status']}.")
            conn.execute(
                "UPDATE approvals SET status='executing' WHERE approval_id=? AND status='approved'",
                (approval_id,),
            )
            conn.commit()
        return request


    def verify_execution_claim(self, approval_id: str, request: ActionRequest) -> bool:
        """Verify that this exact request owns the atomic executing claim."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT request_digest, request_json, status FROM approvals WHERE approval_id=?",
                (approval_id,),
            ).fetchone()
        if row is None or row["status"] != "executing":
            return False
        if row["request_digest"] != request.digest:
            return False
        try:
            stored = json.loads(row["request_json"])
        except (TypeError, ValueError):
            return False
        return (
            stored.get("agent_id") == request.agent_id
            and stored.get("action") == request.action
            and stored.get("resource") == request.resource
            and stored.get("request_id") == request.request_id
        )


    def finish_execution(self, approval_id: str, status: str, result: dict[str, Any] | None = None) -> None:
        if status not in {"executed", "failed", "blocked"}:
            raise ValueError("Invalid terminal approval status.")
        result_json = canonical_json(result) if result is not None else None
        with self._connect() as conn:
            cursor = conn.execute(
                """UPDATE approvals SET status=?, result_json=?
                   WHERE approval_id=? AND status='executing'""",
                (status, result_json, approval_id),
            )
            if cursor.rowcount != 1:
                raise ApprovalConflict("Approval execution state changed unexpectedly.")


class CustosGateway:
    def __init__(
        self,
        store: ApprovalStore,
        audit_log: AuditLog,
        adapter: ExecutionAdapter | None = None,
        policy_engine: PolicyEngine | None = None,
        approval_ttl_seconds: int = 300,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if approval_ttl_seconds < 1:
            raise ValueError("approval_ttl_seconds must be positive.")
        self.store = store
        self.audit_log = audit_log
        self.policy_engine = policy_engine or PolicyEngine()
        self.clock = clock
        self.approval_ttl_seconds = approval_ttl_seconds
        self._dispatch_authority = DispatchAuthority(clock=clock, ttl_seconds=15.0)
        self.adapter = GuardedExecutionAdapter(
            delegate=adapter or MockExecutionAdapter(),
            policy_engine=self.policy_engine,
            dispatch_authority=self._dispatch_authority,
            approval_claim_verifier=self.store.verify_execution_claim,
        )

    def submit(self, request: ActionRequest) -> dict[str, Any]:
        now = self.clock()
        cached = self.store.claim_request(request, now)
        if cached is not None:
            self.audit_log.record(
                "REQUEST_REPLAYED",
                {"request_id": request.request_id, "agent_id": request.agent_id},
            )
            return cached

        try:
            self.audit_log.record("REQUEST_RECEIVED", request.to_dict())
            decision, reason = self.policy_engine.evaluate(request)
            self.audit_log.record(
                "POLICY_DECISION",
                {"request_id": request.request_id, "decision": decision.value, "reason": reason},
            )

            if decision is Decision.BLOCK:
                response = {
                    "decision": Decision.BLOCK.value,
                    "reason": reason,
                    "executed": False,
                    "request_id": request.request_id,
                }
            elif decision is Decision.HUMAN_APPROVAL:
                approval_id = self.store.create(request, self.approval_ttl_seconds, now)
                self.audit_log.record(
                    "APPROVAL_PENDING",
                    {"approval_id": approval_id, "request_id": request.request_id, "expires_at": now + self.approval_ttl_seconds},
                )
                response = {
                    "decision": Decision.HUMAN_APPROVAL.value,
                    "reason": reason,
                    "executed": False,
                    "approval_id": approval_id,
                    "expires_at": now + self.approval_ttl_seconds,
                    "request_id": request.request_id,
                }
            else:
                response = self._execute_allowed(request)

            self.store.complete_request(request, response)
            return response
        except Exception as exc:
            self.store.fail_request(request)
            self.audit_log.record(
                "REQUEST_PROCESSING_FAILED",
                {"request_id": request.request_id, "error": type(exc).__name__},
            )
            raise

    def _execute_allowed(self, request: ActionRequest) -> dict[str, Any]:
        decision, reason = self.policy_engine.evaluate(request)
        if decision is not Decision.ALLOW:
            self.audit_log.record(
                "DISPATCH_BLOCKED",
                {"request_id": request.request_id, "decision": decision.value, "reason": reason},
            )
            return {
                "decision": Decision.BLOCK.value,
                "reason": "Dispatch-time policy check did not return ALLOW.",
                "executed": False,
                "request_id": request.request_id,
            }

        permit = self._dispatch_authority.issue(request, mode="ALLOW")
        try:
            result = self.adapter.execute(request, permit)
        except DispatchAuthorizationError:
            self.audit_log.record(
                "DISPATCH_BLOCKED_AT_ADAPTER_BOUNDARY",
                {"request_id": request.request_id, "reason": "Dispatch permit or current authorization was rejected."},
            )
            return {
                "decision": Decision.BLOCK.value,
                "reason": "Adapter-boundary authorization rejected dispatch.",
                "executed": False,
                "request_id": request.request_id,
            }
        self.audit_log.record("EXECUTION_SIMULATED", {"request_id": request.request_id, "result": result})
        return {
            "decision": Decision.ALLOW.value,
            "reason": reason,
            "executed": True,
            "result": result,
            "request_id": request.request_id,
        }

    def review_approval(self, approval_id: str, reviewer_id: str, approve: bool) -> dict[str, Any]:
        original = self.store.get(approval_id)
        if original is None:
            raise ApprovalNotFound("Approval request was not found.")
        reviewed = self.store.review(approval_id, reviewer_id, approve, self.clock())
        request_data = original["request"]
        request = ActionRequest.from_payload(
            request_data["agent_id"],
            {
                "action": request_data["action"],
                "resource": request_data["resource"],
                "parameters": request_data["parameters"],
                "request_id": request_data["request_id"],
            },
        )
        self.store.update_request_result(
            request,
            {
                "decision": Decision.HUMAN_APPROVAL.value,
                "reason": "Human reviewer approved the request." if approve else "Human reviewer denied the request.",
                "executed": False,
                "approval_id": approval_id,
                "status": reviewed["status"],
                "reviewer_id": reviewer_id,
            },
        )
        self.audit_log.record(
            "APPROVAL_REVIEWED",
            {
                "approval_id": approval_id,
                "reviewer_id": reviewer_id,
                "decision": "approved" if approve else "denied",
            },
        )
        return {
            "approval_id": approval_id,
            "status": reviewed["status"],
            "reviewer_id": reviewer_id,
            "reviewed_at": reviewed["reviewed_at"],
        }

    def pending_approvals(self) -> list[dict[str, Any]]:
        rows = self.store.list_pending(self.clock())
        return [
            {
                "approval_id": row["approval_id"],
                "request": row["request"],
                "created_at": row["created_at"],
                "expires_at": row["expires_at"],
                "status": row["status"],
            }
            for row in rows
        ]

    def execute_approved(self, approval_id: str, agent_id: str) -> dict[str, Any]:
        request = self.store.claim_for_execution(approval_id, agent_id, self.clock())
        try:
            decision, reason = self.policy_engine.evaluate(request)
            if decision is Decision.BLOCK:
                self.store.finish_execution(approval_id, "blocked", {"reason": reason})
                self.audit_log.record(
                    "APPROVED_ACTION_BLOCKED_AT_DISPATCH",
                    {"approval_id": approval_id, "request_id": request.request_id, "reason": reason},
                )
                response = {
                    "decision": Decision.BLOCK.value,
                    "reason": "Current policy blocks this previously approved action.",
                    "executed": False,
                    "approval_id": approval_id,
                }
                self.store.update_request_result(request, response)
                return response

            permit = self._dispatch_authority.issue(
                request,
                mode="APPROVED",
                approval_id=approval_id,
            )
            result = self.adapter.execute(request, permit)
            self.store.finish_execution(approval_id, "executed", result)
            self.audit_log.record(
                "APPROVED_ACTION_EXECUTED",
                {"approval_id": approval_id, "request_id": request.request_id, "result": result},
            )
            response = {
                "decision": Decision.ALLOW.value,
                "reason": "A valid human approval was verified; simulated execution completed.",
                "executed": True,
                "approval_id": approval_id,
                "result": result,
            }
            self.store.update_request_result(request, response)
            return response
        except Exception as exc:
            try:
                self.store.finish_execution(approval_id, "failed", {"error": type(exc).__name__})
            except ApprovalError:
                pass
            self.audit_log.record(
                "APPROVED_ACTION_FAILED",
                {"approval_id": approval_id, "request_id": request.request_id, "error": type(exc).__name__},
            )
            raise
