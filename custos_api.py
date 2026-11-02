from __future__ import annotations

import hmac
import ipaddress
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from audit_log import AuditLog
from custos_gateway import (
    ActionRequest,
    ApprovalConflict,
    ApprovalError,
    ApprovalExpired,
    ApprovalForbidden,
    ApprovalNotFound,
    ApprovalStore,
    CustosGateway,
)

MAX_BODY_BYTES = 65_536


class AuthenticationError(Exception):
    pass


class CustosHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _validate_loopback_host(host: str) -> None:
    if host == "localhost":
        return
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("Custos API only binds to localhost/loopback in this prototype.") from exc
    if not address.is_loopback:
        raise ValueError("Remote binding is disabled. Use 127.0.0.1 or ::1.")


def create_server(
    agent_tokens: dict[str, str],
    reviewer_token: str,
    db_path: str | Path = ".custos-data/approvals.sqlite3",
    audit_path: str | Path = ".custos-data/audit.jsonl",
    host: str = "127.0.0.1",
    port: int = 8765,
    gateway: CustosGateway | None = None,
) -> CustosHTTPServer:
    """Create a loopback-only HTTP API. HTTPS/reverse proxy is intentionally not configured."""
    _validate_loopback_host(host)
    if not agent_tokens:
        raise ValueError("At least one agent token must be configured.")
    for agent_id, token in agent_tokens.items():
        if not isinstance(agent_id, str) or not agent_id:
            raise ValueError("Agent token map contains an invalid agent id.")
        if not isinstance(token, str) or len(token) < 32:
            raise ValueError("Each agent token must contain at least 32 characters.")
    if not isinstance(reviewer_token, str) or len(reviewer_token) < 32:
        raise ValueError("Reviewer token must contain at least 32 characters.")

    gateway = gateway or CustosGateway(
        store=ApprovalStore(db_path),
        audit_log=AuditLog(str(audit_path)),
    )

    class Handler(BaseHTTPRequestHandler):
        server_version = "CustosPrototype/0.2"
        sys_version = ""

        def log_message(self, format: str, *args: Any) -> None:
            # Avoid writing bearer credentials or request bodies to the standard log.
            super().log_message(format, *args)

        def _send(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> dict[str, Any]:
            raw_length = self.headers.get("Content-Length")
            if raw_length is None:
                raise ValueError("Content-Length header is required.")
            try:
                length = int(raw_length)
            except ValueError as exc:
                raise ValueError("Content-Length must be an integer.") from exc
            if length < 1:
                raise ValueError("Request body is required.")
            if length > MAX_BODY_BYTES:
                raise OverflowError("Request body exceeds the 64 KiB limit.")
            raw = self.rfile.read(length)
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("Request body must be valid UTF-8 JSON.") from exc
            if not isinstance(value, dict):
                raise ValueError("Request body must be a JSON object.")
            return value

        def _bearer(self) -> str:
            header = self.headers.get("Authorization", "")
            scheme, separator, value = header.partition(" ")
            if not separator or scheme.lower() != "bearer" or not value:
                raise AuthenticationError("A valid Bearer token is required.")
            return value.strip()

        def _agent_identity(self) -> str:
            supplied = self._bearer()
            for agent_id, expected in agent_tokens.items():
                if hmac.compare_digest(supplied, expected):
                    return agent_id
            raise AuthenticationError("Agent token is invalid.")

        def _require_reviewer(self) -> None:
            supplied = self._bearer()
            if not hmac.compare_digest(supplied, reviewer_token):
                raise AuthenticationError("Reviewer token is invalid.")

        def _approval_error(self, exc: ApprovalError) -> None:
            if isinstance(exc, ApprovalNotFound):
                self._send(404, {"error": str(exc)})
            elif isinstance(exc, ApprovalForbidden):
                self._send(403, {"error": str(exc)})
            elif isinstance(exc, ApprovalExpired):
                self._send(410, {"error": str(exc)})
            else:
                self._send(409, {"error": str(exc)})

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            if path == "/health":
                self._send(200, {"status": "ok", "service": "custos-api", "mode": "local-simulation"})
                return
            if path == "/v1/approvals":
                try:
                    self._require_reviewer()
                    self._send(200, {"approvals": gateway.pending_approvals()})
                except AuthenticationError as exc:
                    self._send(401, {"error": str(exc)})
                return
            self._send(404, {"error": "Route not found."})

        def do_POST(self) -> None:
            path = urlsplit(self.path).path
            try:
                body = self._body()
            except OverflowError as exc:
                self._send(413, {"error": str(exc)})
                return
            except ValueError as exc:
                self._send(400, {"error": str(exc)})
                return

            if path == "/v1/requests":
                try:
                    agent_id = self._agent_identity()
                    request = ActionRequest.from_payload(agent_id, body)
                    self._send(200, gateway.submit(request))
                except AuthenticationError as exc:
                    self._send(401, {"error": str(exc)})
                except ValueError as exc:
                    self._send(400, {"error": str(exc)})
                except ApprovalError as exc:
                    self._approval_error(exc)
                except Exception:
                    self._send(500, {"error": "Internal gateway error."})
                return

            parts = path.strip("/").split("/")
            if len(parts) == 4 and parts[0:2] == ["v1", "approvals"]:
                approval_id, operation = parts[2], parts[3]
                if operation == "review":
                    try:
                        self._require_reviewer()
                        decision = body.get("decision")
                        if decision not in {"approve", "deny"}:
                            raise ValueError("decision must be 'approve' or 'deny'.")
                        self._send(
                            200,
                            gateway.review_approval(
                                approval_id,
                                reviewer_id="configured_reviewer",
                                approve=decision == "approve",
                            ),
                        )
                    except AuthenticationError as exc:
                        self._send(401, {"error": str(exc)})
                    except ValueError as exc:
                        self._send(400, {"error": str(exc)})
                    except ApprovalError as exc:
                        self._approval_error(exc)
                    except Exception:
                        self._send(500, {"error": "Internal approval error."})
                    return

                if operation == "execute":
                    try:
                        agent_id = self._agent_identity()
                        self._send(200, gateway.execute_approved(approval_id, agent_id))
                    except AuthenticationError as exc:
                        self._send(401, {"error": str(exc)})
                    except ApprovalError as exc:
                        self._approval_error(exc)
                    except Exception:
                        self._send(500, {"error": "Internal execution error."})
                    return

            self._send(404, {"error": "Route not found."})

    return CustosHTTPServer((host, port), Handler)


def main() -> None:
    raw_tokens = os.environ.get("CUSTOS_AGENT_TOKENS", "")
    reviewer_token = os.environ.get("CUSTOS_REVIEWER_TOKEN", "")
    if not raw_tokens or not reviewer_token:
        raise SystemExit(
            "Set CUSTOS_AGENT_TOKENS to a JSON object and CUSTOS_REVIEWER_TOKEN "
            "to random tokens of at least 32 characters. Do not commit tokens."
        )
    try:
        agent_tokens = json.loads(raw_tokens)
    except json.JSONDecodeError as exc:
        raise SystemExit("CUSTOS_AGENT_TOKENS must be valid JSON.") from exc
    if not isinstance(agent_tokens, dict):
        raise SystemExit("CUSTOS_AGENT_TOKENS must be a JSON object.")

    data_dir = Path(os.environ.get("CUSTOS_DATA_DIR", ".custos-data"))
    server = create_server(
        agent_tokens=agent_tokens,
        reviewer_token=reviewer_token,
        db_path=data_dir / "approvals.sqlite3",
        audit_path=data_dir / "audit.jsonl",
        host=os.environ.get("CUSTOS_HOST", "127.0.0.1"),
        port=int(os.environ.get("CUSTOS_PORT", "8765")),
    )
    print(f"Custos local API listening on http://{server.server_address[0]}:{server.server_address[1]}")
    print("Mode: local simulation only. No external tools are connected.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Custos API.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
