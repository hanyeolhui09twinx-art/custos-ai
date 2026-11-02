from __future__ import annotations

import hmac
import ipaddress
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

from audit_log import AuditLog
from keyring_audit import KEY_LIFECYCLE_EVENTS, read_keyring_observability
from custos_gateway import (
    ActionRequest,
    ApprovalConflict,
    ApprovalError,
    ApprovalExpired,
    ApprovalForbidden,
    ApprovalNotFound,
    ApprovalStore,
    CustosGateway,
    IDENTIFIER_RE,
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
    provider_db_path: str | Path | None = None,
    provider_audit_path: str | Path | None = None,
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

    resolved_provider_db = Path(provider_db_path) if provider_db_path is not None else Path(
        os.environ.get("CUSTOS_PROVIDER_DB", str(Path(db_path).parent / "provider-replay.sqlite3"))
    )
    resolved_provider_audit = Path(provider_audit_path) if provider_audit_path is not None else Path(
        os.environ.get("CUSTOS_PROVIDER_AUDIT_LOG", str(resolved_provider_db.with_suffix(".audit.jsonl")))
    )

    if gateway is None:
        adapter = None
        dispatch_signing_key = None
        dispatch_signing_keys = None
        active_dispatch_key_id = os.environ.get("CUSTOS_ACTIVE_DISPATCH_KEY_ID", "default")
        provider_url = os.environ.get("CUSTOS_TOOL_PROVIDER_URL", "")
        if provider_url:
            raw_key_ring = os.environ.get("CUSTOS_DISPATCH_KEYS", "")
            if raw_key_ring:
                try:
                    encoded_keys = json.loads(raw_key_ring)
                except json.JSONDecodeError as exc:
                    raise ValueError("CUSTOS_DISPATCH_KEYS must be a JSON object.") from exc
                if not isinstance(encoded_keys, dict) or not encoded_keys:
                    raise ValueError("CUSTOS_DISPATCH_KEYS must be a non-empty JSON object.")
                dispatch_signing_keys = {}
                for key_id, key_hex in encoded_keys.items():
                    if not isinstance(key_id, str) or not IDENTIFIER_RE.fullmatch(key_id) or not isinstance(key_hex, str):
                        raise ValueError("CUSTOS_DISPATCH_KEYS contains an invalid entry.")
                    try:
                        key_value = bytes.fromhex(key_hex)
                    except ValueError as exc:
                        raise ValueError(f"Dispatch key {key_id!r} must be hexadecimal.") from exc
                    if len(key_value) < 32:
                        raise ValueError(f"Dispatch key {key_id!r} must encode at least 32 bytes.")
                    dispatch_signing_keys[key_id] = key_value
                if active_dispatch_key_id not in dispatch_signing_keys:
                    raise ValueError("CUSTOS_ACTIVE_DISPATCH_KEY_ID must exist in CUSTOS_DISPATCH_KEYS.")
            else:
                key_hex = os.environ.get("CUSTOS_DISPATCH_SIGNING_KEY", "")
                try:
                    dispatch_signing_key = bytes.fromhex(key_hex)
                except ValueError as exc:
                    raise ValueError("CUSTOS_DISPATCH_SIGNING_KEY must be hexadecimal.") from exc
                if len(dispatch_signing_key) < 32:
                    raise ValueError("CUSTOS_DISPATCH_SIGNING_KEY must encode at least 32 bytes.")
            from custos_provider import HttpToolProviderAdapter
            adapter = HttpToolProviderAdapter(
                provider_url,
                receipt_signing_key=dispatch_signing_key,
                receipt_signing_keys=dispatch_signing_keys,
                receipt_signing_key_id=active_dispatch_key_id,
            )
        gateway = CustosGateway(
            store=ApprovalStore(db_path),
            audit_log=AuditLog(str(audit_path)),
            adapter=adapter,
            dispatch_signing_key=dispatch_signing_key,
            dispatch_signing_keys=dispatch_signing_keys,
            active_dispatch_key_id=active_dispatch_key_id,
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
            origin = self.headers.get("Origin")
            if origin == "https://hanyeolhui09twinx-art.github.io":
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self) -> None:
            origin = self.headers.get("Origin")
            if origin != "https://hanyeolhui09twinx-art.github.io":
                self._send(403, {"error": "Browser origin is not allowed."})
                return
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
            self.send_header("Access-Control-Max-Age", "300")
            self.send_header("Content-Length", "0")
            self.end_headers()

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
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
                raise ValueError("Request body must be valid, bounded UTF-8 JSON.") from exc
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
            if path == "/v1/security/overview":
                try:
                    self._require_reviewer()
                except AuthenticationError as exc:
                    self._send(401, {"error": str(exc)})
                    return
                try:
                    query = parse_qs(urlsplit(self.path).query, keep_blank_values=True, strict_parsing=True)
                    if set(query) - {"component", "event", "limit"} or any(len(values) != 1 for values in query.values()):
                        raise ValueError("Only one component, event, and limit filter may be supplied.")
                    component_filter = query.get("component", ["all"])[0]
                    if component_filter not in {"all", "gateway", "provider"}:
                        raise ValueError("component must be all, gateway, or provider.")
                    event_filter = query.get("event", [None])[0]
                    if event_filter == "":
                        event_filter = None
                    if event_filter is not None and event_filter not in KEY_LIFECYCLE_EVENTS:
                        raise ValueError("Unsupported key lifecycle event filter.")
                    try:
                        limit = int(query.get("limit", ["100"])[0])
                    except ValueError as exc:
                        raise ValueError("limit must be an integer between 1 and 200.") from exc
                    if not 1 <= limit <= 200:
                        raise ValueError("limit must be an integer between 1 and 200.")

                    selected = [component_filter] if component_filter != "all" else ["gateway", "provider"]
                    sources = {
                        "gateway": (gateway.store.db_path, gateway.audit_log.file_path),
                        "provider": (resolved_provider_db, resolved_provider_audit),
                    }
                    components = {
                        name: read_keyring_observability(
                            *sources[name], name, event_filter=event_filter, limit=limit
                        )
                        for name in selected
                    }
                    events = [event for state in components.values() for event in state["events"]]
                    events.sort(key=lambda item: item.get("timestamp", ""), reverse=True)
                    payload = {
                        "generated_at": datetime.now(timezone.utc).isoformat(),
                        "filters": {"component": component_filter, "event": event_filter, "limit": limit},
                        "components": components,
                        "events": events[:limit],
                    }
                    self._send(200, payload)
                except ValueError as exc:
                    self._send(400, {"error": str(exc)})
                except Exception:
                    self._send(500, {"error": "Security observability could not be read."})
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
        provider_db_path=os.environ.get("CUSTOS_PROVIDER_DB", str(data_dir / "provider-replay.sqlite3")),
        provider_audit_path=os.environ.get("CUSTOS_PROVIDER_AUDIT_LOG", str(data_dir / "provider-audit.jsonl")),
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
