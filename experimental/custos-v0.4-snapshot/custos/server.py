"""HTTP front door: puts the agent in a DIFFERENT PROCESS from the gateway.

This is what turns the threat model from "the agent calls our Python function" into "the agent can
only send bytes to a socket". Everything the earlier red-team rounds assumed (the agent has only
`submit`) is now structurally true instead of a convention.

  POST /v1/submit      signed request (JSON)  ->  minimal decision JSON (never signals / rule details)
  GET  /v1/challenge   (closed-access mode)   ->  one-time nonce
  POST /v1/handshake   (closed-access mode)   ->  session id, or 403 with no detail

Hardening: strict JSON (duplicate keys, NaN rejected), mandatory Content-Length, hard body limit,
no chunked bodies, socket timeouts (slowloris), a cap on concurrent in-flight requests, no server
banner, no-store caching, and any internal error answers with a generic denial (fail-closed).
Plain HTTP on localhost for the prototype: terminate mTLS in front of it for real deployments.
"""
from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import time

from .access import AccessError, ClosedAccessGate, OrgCertificate
from .control_plane import ControlError, ControlPlane
from .crypto import verify
from .audit import _loads
from .gateway import Gateway
from .models import ActionRequest, RequestError

log = logging.getLogger("custos.server")
MAX_BODY = 64 * 1024 + 4096
DENIED = {"status": "DENIED", "executed": False}


class _Handler(BaseHTTPRequestHandler):
    server_version = "custos"
    sys_version = ""
    protocol_version = "HTTP/1.0"  # one request per connection: simpler, no keep-alive abuse

    def version_string(self) -> str:
        return "custos"  # no Python / library version in the banner

    def setup(self) -> None:
        self.timeout = self.server.request_timeout  # type: ignore[attr-defined]
        super().setup()

    def log_message(self, *args: Any) -> None:  # no access log with request data
        pass

    def _send(self, code: int, obj: Any) -> None:
        body = json.dumps(obj, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict | None:
        if self.headers.get("Transfer-Encoding"):
            self._send(400, {"error": "chunked bodies are not accepted"})
            return None
        lengths = self.headers.get_all("Content-Length") or []
        if len(lengths) > 1:  # ambiguous framing is how request smuggling starts: refuse outright
            self._send(400, {"error": "multiple Content-Length headers"})
            return None
        cl = lengths[0] if lengths else None
        if cl is None:
            self._send(411, {"error": "Content-Length required"})
            return None
        if not cl.isdigit():
            self._send(400, {"error": "bad Content-Length"})
            return None
        if int(cl) > MAX_BODY:
            self._send(413, {"error": "payload too large"})
            return None
        raw = self.rfile.read(int(cl))
        if len(raw) != int(cl):
            self._send(400, {"error": "truncated body"})
            return None
        try:
            data = _loads(raw)
        except (ValueError, UnicodeDecodeError, RecursionError):  # nesting bombs are malformed input, not errors
            self._send(400, {"error": "invalid JSON"})
            return None
        if not isinstance(data, dict):
            self._send(400, {"error": "JSON object required"})
            return None
        return data

    def do_GET(self) -> None:
        app = self.server  # type: ignore[assignment]
        if self.path == "/v1/challenge" and app.gate is not None:  # type: ignore[attr-defined]
            try:
                self._send(200, {"nonce": app.gate.issue_challenge(self.client_address[0]).hex()})  # type: ignore[attr-defined]
            except AccessError:
                self._send(503, {"error": "busy"})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        app = self.server
        if self.path not in ("/v1/submit", "/v1/handshake"):
            self._send(404, {"error": "not found"})
            return
        if not app.slots.acquire(blocking=False):  # type: ignore[attr-defined]
            self._send(503, {"error": "busy"})
            return
        try:
            data = self._read_json()
            if data is None:
                return
            if self.path == "/v1/handshake":
                self._handshake(data)
            else:
                self._submit(data)
        except Exception:
            log.exception("unexpected server error")
            self._send(500, DENIED)  # fail-closed
        finally:
            app.slots.release()  # type: ignore[attr-defined]

    def _handshake(self, data: dict) -> None:
        gate: ClosedAccessGate | None = self.server.gate  # type: ignore[attr-defined]
        if gate is None:
            self._send(404, {"error": "not found"})
            return
        try:
            cert = OrgCertificate.from_dict(data["cert"])
            sid = gate.handshake(cert, bytes.fromhex(data["nonce"]), str(data["signature"]))
        except (KeyError, TypeError, ValueError, AccessError):
            sid = None
        self._send(200, {"session": sid}) if sid else self._send(403, DENIED)

    def _submit(self, data: dict) -> None:
        gate: ClosedAccessGate | None = self.server.gate  # type: ignore[attr-defined]
        gateway: Gateway = self.server.gateway  # type: ignore[attr-defined]
        if gate is None:
            self._send(200, gateway.submit_raw(data).public())
            return
        try:
            request = ActionRequest.from_mapping(data)
        except (RequestError, TypeError, ValueError):
            self._send(200, DENIED)
            return
        self._send(200, gate.submit(self.headers.get("X-Custos-Session", ""), request))


class _CappedServer(ThreadingHTTPServer):
    """One thread per connection is only safe with a bound on connections (total AND per address),
    otherwise idle sockets exhaust threads long before any request is parsed."""

    daemon_threads = True
    request_queue_size = 64
    max_connections = 128
    max_per_ip = 32

    def _init_caps(self, max_connections: int, max_per_ip: int) -> None:
        self.max_connections, self.max_per_ip = max_connections, max_per_ip
        self._conn_lock = threading.Lock()
        self._conns_total, self._conns_by_ip = 0, {}

    def process_request(self, request: Any, client_address: Any) -> None:
        ip = client_address[0]
        with self._conn_lock:
            full = (self._conns_total >= self.max_connections or self._conns_by_ip.get(ip, 0) >= self.max_per_ip)
            if not full:
                self._conns_total += 1
                self._conns_by_ip[ip] = self._conns_by_ip.get(ip, 0) + 1
        if full:
            self.shutdown_request(request)  # shed load immediately: no thread is created
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._conn_lock:
                ip = client_address[0]
                self._conns_total -= 1
                self._conns_by_ip[ip] = self._conns_by_ip.get(ip, 1) - 1
                if self._conns_by_ip[ip] <= 0:
                    self._conns_by_ip.pop(ip, None)


class CustosServer(_CappedServer):
    def __init__(self, addr: tuple[str, int], gateway: Gateway, gate: ClosedAccessGate | None,
                 max_inflight: int, request_timeout: float, max_connections: int = 128,
                 max_per_ip: int = 32) -> None:
        super().__init__(addr, _Handler)
        self._init_caps(max_connections, max_per_ip)
        self.gateway, self.gate = gateway, gate
        self.slots = threading.BoundedSemaphore(max_inflight)
        self.request_timeout = request_timeout


def start_server(gateway: Gateway, gate: ClosedAccessGate | None = None, *, host: str = "127.0.0.1",
                 port: int = 0, max_inflight: int = 32, request_timeout: float = 10.0,
                 max_connections: int = 128, max_per_ip: int = 32) -> tuple[CustosServer, threading.Thread]:
    server = CustosServer((host, port), gateway, gate, max_inflight, request_timeout, max_connections, max_per_ip)
    thread = threading.Thread(target=server.serve_forever, daemon=True, name="custos-http")
    thread.start()
    return server, thread


# --------------------------------------------------------------------------------------------
# Admin listener: a SEPARATE port for human approvers. Agents are never given this address, and
# every call is authenticated by the approver's own signature (not by network position).
# --------------------------------------------------------------------------------------------
def admin_payload(audience: str, op: str, ts: float) -> bytes:
    return f"custos-admin-v1\n{audience}\n{op}\n{ts!r}".encode()


class _AdminHandler(_Handler):
    def do_GET(self) -> None:
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        app = self.server
        if self.path not in ("/admin/pending", "/admin/approve", "/admin/reject"):
            self._send(404, {"error": "not found"})
            return
        if not app.slots.acquire(blocking=False):  # type: ignore[attr-defined]
            self._send(503, {"error": "busy"})
            return
        try:
            data = self._read_json()
            if data is None:
                return
            gateway: Gateway = app.gateway  # type: ignore[attr-defined]
            control: ControlPlane = app.control  # type: ignore[attr-defined]
            approver, rid = data.get("approver_id"), data.get("request_id")
            if not isinstance(approver, str):
                self._send(400, {"error": "approver_id required"})
                return
            if self.path == "/admin/pending":
                ts, key = data.get("ts"), control.approver_key(approver)
                ok = (key is not None and isinstance(ts, (int, float)) and abs(time.time() - ts) <= 60
                      and verify(key, str(data.get("signature")), admin_payload(app.audience, "pending", ts)))  # type: ignore[attr-defined]
                # a captured authenticated call must not be re-playable to read parked parameters
                if not ok or not app.replay.first_use(str(data.get("signature"))):  # type: ignore[attr-defined]
                    self._send(403, {"error": "refused"})
                    return
                self._send(200, {"pending": gateway.list_pending()})
                return
            try:
                if self.path == "/admin/reject":
                    control.reject(str(rid), approver, str(data.get("signature")))
                    gateway.drop_pending(str(rid))
                    self._send(200, {"status": "REJECTED"})
                else:
                    approval_id = control.approve(str(rid), approver, str(data.get("signature")))
                    out = gateway.execute_approved(str(rid), approval_id)
                    self._send(200, {"outcome": out.public(), "signals": list(out.signals)})
            except ControlError as exc:
                self._send(403, {"error": str(exc)})
        except Exception:
            log.exception("unexpected admin error")
            self._send(500, DENIED)
        finally:
            app.slots.release()  # type: ignore[attr-defined]


class _ReplayCache:
    """Remembers authenticated admin signatures for twice the timestamp window."""

    def __init__(self, ttl: float = 130.0) -> None:
        self._ttl, self._seen, self._lock = ttl, {}, threading.Lock()

    def first_use(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            self._seen = {k: e for k, e in self._seen.items() if e > now}
            if key in self._seen:
                return False
            self._seen[key] = now + self._ttl
            return True


class AdminServer(_CappedServer):
    def __init__(self, addr: tuple[str, int], gateway: Gateway, control: ControlPlane, audience: str,
                 max_inflight: int, request_timeout: float) -> None:
        super().__init__(addr, _AdminHandler)
        self._init_caps(16, 4)
        self.replay = _ReplayCache()
        self.gateway, self.control, self.audience = gateway, control, audience
        self.slots = threading.BoundedSemaphore(max_inflight)
        self.request_timeout = request_timeout


def start_admin(gateway: Gateway, control: ControlPlane, audience: str, *, host: str = "127.0.0.1",
                port: int = 0, max_inflight: int = 8,
                request_timeout: float = 10.0) -> tuple[AdminServer, threading.Thread]:
    server = AdminServer((host, port), gateway, control, audience, max_inflight, request_timeout)
    thread = threading.Thread(target=server.serve_forever, daemon=True, name="custos-admin")
    thread.start()
    return server, thread
