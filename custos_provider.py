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
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from custos_gateway import (
    ActionRequest, DispatchAuthorizationError, DispatchAuthority,
    DispatchPermit, MockExecutionAdapter, canonical_json,
)

MAX_BODY_BYTES = 65_536
PROVIDER_PATH = "/v1/dispatch"


class DurableDispatchPermitVerifier:
    """Verify gateway-issued permits and persist nonce consumption in SQLite."""

    def __init__(
        self, db_path: str | Path, signing_key: bytes,
        clock: Callable[[], float] = time.time, max_ttl_seconds: float = 15.0,
    ) -> None:
        if not isinstance(signing_key, bytes) or len(signing_key) < 32:
            raise ValueError("Provider signing key must be at least 32 bytes.")
        if (isinstance(max_ttl_seconds, bool) or not isinstance(max_ttl_seconds, (int, float))
                or not math.isfinite(max_ttl_seconds) or max_ttl_seconds <= 0):
            raise ValueError("Provider TTL must be finite and positive.")
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._key = signing_key
        self._clock = clock
        self._ttl = float(max_ttl_seconds)
        with self._connect() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS consumed_permits (
                nonce TEXT PRIMARY KEY, request_digest TEXT NOT NULL,
                expires_at REAL NOT NULL, consumed_at REAL NOT NULL)""")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_consumed_permits_expiry ON consumed_permits(expires_at)")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

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
        if not isinstance(permit.nonce, str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", permit.nonce):
            raise DispatchAuthorizationError("Invalid permit nonce.")
        if not isinstance(permit.signature, str) or not re.fullmatch(r"[0-9a-f]{64}", permit.signature):
            raise DispatchAuthorizationError("Invalid permit signature.")
        for value in (permit.issued_at, permit.expires_at):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise DispatchAuthorizationError("Invalid permit timestamp.")
        try:
            expected = hmac.new(
                self._key, canonical_json(DispatchAuthority._claims(permit)).encode("utf-8"),
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


class ToolProviderService:
    """The provider owns its tool registry; the calling agent receives no tool client."""

    def __init__(self, verifier: DurableDispatchPermitVerifier) -> None:
        self.verifier = verifier
        self.adapter = MockExecutionAdapter()

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
        self.verifier.consume(request, payload["permit"])
        # MockExecutionAdapter has an exact action/resource registry and no external effects.
        return self.adapter.execute(request)


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
                if urlsplit(self.path).path == "/health":
                    self._send(200, {"status": "ok", "service": "custos-tool-provider", "mode": "mock"})
                else:
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
                    self._send(403, {"error": "Dispatch authorization rejected."})
                except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
                    self._send(400, {"error": "Malformed or unsupported provider request."})
                except Exception:
                    self._send(500, {"error": "Provider execution failed."})

            def log_message(self, format: str, *args: Any) -> None:
                # Default access logs contain method/path only, never the request body.
                super().log_message(format, *args)
        return Handler


def create_provider_server(
    signing_key: bytes, db_path: str | Path = ".custos-data/provider-replay.sqlite3",
    host: str = "127.0.0.1", port: int = 8766,
) -> ToolProviderHTTPServer:
    if host != "127.0.0.1":
        raise ValueError("The mock provider only binds to loopback.")
    return ToolProviderHTTPServer(
        (host, port), ToolProviderService(DurableDispatchPermitVerifier(db_path, signing_key))
    )


class HttpToolProviderAdapter:
    """Gateway-side client that forwards a permit, never a raw tool client or credential."""

    def __init__(self, endpoint: str, timeout_seconds: float = 3.0) -> None:
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
            if 400 <= exc.code < 500:
                raise DispatchAuthorizationError("Provider rejected dispatch.") from exc
            raise RuntimeError("Provider execution failed.") from exc
        except (URLError, TimeoutError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DispatchAuthorizationError("Provider unavailable; dispatch failed closed.") from exc
        if not isinstance(result, dict) or set(result) != {"result"} or not isinstance(result["result"], dict):
            raise RuntimeError("Provider returned an invalid response.")
        return result["result"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local Custos mock tool provider.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--db", default=".custos-data/provider-replay.sqlite3")
    args = parser.parse_args()
    try:
        key = bytes.fromhex(os.environ.get("CUSTOS_DISPATCH_SIGNING_KEY", ""))
    except ValueError as exc:
        raise SystemExit("CUSTOS_DISPATCH_SIGNING_KEY must be hexadecimal.") from exc
    if len(key) < 32:
        raise SystemExit("CUSTOS_DISPATCH_SIGNING_KEY must encode at least 32 bytes.")
    server = create_provider_server(key, db_path=args.db, host=args.host, port=args.port)
    print(f"Custos mock tool provider listening on {args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
