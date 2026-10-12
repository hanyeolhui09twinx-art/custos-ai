"""Agent-side SDK. The agent holds its OWN signing key; the gateway only ever sees public keys."""
from __future__ import annotations

import json
import secrets
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Mapping, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import to_wire  # noqa: F401  (re-exported)
from .crypto import sign_request
from .models import ActionRequest


class AgentClient:
    def __init__(self, base_url: str, actor_id: str, signing_key: Ed25519PrivateKey, audience: str, *,
                 clock: Callable[[], float] = time.time, session: str | None = None,
                 timeout: float = 15.0) -> None:
        self.base_url, self.actor_id, self._key = base_url.rstrip("/"), actor_id, signing_key
        self.audience, self._clock, self.session, self.timeout = audience, clock, session, timeout

    def build(self, action: str, resource: str, params: Mapping[str, Any], purpose: str, *,
              handles: Sequence[str] = (), chain: Sequence[str] = (), ttl: float = 30.0) -> ActionRequest:
        now = self._clock()
        req = ActionRequest(request_id="r_" + secrets.token_hex(8), actor_id=self.actor_id, action=action,
                            target_resource_id=resource, parameters=dict(params), purpose=purpose,
                            issued_at=now, expires_at=now + ttl, nonce=secrets.token_hex(16),
                            handle_ids=tuple(handles), delegation_chain=tuple(chain), audience=self.audience)
        return sign_request(self._key, req)

    def _post(self, path: str, body: Mapping[str, Any], headers: Mapping[str, str] | None = None) -> tuple[int, dict]:
        req = urllib.request.Request(self.base_url + path, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read())
            except ValueError:
                return e.code, {"status": "DENIED", "executed": False}

    def call(self, action: str, resource: str, params: Mapping[str, Any], purpose: str, **kw: Any) -> dict[str, Any]:
        request = self.build(action, resource, params, purpose, **kw)
        headers = {"X-Custos-Session": self.session} if self.session else {}
        _, out = self._post("/v1/submit", to_wire(request), headers)
        return out

    def open_session(self, certificate_dict: Mapping[str, Any], device_key: Ed25519PrivateKey) -> bool:
        """Closed-access mode: fetch a challenge, prove possession of the device key, keep the session."""
        from .access import sign_challenge  # local import: only needed in closed-access mode
        with urllib.request.urlopen(self.base_url + "/v1/challenge", timeout=self.timeout) as r:
            nonce = bytes.fromhex(json.loads(r.read())["nonce"])
        code, out = self._post("/v1/handshake", {"cert": dict(certificate_dict), "nonce": nonce.hex(),
                                                 "signature": sign_challenge(device_key, self.audience, nonce)})
        self.session = out.get("session") if code == 200 else None
        return self.session is not None


class AdminClient:
    """The human approver's tool. It RECOMPUTES the digest from the fields it displays before signing."""

    def __init__(self, base_url: str, approver_id: str, signing_key: Ed25519PrivateKey, audience: str,
                 timeout: float = 15.0) -> None:
        self.base_url, self.approver_id, self._key = base_url.rstrip("/"), approver_id, signing_key
        self.audience, self.timeout = audience, timeout

    def _post(self, path: str, body: Mapping[str, Any]) -> tuple[int, dict]:
        req = urllib.request.Request(self.base_url + path, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read())
            except ValueError:
                return e.code, {"error": "refused"}

    def pending(self) -> list[dict[str, Any]]:
        from .crypto import sign
        from .server import admin_payload
        ts = time.time()
        code, out = self._post("/admin/pending", {"approver_id": self.approver_id, "ts": ts,
                                                  "signature": sign(self._key, admin_payload(self.audience, "pending", ts))})
        if code != 200:
            raise PermissionError("admin listener refused the request")
        return out["pending"]

    def _view(self, request_id: str) -> dict[str, Any]:
        for v in self.pending():
            if v["request_id"] == request_id:
                return v
        raise KeyError("no such pending request")

    def approve(self, request_id: str) -> dict[str, Any]:
        from .control_plane import sign_approval_from_view
        sig = sign_approval_from_view(self._key, self._view(request_id))  # refuses on digest mismatch
        _, out = self._post("/admin/approve", {"approver_id": self.approver_id, "request_id": request_id,
                                               "signature": sig})
        return out

    def reject(self, request_id: str) -> dict[str, Any]:
        from .canonical import digest_of_fields
        from .control_plane import ControlError, sign_rejection
        view = self._view(request_id)
        if digest_of_fields(view["fields"]) != view["digest"]:
            raise ControlError("digest does not match the displayed request: refusing to sign")
        _, out = self._post("/admin/reject", {"approver_id": self.approver_id, "request_id": request_id,
                                              "signature": sign_rejection(self._key, request_id, view["digest"])})
        return out
