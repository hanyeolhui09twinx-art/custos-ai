from __future__ import annotations

import ipaddress
import json
import math
import re
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any
from urllib.parse import urlsplit


REQUEST_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$")
MAX_RESPONSE_BYTES = 1_048_576


class CustosClientError(RuntimeError):
    """Base exception for Custos API client errors."""


class CustosAPIError(CustosClientError):
    def __init__(self, status: int, message: str) -> None:
        self.status = status
        self.message = message
        super().__init__(f"Custos API returned HTTP {status}: {message}")


class CustosTransportError(CustosClientError):
    """The client could not confirm whether the gateway received a request."""

    def __init__(self, request_id: str, message: str) -> None:
        self.request_id = request_id
        self.message = message
        super().__init__(message)


class CustosClient:
    """Small loopback-only client for the Custos agent and approval API routes.

    The client never receives reviewer credentials. Approval decisions must be
    made through a separate reviewer identity and channel.
    """

    def __init__(
        self,
        agent_token: str,
        base_url: str = "http://127.0.0.1:8765",
        timeout: float = 8.0,
    ) -> None:
        if not isinstance(agent_token, str) or len(agent_token) < 32 or any(ch.isspace() for ch in agent_token):
            raise ValueError("agent_token must be a non-empty secret of at least 32 characters.")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or not 0 < timeout <= 60
        ):
            raise ValueError("timeout must be a finite number between 0 and 60 seconds.")
        if not isinstance(base_url, str):
            raise ValueError("base_url must be a loopback HTTP URL.")
        parts = urlsplit(base_url)
        if (
            parts.scheme != "http"
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
            or parts.path not in {"", "/"}
        ):
            raise ValueError("CustosClient accepts only a plain HTTP loopback origin without a path, query, or fragment.")
        hostname = parts.hostname.rstrip(".").lower()
        try:
            is_loopback = hostname == "localhost" or ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            is_loopback = False
        if not is_loopback:
            raise ValueError("CustosClient requires a loopback API address; remote connections are disabled in this prototype.")
        try:
            port = parts.port
        except ValueError as exc:
            raise ValueError("base_url contains an invalid port.") from exc
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("base_url port must be between 1 and 65535.")
        self.base_url = f"http://{parts.netloc}"
        self._agent_token = agent_token
        self.timeout = float(timeout)

    def _post(self, path: str, payload: dict[str, Any], *, request_id: str) -> dict[str, Any]:
        if not REQUEST_ID_RE.fullmatch(request_id):
            raise ValueError("request_id must be a valid Custos identifier.")
        try:
            encoded = json.dumps(
                payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False
            ).encode("utf-8")
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("Custos request must contain bounded JSON-compatible values.") from exc
        request = urllib.request.Request(
            self.base_url + path,
            data=encoded,
            method="POST",
            headers={
                "Authorization": "Bearer " + self._agent_token,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                status = response.status
        except urllib.error.HTTPError as exc:
            raw = exc.read(MAX_RESPONSE_BYTES + 1)
            try:
                error_body = json.loads(raw.decode("utf-8")) if len(raw) <= MAX_RESPONSE_BYTES else {}
            except (UnicodeDecodeError, json.JSONDecodeError):
                error_body = {}
            message = error_body.get("error") if isinstance(error_body, dict) else None
            raise CustosAPIError(exc.code, message if isinstance(message, str) else "Request was rejected.") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise CustosTransportError(
                request_id,
                "Custos did not return a definitive response. Reconcile using the same request ID; do not create a new ID for the same operation.",
            ) from exc
        if len(raw) > MAX_RESPONSE_BYTES:
            raise CustosAPIError(status, "Custos response exceeded the client size limit.")
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CustosAPIError(status, "Custos returned a malformed JSON response.") from exc
        if not isinstance(body, dict):
            raise CustosAPIError(status, "Custos returned a non-object JSON response.")
        if not 200 <= status < 300:
            message = body.get("error") if isinstance(body.get("error"), str) else "Request was rejected."
            raise CustosAPIError(status, message)
        return body

    def submit(
        self,
        action: str,
        resource: str,
        parameters: dict[str, Any],
        *,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Submit one logical action; callers should reuse request_id for retries."""
        resolved_id = request_id or str(uuid.uuid4())
        return self._post(
            "/v1/requests",
            {
                "action": action,
                "resource": resource,
                "parameters": parameters,
                "request_id": resolved_id,
            },
            request_id=resolved_id,
        )

    def execute_approved(self, approval_id: str) -> dict[str, Any]:
        """Ask the gateway to execute a reviewer-approved request for this agent."""
        try:
            resolved_id = str(uuid.UUID(approval_id))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError("approval_id must be a valid UUID.") from exc
        return self._post(
            "/v1/approvals/" + urllib.parse.quote(resolved_id, safe="") + "/execute",
            {},
            request_id="approval_" + resolved_id.replace("-", ""),
        )
