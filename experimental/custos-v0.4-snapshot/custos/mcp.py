"""Minimal MCP (Model Context Protocol) governance proxy over stdio.

An MCP client (an agent runtime) lists and calls tools on THIS server. Every call is turned into a
signed Custos request, so tool use by an AI agent is authorised, audited and, when risky, parked for
a human. The agent never talks to the real tools.

Implements the JSON-RPC 2.0 subset a client needs: initialize, notifications/initialized, ping,
tools/list, tools/call. Newline-delimited JSON on stdin/stdout.

HONEST LIMIT: written against the public MCP specification and tested with simulated messages; it has
not been validated against real MCP clients or every protocol revision.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, TextIO

from . import __version__
from .client import AgentClient

SUPPORTED_PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")


@dataclass(frozen=True)
class GovernedTool:
    name: str
    description: str
    action: str
    resource: str
    purpose: str
    input_schema: Mapping[str, Any]


def _err(mid: Any, code: int, msg: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": msg}}


class McpGovernanceProxy:
    def __init__(self, client: AgentClient, tools: Iterable[GovernedTool]) -> None:
        self.client = client
        self.tools = {t.name: t for t in tools}

    def handle(self, msg: Any) -> dict[str, Any] | None:
        """Returns the JSON-RPC response, or None for notifications."""
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
            return _err(msg.get("id") if isinstance(msg, dict) else None, -32600, "invalid request")
        mid, method, params = msg.get("id"), msg["method"], msg.get("params") or {}
        if "id" not in msg:  # notification: never answered
            return None
        if not isinstance(params, dict):
            return _err(mid, -32602, "params must be an object")
        if method == "initialize":
            wanted = params.get("protocolVersion")
            version = wanted if wanted in SUPPORTED_PROTOCOLS else SUPPORTED_PROTOCOLS[0]
            return {"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": version, "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "custos-governance-proxy", "version": __version__}}}
        if method == "ping":
            return {"jsonrpc": "2.0", "id": mid, "result": {}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": mid, "result": {"tools": [
                {"name": t.name, "description": t.description, "inputSchema": dict(t.input_schema)}
                for t in self.tools.values()]}}
        if method == "tools/call":
            return self._call(mid, params)
        return _err(mid, -32601, "method not found")

    def _call(self, mid: Any, params: dict[str, Any]) -> dict[str, Any]:
        tool = self.tools.get(params.get("name")) if isinstance(params.get("name"), str) else None
        args = params.get("arguments", {})
        if tool is None or not isinstance(args, dict):
            return _err(mid, -32602, "unknown tool or invalid arguments")
        handles = args.pop("handle_ids", ())  # governance metadata, not tool input
        try:
            out = self.client.call(tool.action, tool.resource, args, tool.purpose,
                                   handles=tuple(handles) if isinstance(handles, (list, tuple)) else ())
        except Exception:
            out = {"status": "DENIED", "executed": False}
        status = out.get("status")
        if status == "DONE":
            text, is_error = json.dumps(out.get("result", {}), ensure_ascii=False), False
        elif status == "PENDING_APPROVAL":
            text, is_error = f"Awaiting human approval (request {out.get('request_id')}). Nothing was executed.", True
        else:
            text, is_error = "Denied by policy. Nothing was executed.", True  # no reasons: probing aid
        return {"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": text}],
                                                         "isError": is_error}}

    def serve_stdio(self, stdin: TextIO, stdout: TextIO) -> None:
        for line in stdin:
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                resp: dict[str, Any] | None = _err(None, -32700, "parse error")
            else:
                resp = self.handle(msg)
            if resp is not None:
                stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
                stdout.flush()
