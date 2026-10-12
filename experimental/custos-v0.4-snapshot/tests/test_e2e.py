"""End-to-end with REAL processes: a server process, agent/approver clients over sockets, the `custos`
CLI, persistence across restarts, tamper detection, MCP over stdio, attestation CLI."""
from __future__ import annotations

import json
import os
import select
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from custos.client import AdminClient, AgentClient
from custos.crypto import generate_keypair, private_from_hex, sign
from custos.governance import sign_for_group
from custos.workspace import WorkspaceError, init_workspace, load_workspace

EMAIL = {"to": "cto@company.local", "subject": "Weekly", "body": "summary"}
PY = [sys.executable, "-m", "custos"]
ENV = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parent.parent)}


def cli(*args, timeout=60):
    return subprocess.run([*PY, *map(str, args)], capture_output=True, text=True, timeout=timeout, env=ENV)


class Live:
    def __init__(self, ws: Path):
        self.ws = ws
        self.proc = subprocess.Popen([*PY, "serve", str(ws), "--port", "0", "--admin-port", "0"],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=ENV)
        self.info = self._ready()
        cfg = json.loads((ws / "config.json").read_text())
        self.audience = cfg["audience"]

    def _ready(self):
        deadline = time.time() + 20
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("server exited: " + self.proc.stderr.read())
            if select.select([self.proc.stdout], [], [], 0.2)[0]:
                line = self.proc.stdout.readline()
                if line.strip().startswith("{"):
                    return json.loads(line)
        raise RuntimeError("server did not become ready")

    def agent(self, actor="research_agent") -> AgentClient:
        key = private_from_hex((self.ws / "keys" / "agents" / f"{actor}.key").read_text())
        return AgentClient(f"http://127.0.0.1:{self.info['port']}", actor, key, self.audience)

    def admin(self, approver="alice_ops", key=None) -> AdminClient:
        key = key or private_from_hex((self.ws / "keys" / "approvers" / f"{approver}.key").read_text())
        return AdminClient(f"http://127.0.0.1:{self.info['admin_port']}", approver, key, self.audience)

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()


@pytest.fixture
def ws(tmp_path):
    path = tmp_path / "ws"
    init_workspace(path)
    return path


@pytest.fixture
def live(ws):
    s = Live(ws)
    yield s
    s.stop()


READ = ("read_database", "research_db_main", {"query": "market_trends"}, "research")


def test_agent_and_human_approver_run_in_separate_processes(live):
    a = live.agent()
    assert a.call(*READ)["status"] == "DONE"
    assert a.call("read_database", "finance_db_main", {"query": "finance_summary"}, "research")["status"] == "DENIED"
    p = a.call("send_email", "company_email", EMAIL, "research")
    assert p["status"] == "PENDING_APPROVAL" and not list((live.ws / "outbox").glob("*.json"))
    out = live.admin().approve(p["request_id"])
    assert out["outcome"]["status"] == "DONE"
    assert len(list((live.ws / "outbox").glob("*.json"))) == 1


def test_pending_requests_and_the_audit_chain_survive_restarts(ws):
    s = Live(ws)
    p = s.agent().call("send_email", "company_email", EMAIL, "research")
    s.stop()
    s2 = Live(ws)  # restart: the parked request must still be there, and approvable exactly once
    try:
        assert [v["request_id"] for v in s2.admin().pending()] == [p["request_id"]]
        assert s2.admin().approve(p["request_id"])["outcome"]["executed"] is True
        assert len(list((ws / "outbox").glob("*.json"))) == 1
        with pytest.raises(KeyError):
            s2.admin().approve(p["request_id"])
    finally:
        s2.stop()
    s3 = Live(ws)
    s3.stop()
    assert cli("audit-verify", ws).returncode == 0  # one valid chain across three process lifetimes


def test_revocation_by_cli_is_instant_and_permanent(ws):
    s = Live(ws)
    try:
        assert s.agent().call(*READ)["status"] == "DONE"
        r = cli("revoke", ws, "research_agent", "--by", "ops")
        assert r.returncode == 0, r.stderr
        assert s.agent().call(*READ)["status"] == "DENIED"  # the running server sees it immediately
    finally:
        s.stop()
    s2 = Live(ws)
    try:
        assert s2.agent().call(*READ)["status"] == "DENIED"  # and a restart does not resurrect the agent
    finally:
        s2.stop()


def test_the_agents_key_is_not_an_approvers_key(live):
    a = live.agent()
    p = a.call("send_email", "company_email", EMAIL, "research")
    agent_key = private_from_hex((live.ws / "keys" / "agents" / "research_agent.key").read_text())
    with pytest.raises(PermissionError):
        live.admin(approver="research_agent", key=agent_key).pending()
    with pytest.raises(PermissionError):
        live.admin(approver="alice_ops", key=agent_key).pending()  # right name, wrong key
    assert p["status"] == "PENDING_APPROVAL" and not list((live.ws / "outbox").glob("*.json"))


def test_server_keeps_serving_after_garbage_traffic(live):
    import socket
    for payload in (b"\x00\xff" * 500, b"GET / HTTP/9.9\r\n\r\n", b"POST /v1/submit HTTP/1.0\r\n\r\n",
                    b"POST /v1/submit HTTP/1.0\r\nContent-Length: 5\r\n\r\n{{{"):
        s = socket.create_connection(("127.0.0.1", live.info["port"]), timeout=5)
        s.sendall(payload)
        s.close()
    assert live.agent().call(*READ)["status"] == "DONE"
    assert live.proc.poll() is None


def test_tampered_audit_log_is_detected_and_the_server_refuses_to_start(ws):
    s = Live(ws)
    s.agent().call(*READ)
    s.stop()
    assert cli("audit-verify", ws).returncode == 0
    log = ws / "audit" / "audit.jsonl"
    lines = log.read_text().splitlines()
    target = next(i for i, l in enumerate(lines) if '"status":"DONE"' in l)  # the RESULT of the agent's read
    edited = lines[target].replace('"status":"DONE"', '"status":"XXXX"')
    assert edited != lines[target]  # make sure we REALLY changed something (a silent no-op once fooled a demo)
    log.write_text("\n".join(lines[:target] + [edited] + lines[target + 1:]) + "\n")
    bad = cli("audit-verify", ws)
    assert bad.returncode == 1 and "FAILED" in bad.stdout
    refused = subprocess.run([*PY, "serve", str(ws), "--port", "0"], capture_output=True, text=True, timeout=30, env=ENV)
    assert refused.returncode != 0


def test_truncating_the_audit_log_is_caught_by_the_persistent_anchor(ws):
    s = Live(ws)
    s.agent().call(*READ)
    s.stop()
    log = ws / "audit" / "audit.jsonl"
    lines = log.read_text().splitlines()
    log.write_text("\n".join(lines[:-2]) + "\n")  # delete the most recent entries
    r = cli("audit-verify", ws)
    assert r.returncode == 1 and "TRUNCATED" in r.stdout
    log.unlink()
    assert "FILE_MISSING" in cli("audit-verify", ws).stdout


def test_modified_policy_is_refused_at_startup(ws):
    pol = ws / "policy.json"
    pol.write_text(pol.read_text().replace("research-read-db", "research-read-xx"))
    r = subprocess.run([*PY, "serve", str(ws), "--port", "0"], capture_output=True, text=True, timeout=30, env=ENV)
    assert r.returncode != 0
    with pytest.raises(WorkspaceError, match="policy refused"):
        load_workspace(ws, announce=False)


def test_governed_policy_mode_requires_every_group_to_reach_quorum(ws):
    raw = (ws / "policy.json").read_bytes()
    cto, cto_pub = generate_keypair()
    sec = [generate_keypair() for _ in range(3)]
    (ws / "governance.json").write_text(json.dumps({"groups": [
        {"name": "engineering", "quorum": 1, "keys": {"cto": cto_pub.hex()}},
        {"name": "security", "quorum": 2, "keys": {f"s{i}": k[1].hex() for i, k in enumerate(sec)}}]}))
    sigs = {"engineering": {"cto": sign_for_group(cto, raw, "engineering")},
            "security": {f"s{i}": sign_for_group(sec[i][0], raw, "security") for i in (0, 1)}}
    (ws / "policy.signatures.json").write_text(json.dumps(sigs))
    assert load_workspace(ws, announce=False).policy.version  # CTO + 2 of 3 security officers: accepted
    sigs["security"].pop("s1")
    (ws / "policy.signatures.json").write_text(json.dumps(sigs))
    with pytest.raises(WorkspaceError, match="governed policy refused"):
        load_workspace(ws, announce=False)  # 1 of 3 security officers: refused, no CEO involved either way


def test_init_refuses_a_non_empty_directory_and_protects_secret_keys(ws, tmp_path):
    with pytest.raises(WorkspaceError):
        init_workspace(ws)
    for secret in [*(ws / "keys" / "agents").glob("*.key"), *(ws / "secrets").glob("*.key"),
                   ws / "keys" / "attester.key", *(ws / "keys" / "approvers").glob("*.key")]:
        assert stat.S_IMODE(secret.stat().st_mode) == 0o600, secret
    assert cli("init", ws).returncode == 2 or cli("init", ws).returncode != 0


def _mcp(ws, actor="research_agent"):
    return subprocess.Popen([*PY, "mcp", str(ws), "--actor", actor], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, env=ENV)


def _ask(proc, msg, timeout=20):
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()
    if not select.select([proc.stdout], [], [], timeout)[0]:
        raise TimeoutError("no MCP response")
    return json.loads(proc.stdout.readline())


def test_mcp_proxy_as_a_real_stdio_process(live):
    p = _mcp(live.ws)
    try:
        assert _ask(p, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                        "params": {"protocolVersion": "2025-06-18"}})["result"]["serverInfo"]["name"]
        p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        names = [t["name"] for t in _ask(p, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]]
        assert names == ["read_market_trends", "send_email"]
        r = _ask(p, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                     "params": {"name": "read_market_trends", "arguments": {"query": "market_trends"}}})
        assert r["result"]["isError"] is False and "AI infrastructure" in r["result"]["content"][0]["text"]
        m = _ask(p, {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                     "params": {"name": "send_email", "arguments": EMAIL}})
        assert m["result"]["isError"] is True and "human approval" in m["result"]["content"][0]["text"]
        pend = live.admin().pending()
        assert len(pend) == 1 and pend[0]["action"] == "send_email"  # the agent's tool call is waiting for a human
    finally:
        p.kill()


def test_zero_knowledge_attestation_cli_roundtrip(ws):
    s = Live(ws)
    try:
        a = s.agent()
        a.call(*READ)
        for _ in range(2):
            p = a.call("send_email", "company_email", EMAIL, "research")
            s.admin().approve(p["request_id"])
        out = ws / "att.json"
        r = cli("attest", ws, "--org", "acme", "--max-egress", "5", "--max-class", "2", "--out", out)
        assert r.returncode == 0, r.stderr
        blob = out.read_text()
        assert '"signature"' in blob and "egress_count" in blob
        v = cli("verify-attestation", ws, "--org", "acme", "--max-egress", "5", "--max-class", "2", "--attestation", out)
        assert v.returncode == 0 and "VALID" in v.stdout and "egress_count" in v.stdout
        strict = cli("verify-attestation", ws, "--org", "acme", "--max-egress", "1", "--max-class", "2", "--attestation", out)
        assert strict.returncode == 1 and "INVALID" in strict.stdout  # the real count is 2
        wrong_org = cli("verify-attestation", ws, "--org", "other", "--max-egress", "5", "--attestation", out)
        assert wrong_org.returncode == 1
        refused = cli("attest", ws, "--org", "acme", "--max-egress", "1", "--out", ws / "bad.json")
        assert refused.returncode == 1 and "not compliant" in refused.stderr and not (ws / "bad.json").exists()
        att = json.loads(blob)
        att["commitments"]["egress_count"] = format(int(att["commitments"]["egress_count"], 16) ^ 2, "x")
        out.write_text(json.dumps(att))
        assert cli("verify-attestation", ws, "--org", "acme", "--max-egress", "5", "--attestation", out).returncode == 1
    finally:
        s.stop()
