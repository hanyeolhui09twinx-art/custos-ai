# Custos AI

**An independent control and visibility layer for autonomous AI.**

**Never trust. Always verify.**

Custos is an early-stage research prototype for evaluating autonomous-agent actions outside the agent before those actions reach a tool.

## What exists now

### 1. Browser Simulation Studio

The [bilingual Simulation Studio](https://hanyeolhui09twinx-art.github.io/custos-ai/) is a static browser-only sandbox.

- Korean / English interface
- 13 predefined scenarios
- Policy decision, human approval/denial, sequential and Multi-Agent simulations
- Pause/resume, browser-local history, and trace/report export

**Boundary:** the hosted Studio does not call the Python API or control real agents. Its actions and side effects are simulated in the browser. See [the Studio guide](simulation-studio/README.md).

### 2. Python policy gateway and local API

The repository now includes a separate, loopback-only API prototype:

- `custos_gateway.py` — deny-by-default policy evaluation, request validation, SQLite-backed approval state, dispatch-time policy re-check, and a mock execution adapter.
- `custos_api.py` — authenticated local HTTP API for agent requests and human-review operations.
- `audit_log.py` — local JSONL audit events linked by a SHA-256 hash chain.
- `tests/test_custos.py` — policy, approval lifecycle, API authentication, and audit-integrity tests.

Default demonstration policy:

| Agent | Action | Resource | Result |
|---|---|---|---|
| `research_agent` | `read_database` | `research_db` | ALLOW (mock execution) |
| `research_agent` | `send_email` | `company_email` | HUMAN_APPROVAL, then mock execution |
| Any configured agent | `disable_custos`, `modify_custos_policy`, `delete_audit_log` | Any | BLOCK |

Unknown agents, unlisted actions, and out-of-scope resources are denied by default. The mock adapter does not send email, read a real database, or call external tools.

## Run locally

Requires Python 3.10+ and uses only the Python standard library.

### Run automated tests

```bash
python -m unittest discover -s tests -v
```

### Start the local API

Generate fresh random tokens and keep them outside the repository. Do not paste tokens into issues, commits, or screenshots.

PowerShell example:

```powershell
$env:CUSTOS_AGENT_TOKENS='{"research_agent":"REPLACE_WITH_RANDOM_TOKEN_OF_32_OR_MORE_CHARACTERS"}'
$env:CUSTOS_REVIEWER_TOKEN='REPLACE_WITH_A_DIFFERENT_RANDOM_TOKEN_OF_32_OR_MORE_CHARACTERS'
python custos_api.py
```

The server binds to `127.0.0.1:8765` by default. Remote binding is rejected in this prototype.

### API routes

All routes except `GET /health` require a Bearer token.

| Method | Route | Credential | Purpose |
|---|---|---|---|
| GET | `/health` | None | Local service health |
| POST | `/v1/requests` | Agent | Submit an action request |
| GET | `/v1/approvals` | Reviewer | List pending approvals |
| POST | `/v1/approvals/{id}/review` | Reviewer | Approve or deny an exact request |
| POST | `/v1/approvals/{id}/execute` | Original agent | Execute an approved request once |

Example request:

```bash
curl http://127.0.0.1:8765/v1/requests \
  -H "Authorization: Bearer YOUR_AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"read_database","resource":"research_db","parameters":{"query":"market_trends"}}'
```

For an approval-required action, the agent receives an `approval_id`. A reviewer lists pending approvals, posts `{"decision":"approve"}` or `{"decision":"deny"}` to the review route, and the original agent calls the execute route. Approval records expire and can be consumed only once.

Local runtime files are written under `.custos-data/` by default and are excluded from Git.

## Automated checks

GitHub Actions runs Python compilation and the unit/API tests on pushes and pull requests to `main`.

## Security and implementation limits

This is **not a production security product**. Current guarantees are deliberately limited:

- The API is a local demonstration service. It has Bearer-token authentication but no TLS, token rotation, user/role directory, rate limiting, or production deployment configuration.
- It binds to loopback only. Do not expose it to a network or connect it to valuable tools.
- Agent identity is mapped from a configured static token. There is no asymmetric identity, signed request envelope, delegated credential chain, or hardware-backed key protection yet.
- Approval state is stored in local SQLite. The approval is bound to the immutable request snapshot and is single-use within this service, but there is no distributed transaction with an external tool.
- The execution adapter is a mock. A production adapter must enforce authorization at the actual tool boundary and deal with timeouts, retries, partial success, and compensating actions.
- The JSONL audit log is hash-chained and detects ordinary edits to the recorded chain. It is not immutable against an attacker who can rewrite the entire file. Production needs remote/WORM storage and independent integrity anchoring.
- The GitHub Pages Studio is still a separate browser simulation and is not integrated with this API.

The next engineering gates are a real agent adapter in a controlled sandbox, stronger identity and delegated-scope management, durable reviewer identity, distributed/idempotent execution semantics, adversarial testing, and independent security review.
