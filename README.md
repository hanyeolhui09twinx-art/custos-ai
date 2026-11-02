# Custos AI

**An independent control and visibility layer for autonomous AI.**

**Never trust. Always verify.**

Custos is an early-stage research prototype for evaluating autonomous-agent actions outside the agent before those actions reach a tool.

## What exists now

### 1. Browser Simulation Studio

The [bilingual Simulation Studio](https://hanyeolhui09twinx-art.github.io/custos-ai/) is a static browser sandbox.

- Korean / English interface
- 13 predefined scenarios
- Policy decision, human approval/denial, sequential and Multi-Agent simulations
- Pause/resume, browser-local history, and trace/report export
- A separate Local API Console that can call a locally running Python gateway

**Boundary:** the main Studio simulates actions in the browser. The Local API Console can connect to the user's own loopback API, but that backend still uses a mock execution adapter. Neither page connects to a real database, email provider, or production agent tool. See [the Studio guide](simulation-studio/README.md).

### 2. Python policy gateway and local API

- **custos_gateway.py** — deny-by-default policy evaluation, strict request validation, SQLite-backed approval state, request idempotency, dispatch-time policy re-check, and a mock execution adapter.
- **custos_api.py** — authenticated local HTTP API for agent requests and human-review operations. It binds to loopback and enables CORS only for the official Custos GitHub Pages origin.
- **audit_log.py** — local JSONL audit events linked by a SHA-256 hash chain.
- **tests/test_custos.py** — policy, approval lifecycle, request replay, API authentication, concurrency, CORS, and audit-integrity tests.

Default demonstration policy:

| Agent | Action | Resource | Result |
|---|---|---|---|
| research_agent | read_database | research_db | ALLOW (mock execution) |
| research_agent | send_email | company_email | HUMAN_APPROVAL, then mock execution |
| Any configured agent | disable_custos, modify_custos_policy, delete_audit_log | Any | BLOCK |

Unknown agents, unlisted actions, and out-of-scope resources are denied by default. The mock adapter does not send email, read a real database, or call external tools.

### Request retries

Clients should send a stable request_id and reuse it when retrying the same logical operation. An exact retry returns the cached result and does not dispatch a second time. Reusing the same request_id with a different payload returns a conflict. Requests left in processing after a process crash are not automatically reclaimed in this version; they require operator investigation.

## Run locally

Requires Python 3.10+ and uses only the Python standard library.

### Run automated tests

~~~bash
python -m unittest discover -s tests -v
~~~

### Start the local API

Generate fresh random tokens and keep them outside the repository. Do not paste tokens into issues, commits, or screenshots.

PowerShell example:

~~~powershell
$agentToken = python -c "import secrets; print(secrets.token_urlsafe(32))"
$reviewerToken = python -c "import secrets; print(secrets.token_urlsafe(32))"
$env:CUSTOS_AGENT_TOKENS = '{"research_agent":"' + $agentToken + '"}'
$env:CUSTOS_REVIEWER_TOKEN = $reviewerToken
python custos_api.py
~~~

Keep this terminal open while using the console. The tokens exist only in this shell environment; do not commit them or send them to anyone. Then open the [Local API Console](https://hanyeolhui09twinx-art.github.io/custos-ai/local-console.html), paste the two token values into their respective fields, and select **Test connection**. Your browser may ask you to allow Loopback network access for the Custos GitHub Pages site.

The server binds to 127.0.0.1:8765 by default. Remote binding is rejected.

### API routes

All routes except GET /health require a Bearer token.

| Method | Route | Credential | Purpose |
|---|---|---|---|
| GET | /health | None | Local service health |
| POST | /v1/requests | Agent | Submit an action request |
| GET | /v1/approvals | Reviewer | List pending approvals |
| POST | /v1/approvals/{id}/review | Reviewer | Approve or deny an exact request |
| POST | /v1/approvals/{id}/execute | Original agent | Execute an approved request once |

Example request:

~~~bash
curl http://127.0.0.1:8765/v1/requests \
  -H "Authorization: Bearer YOUR_AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"read_database","resource":"research_db","request_id":"job-2026-001","parameters":{"query":"market_trends"}}'
~~~

For an approval-required action, the agent receives an approval_id. A reviewer lists pending approvals, posts {"decision":"approve"} or {"decision":"deny"} to the review route, and the original agent calls the execute route. Approval records expire and can be consumed only once.

Local runtime files are written under .custos-data/ by default and are excluded from Git.

## Automated checks

GitHub Actions runs Python compilation and the unit/API tests on pushes and pull requests to main.

## Security and implementation limits

This is **not a production security product**:

- The API has Bearer-token authentication but no TLS, token rotation, user/role directory, rate limiting, or production deployment configuration.
- It binds to loopback only. Do not expose it to a network or connect it to valuable tools.
- Agent identity is mapped from a configured static token. There is no asymmetric identity, signed request envelope, delegated credential chain, or hardware-backed key protection yet.
- Approval state is stored in local SQLite. The approval is bound to the immutable request snapshot and is single-use within this service, but there is no distributed transaction with a downstream tool.
- The mock execution adapter does not prove that a real tool cannot be called directly. A production adapter must enforce authorization at the actual tool boundary and handle timeouts, retries, partial success, and reconciliation.
- Request receipts are retained indefinitely. A request stuck in processing after a crash needs manual investigation.
- The JSONL audit log is hash-chained and detects ordinary edits to the recorded chain. It is not immutable against an attacker who can rewrite the entire file. Production needs remote/WORM storage and independent integrity anchoring.
- Local API access from the hosted console is gated by the browser's loopback-network permission and CORS. It does not change the backend's prototype limitations.

See [the threat model and engineering self-critique](docs/THREAT_MODEL.md) for assumptions, counterarguments, edge cases, and next verification gates.
