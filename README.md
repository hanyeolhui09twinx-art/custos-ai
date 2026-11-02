# Custos AI

**Independent control for autonomous AI.**  
**Never trust. Always verify.**

Custos is an early-stage research project exploring an independent authorization layer between autonomous AI agents and the tools they can invoke. Its central design principle is to separate an agent's ability to act from its authority to act.

## Public website

**[Open the Custos AI corporate website](https://hanyeolhui09twinx-art.github.io/custos-ai/)** · [Developer Docs](https://hanyeolhui09twinx-art.github.io/custos-ai/developers.html) · [Updates](https://hanyeolhui09twinx-art.github.io/custos-ai/updates.html)

The public site includes dedicated pages:

| Page | Purpose |
|---|---|
| Home | Project overview and interactive policy concept demo |
| Platform | Request validation, policy decisions, human approval, and audit flow |
| Technology | Technical architecture and implementation status |
| Security & Trust | Implemented controls, limitations, and five-lens threat model |
| Research | Research questions, roadmap, and engineering records |
| About | Project mission and current status |
| Contact | GitHub-based technical feedback and collaboration |
| Privacy | Data handling for the static site and browser tools |
| Terms of Use | Usage boundaries for the research website and prototype tools |
| Updates | Engineering milestones, test status, and next development gates |
| Developer Docs | Local API setup, request schema, routes, and security boundaries |
| Simulation Lab | Preserved bilingual browser simulation |
| Local Control Room | Browser console for a locally running Python API |

The site is built as static HTML, CSS, and JavaScript and deployed through GitHub Pages. It is not a hosted SaaS backend.

## What exists in the repository

### 1. Python policy gateway and local API

- `custos_gateway.py` — deny-by-default policy evaluation, strict request validation, SQLite-backed approval and request state, gateway-restart recovery for interrupted requests, 15-second request-bound HMAC dispatch permits, adapter-boundary policy re-checks, approval-claim verification, and optional signed dispatch to a separate provider process.
- `custos_provider.py` — loopback-only mock tool-provider service. It independently verifies gateway permits, persists consumed nonces, and maintains a SQLite execution-receipt ledger keyed by Agent and request ID.
- `custos_api.py` — authenticated local HTTP API. It binds to loopback and allows browser CORS only from the official Custos GitHub Pages origin.
- `audit_log.py` — local JSONL events linked by a SHA-256 hash chain.
- `tests/test_custos.py` and `tests/test_provider_process.py` — gateway/API controls plus separate-process tests for normal and human-approved dispatch, signed permits, replay, request idempotency, crash recovery, lost-response reconciliation, and fail-closed behavior.

Demonstration policy:

| Agent | Action | Resource | Result |
|---|---|---|---|
| `research_agent` | `read_database` | `research_db` | ALLOW (mock execution) |
| `research_agent` | `send_email` | `company_email` | HUMAN_APPROVAL, then mock execution |
| Any configured agent | `disable_custos`, `modify_custos_policy`, `delete_audit_log` | Any | BLOCK |

Unknown agents, unlisted actions, and out-of-scope resources are denied by default. The separate loopback provider independently verifies signed permits and persists both consumed nonces and execution receipts. A completed receipt returns the stored result for the same Agent/request ID and digest; a different digest conflicts. An interrupted executing receipt becomes indeterminate at provider startup and is never replayed automatically. The provider still runs only a mock adapter and has no real tool credentials. This is a same-host research harness, not an OS sandbox or production isolation boundary.

### 2. Browser Simulation Lab

The original bilingual browser simulation is preserved at [Simulation Lab](https://hanyeolhui09twinx-art.github.io/custos-ai/lab.html). It includes predefined scenarios, sequential and Multi-Agent simulations, policy traces, and browser-local experiment history. Its actions remain simulated inside the browser.

### 3. Local Control Room

The [Local Control Room](https://hanyeolhui09twinx-art.github.io/custos-ai/local-console.html) can call the Python API on the user's own computer. The [OpenAPI 3.1 contract](https://hanyeolhui09twinx-art.github.io/custos-ai/openapi.json) documents the local routes and schemas. The page keeps entered tokens in memory rather than localStorage and requires browser Loopback network permission in supported browsers.

The hosted site does not provide the Python backend. The API must be started locally.

## Run locally

Requires Python 3.10+ and uses only the Python standard library.

### Run automated tests

~~~bash
python -m unittest discover -s tests -v
~~~

### Start the local API

Generate temporary development tokens in PowerShell. Do not use production credentials.

~~~powershell
$agentToken = python -c "import secrets; print(secrets.token_urlsafe(32))"
$reviewerToken = python -c "import secrets; print(secrets.token_urlsafe(32))"
$env:CUSTOS_AGENT_TOKENS = '{"research_agent":"' + $agentToken + '"}'
$env:CUSTOS_REVIEWER_TOKEN = $reviewerToken
Write-Host "Agent token: $agentToken"
Write-Host "Reviewer token: $reviewerToken"
python custos_api.py
~~~

Keep the terminal open while using the [Local Control Room](https://hanyeolhui09twinx-art.github.io/custos-ai/local-console.html). Paste the two generated tokens into the matching fields and select **Test connection**. The browser may ask you to allow Loopback network access for the Custos GitHub Pages site.

The server binds to `127.0.0.1:8765` by default. Remote binding is rejected.

### Optional separate mock tool-provider process

The following two-terminal setup tests a second local process. Both processes must receive the same temporary HMAC key. Use development-only values.

**Terminal A — start the provider:**

~~~powershell
$dispatchKey = python -c "import secrets; print(secrets.token_hex(32))"
$env:CUSTOS_DISPATCH_SIGNING_KEY = $dispatchKey
Write-Host "Copy this temporary key into Terminal B: $dispatchKey"
python custos_provider.py --host 127.0.0.1 --port 8766
~~~

**Terminal B — start the API and route dispatch through the provider:**

~~~powershell
$env:CUSTOS_DISPATCH_SIGNING_KEY = "<same temporary key from Terminal A>"
$env:CUSTOS_TOOL_PROVIDER_URL = "http://127.0.0.1:8766/v1/dispatch"
$agentToken = python -c "import secrets; print(secrets.token_urlsafe(32))"
$reviewerToken = python -c "import secrets; print(secrets.token_urlsafe(32))"
$env:CUSTOS_AGENT_TOKENS = '{"research_agent":"' + $agentToken + '"}'
$env:CUSTOS_REVIEWER_TOKEN = $reviewerToken
python custos_api.py
~~~

The gateway sends the request and signed permit; the provider checks the signature, exact request digest, expiry, and durable one-time nonce before invoking its mock registry. The shared development key is not a production key-management design. Both processes still run on one trusted machine, the provider uses loopback HTTP, and no external tools or credentials are connected.

### API routes

All routes except `GET /health` require a Bearer token.

| Method | Route | Credential | Purpose |
|---|---|---|---|
| GET | `/health` | None | Local service health |
| POST | `/v1/requests` | Agent | Submit an action request |
| GET | `/v1/approvals` | Reviewer | List pending approvals |
| POST | `/v1/approvals/{id}/review` | Reviewer | Approve or deny an exact request |
| POST | `/v1/approvals/{id}/execute` | Original agent | Execute an approved request once |

### Request retries

Clients must send a stable `request_id` and reuse it for every retry of the same logical operation. The provider ledger is keyed by Agent ID and request ID, and also checks the exact request digest. A completed receipt returns the stored result without invoking the mock tool again; reusing the same ID with a changed payload returns a conflict. If the provider restarts with a receipt in `executing`, it changes that receipt to `indeterminate` rather than replaying it.

When the gateway submits a request but does not receive a definite provider response, it returns `decision: "EXECUTION_UNKNOWN"` and `executed: null`. Submit the **same** request ID again to reconcile against the provider receipt. A confirmed completed receipt resolves to the stored result; an `executing` or `indeterminate` receipt remains unresolved. A missing receipt is not treated as proof that the request was never accepted, so Custos does not automatically dispatch again. Do not generate a new request ID to retry an uncertain operation.

On gateway startup, any local request receipt left in `processing` is changed to `indeterminate`. The next same-ID request first looks for an existing request-bound approval, then checks the provider receipt. It can recover a pending approval without creating a second approval ID, or recover a completed provider result without redispatch. Approved executions left in `executing` are also reconciled against the provider receipt. If neither source can prove the outcome, it stays `EXECUTION_UNKNOWN`. The current recovery assumes a single gateway instance owns this local SQLite database; multi-worker recovery leases are not implemented.

## Contributing\n\nSee [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, engineering expectations, required tests, and security rules. Pull requests use a structured checklist in `.github/PULL_REQUEST_TEMPLATE.md`.\n\n## Feedback and collaboration\n\nGitHub Issues includes structured templates for reproducible bug reports and research/collaboration proposals. Public issues should never include secrets, customer data, or confidential details.\n\n## Automated checks and deployment

GitHub Actions runs:
- Python compilation and unit/API tests.
- JavaScript syntax and browser-console security-wiring checks.
- Corporate website route, canonical URL, sitemap, local-link, bilingual navigation, accessibility, contrast, issue-template, and threat-model checks.
- Deterministic Node-based UI behavior checks for policy decisions, approval/denial, language switching, and keyboard navigation.
- GitHub Pages deployment when files under `simulation-studio/` change.

## Security and implementation limits

This is **not a production security product**:

- The API has Bearer-token authentication but no TLS, token rotation, individual reviewer identity, MFA, rate limiting, or production deployment configuration.
- It binds to loopback only. Do not expose it to a network or connect it to valuable tools.
- Agent identity is mapped from a configured static token. There is no asymmetric identity, signed request envelope, delegated credential chain, or hardware-backed key protection.
- Approval state is stored in local SQLite. There is no distributed transaction with a downstream tool.
- The separate mock provider verifies dispatch permits and stores execution receipts in another local process. Gateway startup also recovers local request receipts left processing, but recovery assumes a single gateway instance. The provider is not an OS sandbox and has no real tool credentials. The ledger provides provider-local at-most-once invocation behavior; a crash after a real downstream side effect but before receipt completion still requires that downstream tool's own idempotency key or status-query reconciliation.
- Raw credential field names are rejected, but this is not general-purpose secret detection. Never place secrets in free-text values.
- The audit log is hash-chained but not immutable against a privileged actor who can rewrite the entire file.
- The Local Control Room uses development tokens. The public page code is part of the credential trust boundary; do not enter production secrets.
- Browser-to-loopback access depends on browser permissions and has not been independently verified across every browser/platform.

## Threat model

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full `/ASSUMPTIONS`, `/BLINDSPOT`, `/COUNTER`, `/EDGECASE`, and `/SELFCRITIQUE` review.

Custos should currently be described as a local research prototype with a mock execution adapter, not a production enforcement layer.


## Development logs

- [Day 001](devlog/day-001.md)
- [Day 002](devlog/day-002.md)
- [Day 003 — Corporate website and public interface](devlog/day-003.md)
- [Day 004 — Public updates journal](devlog/day-004.md)
- [Day 005 — Product experience and explanation](devlog/day-005.md)
- [Day 006 — Conditional policy flow](devlog/day-006.md)
- [Day 007 — Simulation Lab reliability](devlog/day-007.md)
- [Day 008 — Guarded execution boundary](devlog/day-008.md)
- [Day 009 — Separate mock tool-provider process](devlog/day-009.md)
- [Day 010 — Durable execution receipts and recovery](devlog/day-010.md)
- [Day 011 — Gateway restart recovery](devlog/day-011.md)
