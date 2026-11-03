# Custos AI

**Preserving Humanity's Agency.**  
**Perfect control is not the assumption. Human agency is the objective.**

Custos is an independent technology venture in formation researching technical and institutional architectures that seek to maximize the time, probability, and recoverability of humanity's meaningful authority around increasingly autonomous AI. It does not assume that AI can be controlled perfectly. Its technical research separates an agent's ability to act from its authority to act, while its broader objective is to preserve human understanding, intervention, containment, and recovery options when safeguards fail.

Product sales are not the mission. Custos intends to develop independent technology and intellectual property, and to work with enterprises and public institutions through negotiated B2B and B2G research, licensing, integration, evaluation, and continuing technical agreements.

## Public website

**[Open the Custos AI corporate website](https://hanyeolhui09twinx-art.github.io/custos-ai/)** · [Developer Docs](https://hanyeolhui09twinx-art.github.io/custos-ai/developers.html) · [Updates](https://hanyeolhui09twinx-art.github.io/custos-ai/updates.html)

The public site includes dedicated pages:

| Page | Purpose |
|---|---|
| Home | Mission-led company overview and interactive policy concept demo |
| Mission | Human agency preservation, intervention time, probability, containment, and recovery objectives |
| Platform | Request validation, policy decisions, human approval, and audit flow |
| Technology | Technical architecture and implementation status |
| Security & Trust | Implemented controls, limitations, and five-lens threat model |
| Research | Research questions, roadmap, and engineering records |
| Company | Founder-led venture direction, independence, and current status |
| Institutional Partnerships | Intended B2B/B2G contract models, responsibilities, and IP boundaries |
| Media Room | Brand-film motion preview, company profile, partnership brief, and film script |
| Contact | Structured technical feedback, research proposals, and institutional collaboration |
| Privacy | Data handling for the static site and browser tools |
| Terms of Use | Usage boundaries for the research website and prototype tools |
| Updates | Engineering milestones, test status, and next development gates |
| Developer Docs | Local API setup, request schema, routes, and security boundaries |
| Simulation Lab | Preserved bilingual browser simulation |
| Local Control Room | Browser console for a locally running Python API |
| Security Operations | Reviewer-only read-only key-ring status and lifecycle audit viewer |

The site is built as static HTML, CSS, and JavaScript and deployed through GitHub Pages. It is not a hosted SaaS backend.

## What exists in the repository

### 1. Python policy gateway and local API

- `custos_gateway.py` — deny-by-default policy evaluation, strict request validation, SQLite-backed approval and request state, gateway-restart recovery for interrupted requests, 15-second request-bound HMAC dispatch permits, adapter-boundary policy re-checks, approval-claim verification, and optional signed dispatch to a separate provider process.
- `custos_provider.py` — loopback-only Provider process. It enforces a deny-by-default exact (Agent, action, resource) registry, versioned v1.0.0 input/output contracts, and required ALLOW/APPROVED permit modes; research uses a three-record synthetic fixture over read-only SQLite, email remains mock-only, and nonce/receipt ledgers are durable.
- `custos_api.py` — authenticated local HTTP API. It binds to loopback and allows browser CORS only from the official Custos GitHub Pages origin.
- `audit_log.py` — local JSONL events linked by a SHA-256 hash chain.
- `tests/test_custos.py` and `tests/test_provider_process.py` — gateway/API controls plus separate-process tests for normal and human-approved dispatch, signed permits, replay, request idempotency, crash recovery, lost-response reconciliation, and fail-closed behavior.

Demonstration policy:

| Agent | Action | Resource | Result |
|---|---|---|---|
| `research_agent` | `read_database` | `research_db` | ALLOW (read-only synthetic SQLite fixture) |
| `research_agent` | `send_email` | `company_email` | HUMAN_APPROVAL, then mock execution |
| Any configured agent | `disable_custos`, `modify_custos_policy`, `delete_audit_log` | Any | BLOCK |

Unknown agents, unlisted actions, and out-of-scope resources are denied by the Gateway; the separate loopback Provider repeats that check against its own exact (agent, action, resource) registry and also requires the registered permit mode. The current bindings are research_agent/read_database/research_db (ALLOW) and research_agent/send_email/company_email (APPROVED). It independently verifies signed permits and persists consumed nonces and execution receipts. A completed receipt returns the stored result for the same Agent/request ID and digest; a different digest conflicts. An interrupted executing receipt becomes indeterminate at Provider startup and is never replayed automatically. APPROVED remains a Gateway-signed assertion: the Provider does not independently query Reviewer identity or the Gateway approval store. For `read_database`, the Provider initializes a local three-record synthetic fixture and opens runtime query connections with SQLite URI `mode=ro` plus `PRAGMA query_only=ON`. It accepts only one bounded `query` parameter, binds every search term as a SQL parameter, uses whole-token matching, and returns at most five rows. `send_email` still uses `MockExecutionAdapter` and never sends email. The fixture is not a production or customer database; no external database, email system, or real tool credentials are connected. This is a same-host research harness, not an OS sandbox or production isolation boundary.

The Provider enforces versioned tool contracts independently of the Gateway. The machine-readable catalog is [`contracts/provider-tool-contracts.v1.0.0.json`](contracts/provider-tool-contracts.v1.0.0.json), using JSON Schema Draft 2020-12 for `research_query_v1` and `email_request_v1` inputs and outputs. The Provider loads this catalog at startup and rejects invalid metadata, duplicate bindings, unsupported schema declarations, and malformed contract versions. The local runtime validator intentionally implements only the subset of keywords used in this catalog; it is not a general-purpose, fully compliant Draft 2020-12 validator. `research_query_v1` accepts exactly `{"query": string}` (1–160 characters and 1–8 searchable terms) and returns a bounded read-only fixture result; `email_request_v1` accepts exactly `{"recipient": string, "subject": string, "body": string}` with bounded fields and returns a `simulated` result. Email is never sent. Inputs are checked before permit consumption and receipt creation; outputs are checked before the durable receipt is stored. Contract versions are included in Provider results and receipts. No production database, external email provider, or arbitrary tool server is connected.

### 2. Browser Simulation Lab

The original bilingual browser simulation is preserved at [Simulation Lab](https://hanyeolhui09twinx-art.github.io/custos-ai/lab.html). It includes predefined scenarios, sequential and Multi-Agent simulations, policy traces, and browser-local experiment history. Its actions remain simulated inside the browser.

### 3. Local Control Room

The [Local Control Room](https://hanyeolhui09twinx-art.github.io/custos-ai/local-console.html) can call the Python API on the user's own computer. The [Security Operations view](https://hanyeolhui09twinx-art.github.io/custos-ai/security-ops.html) reads sanitized key-ring state and key lifecycle events using the reviewer token; it is read-only and does not change keys. The [OpenAPI 3.1 contract](https://hanyeolhui09twinx-art.github.io/custos-ai/openapi.json) documents the local routes and schemas. The page keeps entered tokens in memory rather than localStorage and requires browser Loopback network permission in supported browsers.

The hosted site does not provide the Python backend. The API must be started locally. To view provider state in Security Operations, set `CUSTOS_PROVIDER_DB` and `CUSTOS_PROVIDER_AUDIT_LOG` in the API terminal to the same paths used by the provider process; the defaults in the Developer Guide match.

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

### Optional separate Provider process (read-only research fixture + mock email)

The following two-terminal setup runs the gateway and Provider as separate local processes. Research reads use a local synthetic SQLite fixture in read-only mode; approved email requests still use a mock adapter. It uses a development-only key ring with an old key (`legacy`) retained during a manual rotation overlap and a new active key (`v2`). Never commit these values.

**Terminal A — prepare the key ring and start the provider:**

~~~powershell
$legacyKey = python -c "import secrets; print(secrets.token_hex(32))"
$v2Key = python -c "import secrets; print(secrets.token_hex(32))"
$keyRing = @{ legacy = $legacyKey; v2 = $v2Key }
$encodedKeyRing = $keyRing | ConvertTo-Json -Compress
$env:CUSTOS_DISPATCH_KEYS = $encodedKeyRing
$env:CUSTOS_ACTIVE_DISPATCH_KEY_ID = "v2"
Write-Host "Copy this key ring into Terminal B: $encodedKeyRing"
python custos_provider.py --host 127.0.0.1 --port 8766 --audit .custos-data/provider-audit.jsonl --research-fixture-db .custos-data/research-fixture.sqlite3
~~~

**Terminal B — configure the gateway with the same overlap and activate `v2`:**

~~~powershell
$env:CUSTOS_DISPATCH_KEYS = '<copy the JSON key ring from Terminal A>'
$env:CUSTOS_ACTIVE_DISPATCH_KEY_ID = "v2"
$env:CUSTOS_TOOL_PROVIDER_URL = "http://127.0.0.1:8766/v1/dispatch"
$agentToken = python -c "import secrets; print(secrets.token_urlsafe(32))"
$reviewerToken = python -c "import secrets; print(secrets.token_urlsafe(32))"
$env:CUSTOS_AGENT_TOKENS = '{"research_agent":"' + $agentToken + '"}'
$env:CUSTOS_REVIEWER_TOKEN = $reviewerToken
python custos_api.py
~~~

**Routine rotation sequence:** First deploy the provider with both old and new keys. Then switch every gateway signer to the new `CUSTOS_ACTIVE_DISPATCH_KEY_ID`. Keep the old key in both rings while old gateway instances may still issue permits. After all old signers are stopped and the 15-second permit lifetime plus deployment drain has elapsed, remove the old key from both rings and restart both processes. Removal is the revocation action; there is no built-in scheduled expiry for a retired key.

**Emergency compromise response:** Do not preserve an overlap window for a compromised key. Remove its key ID from the provider's `CUSTOS_DISPATCH_KEYS` and restart the provider first; the provider is the acceptance boundary and will reject permits and receipt-lookup signatures using that ID. Then remove the key from every gateway ring, generate a fresh key under a new ID, update both processes, and restart all gateways. A gateway still holding the old key will fail closed against the provider. Check both components' audit files for `DISPATCH_KEY_REVOKED`, `DISPATCH_KEY_REGISTERED`, and `DISPATCH_KEY_ACTIVATED`. Gateway audit defaults to `.custos-data/audit.jsonl`; the provider defaults to a sibling `.audit.jsonl` based on its database path (or use `--audit`). Audit records contain key IDs and change types, never raw keys or fingerprints. The SQLite lifecycle snapshot stores SHA-256 fingerprints only to detect replacement under an unchanged ID. These local logs are hash-chained, not immutable or remotely anchored.

Revocation only blocks future requests that still need provider verification; it cannot undo an action the provider already accepted. Reconcile uncertain outcomes using the same request ID and the provider receipt. Do not generate a new ID or replay a possibly completed side effect.

The provider validates dispatch `key_id` values against its configured key ring. Receipt reads use a purpose-derived HMAC key selected by `X-Custos-Receipt-Key-Id` and a signature bound to the exact GET path in `X-Custos-Receipt-Signature`. The legacy single-key variable `CUSTOS_DISPATCH_SIGNING_KEY` remains supported as the `default` key for compatibility. Key rotation is manual environment configuration, not KMS/HSM-backed management. Both processes still run on one trusted machine over loopback HTTP, and no external tools or credentials are connected.

### API routes

All routes except `GET /health` require a Bearer token.

| Method | Route | Credential | Purpose |
|---|---|---|---|
| GET | `/health` | None | Local service health |
| POST | `/v1/requests` | Agent | Submit an action request |
| GET | `/v1/approvals` | Reviewer | List pending approvals |
| GET | `/v1/security/overview` | Reviewer | Read sanitized gateway/provider key-ring status and filtered lifecycle events |
| POST | `/v1/approvals/{id}/review` | Reviewer | Approve or deny an exact request |
| POST | `/v1/approvals/{id}/execute` | Original agent | Execute an approved request once |

### Request retries

Clients must send a stable `request_id` and reuse it for every retry of the same logical operation. The provider ledger is keyed by Agent ID and request ID, and also checks the exact request digest. A completed receipt returns the stored result without invoking the mock tool again; reusing the same ID with a changed payload returns a conflict. If the provider restarts with a receipt in `executing`, it changes that receipt to `indeterminate` rather than replaying it.

When the gateway submits a request but does not receive a definite provider response, it returns `decision: "EXECUTION_UNKNOWN"` and `executed: null`. Submit the **same** request ID again to reconcile against the provider receipt. A confirmed completed receipt resolves to the stored result; an `executing` or `indeterminate` receipt remains unresolved. A missing receipt is not treated as proof that the request was never accepted, so Custos does not automatically dispatch again. Do not generate a new request ID to retry an uncertain operation.

On gateway startup, any local request receipt left in `processing` is changed to `indeterminate`. The next same-ID request first looks for an existing request-bound approval, then checks the provider receipt. It can recover a pending approval without creating a second approval ID, or recover a completed provider result without redispatch. Approved executions left in `executing` are also reconciled against the provider receipt. If neither source can prove the outcome, it stays `EXECUTION_UNKNOWN`. The current recovery assumes a single gateway instance owns this local SQLite database; multi-worker recovery leases are not implemented.

### Optional OpenAI Agents SDK integration

Custos includes an adapter for the OpenAI Agents SDK Python `function_tool` runtime. The optional dependency is pinned in `requirements-agents.txt` (`openai-agents==0.24.0`). The adapter exposes exactly three Custos-mediated functions through `create_custos_agent()`:

- `read_research_database` submits `read_database` / `research_db` through `POST /v1/requests`.
- `request_company_email` submits `send_email` / `company_email`. The example policy returns `HUMAN_APPROVAL`; this does not send an email.
- `execute_reviewer_approved_request` asks Custos to execute an approval ID using the original Agent identity. The gateway rejects it unless a separate Reviewer has already approved the exact request.

Install the optional SDK and start the local API in PowerShell:

~~~powershell
python -m pip install -r requirements-agents.txt
$agentToken = python -c "import secrets; print(secrets.token_urlsafe(32))"
$reviewerToken = python -c "import secrets; print(secrets.token_urlsafe(32))"
$env:CUSTOS_AGENT_TOKENS = '{"research_agent":"' + $agentToken + '"}'
$env:CUSTOS_REVIEWER_TOKEN = $reviewerToken
python custos_api.py
~~~

In a second terminal, use the same Agent token and an OpenAI development key:

~~~powershell
$env:CUSTOS_AGENT_TOKEN = '<copy the research_agent token from Terminal A>'
$env:OPENAI_API_KEY = '<your development key>'
python examples/openai_agents_sdk_custos.py
~~~

The integration test starts `custos_provider.py` as a separate process and configures the gateway to forward signed dispatch permits through `HttpToolProviderAdapter`. The Provider verifies the permit and persists an execution receipt in its own SQLite ledger. The Provider reads only its local synthetic SQLite fixture for the research-read action, using a read-only connection and parameterized bounded search. The fixture is test data, not a production or external database. Provider-owned v1.0.0 contracts validate exact tool input fields before a permit is consumed and validate result fields before a receipt is stored. Approved email actions remain on `MockExecutionAdapter` and are never sent; no external email service is connected. This is a separate local process, not an OS sandbox or container isolation boundary. The SDK tool-call ID is converted into a stable Custos request ID for idempotent retries of the same SDK call.

**Enforcement boundary:** `create_custos_agent()` configures only the three Custos function tools. Do not append raw Python functions, hosted tools, MCP servers, shell/computer tools, handoffs, or other execution surfaces and assume this adapter mediates them. Those surfaces require their own Custos-side gateway or server-side enforcement. This integration demonstrates one framework path; it does not prove that every possible Agent action in a process is mediated.

CI installs the pinned optional dependency and invokes the Agents SDK `FunctionTool` runtime against a local Custos API plus a separate mock Provider process. The integration tests inspect the Provider's independent execution-receipt ledger. These contract tests do not call an OpenAI model or require an API key.

## Contributing\n\nSee [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, engineering expectations, required tests, and security rules. Pull requests use a structured checklist in `.github/PULL_REQUEST_TEMPLATE.md`.\n\n## Feedback and collaboration\n\nGitHub Issues includes structured templates for reproducible bug reports and research/collaboration proposals. Public issues should never include secrets, customer data, or confidential details.\n\n## Automated checks and deployment

GitHub Actions runs:
- Python compilation and unit/API tests.
- JavaScript syntax and browser-console security-wiring checks.
- Corporate website route, canonical URL, sitemap, local-link, bilingual navigation, accessibility, contrast, issue-template, and threat-model checks.
- Deterministic Node-based UI behavior checks for policy decisions, approval/denial, language switching, and keyboard navigation.
- Chromium Playwright checks for all fourteen corporate routes at nine viewport widths (320–1024px), including horizontal-overflow detection, 960px tablet-navigation behavior, mobile keyboard/focus handling, local links, language switching, Media Room preview, and reduced-motion behavior. This is Chromium coverage, not full cross-browser or physical-device certification.
- Optional OpenAI Agents SDK integration contract tests install the pinned `openai-agents==0.24.0` dependency and invoke the actual `FunctionTool` runtime against a local Custos API. These tests do not call a model API; research reads use the synthetic SQLite fixture in read-only mode; approved email execution remains mock-only.
- GitHub Pages deployment when files under `simulation-studio/` change.

## Security and implementation limits

This is **not a production security product**:

- The API has Bearer-token authentication but no TLS, token rotation, individual reviewer identity, MFA, rate limiting, or production deployment configuration.
- It binds to loopback only. Do not expose it to a network or connect it to valuable tools.
- Agent identity is mapped from a configured static token. There is no asymmetric identity, signed request envelope, delegated credential chain, or hardware-backed key protection.
- Approval state is stored in local SQLite. There is no distributed transaction with a downstream tool.
- The separate mock provider verifies key-ID-bound dispatch permits, HMAC-authenticates receipt reads, and stores execution receipts in another local process. A manually configured key ring supports overlapping old/new keys and retirement by removing a key. Gateway and provider startup compare configured key IDs, active IDs, and non-secret SHA-256 fingerprints against local SQLite state, then write register/activate/revoke/replace events to separate hash-chained audit files. This records observed startup configuration changes; it is not a remote revocation service or real-time configuration watcher. It is not an automated KMS/HSM system. Gateway startup also recovers local request receipts left processing, but recovery assumes a single gateway instance. The provider is not an OS sandbox and has no real tool credentials. The ledger provides provider-local at-most-once invocation behavior; a crash after a real downstream side effect but before receipt completion still requires that downstream tool's own idempotency key or status-query reconciliation.
- Raw credential field names are rejected, but this is not general-purpose secret detection. Never place secrets in free-text values.
- The audit log is hash-chained but not immutable against a privileged actor who can rewrite the entire file. Key lifecycle history is local to each component and is not remotely anchored; a privileged host attacker can alter both the SQLite snapshot and its log.
- The Local Control Room uses development tokens. The public page code is part of the credential trust boundary; do not enter production secrets.
- Browser-to-loopback access depends on browser permissions and has not been independently verified across every browser/platform.

## Threat model

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full `/ASSUMPTIONS`, `/BLINDSPOT`, `/COUNTER`, `/EDGECASE`, and `/SELFCRITIQUE` review.

Custos should currently be described as a local research prototype with a synthetic read-only research fixture and mock-only email adapter, not a production enforcement layer.


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
- [Day 012 — Authenticated provider receipt lookups](devlog/day-012.md)
- [Day 013 — Dispatch key-ring rotation](devlog/day-013.md)
- [Day 014 — Key compromise response and lifecycle audit](devlog/day-014.md)
- [Day 015 — Read-only Security Operations](devlog/day-015.md)
- [Day 016 — Human Agency Preservation corporate platform](devlog/day-016.md)
- [Day 017 — Responsive corporate site verification](devlog/day-017.md)
- [Day 018 — OpenAI Agents SDK mediation adapter](devlog/day-018.md)
- [Day 019 — Provider-side authorization registry](devlog/day-019.md)
- [Day 020 — Read-only SQLite research fixture](devlog/day-020.md)
- [Day 021 — Versioned Provider tool contracts](devlog/day-021.md)
- [Day 022 — Machine-readable JSON Schema catalog](devlog/day-022.md)
