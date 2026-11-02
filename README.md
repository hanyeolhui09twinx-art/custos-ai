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

- `custos_gateway.py` — deny-by-default policy evaluation, strict request validation, SQLite-backed approval state, request idempotency, dispatch-time policy re-check, and mock execution adapter.
- `custos_api.py` — authenticated local HTTP API. It binds to loopback and allows browser CORS only from the official Custos GitHub Pages origin.
- `audit_log.py` — local JSONL events linked by a SHA-256 hash chain.
- `tests/test_custos.py` — policy, approval lifecycle, replay, API authentication, concurrency, CORS, and audit-integrity tests.

Demonstration policy:

| Agent | Action | Resource | Result |
|---|---|---|---|
| `research_agent` | `read_database` | `research_db` | ALLOW (mock execution) |
| `research_agent` | `send_email` | `company_email` | HUMAN_APPROVAL, then mock execution |
| Any configured agent | `disable_custos`, `modify_custos_policy`, `delete_audit_log` | Any | BLOCK |

Unknown agents, unlisted actions, and out-of-scope resources are denied by default. The mock adapter does not access a real database, send email, or call external tools.

### 2. Browser Simulation Lab

The original bilingual browser simulation is preserved at [Simulation Lab](https://hanyeolhui09twinx-art.github.io/custos-ai/lab.html). It includes predefined scenarios, sequential and Multi-Agent simulations, policy traces, and browser-local experiment history. Its actions remain simulated inside the browser.

### 3. Local Control Room

The [Local Control Room](https://hanyeolhui09twinx-art.github.io/custos-ai/local-console.html) can call the Python API on the user's own computer. The page keeps entered tokens in memory rather than localStorage and requires browser Loopback network permission in supported browsers.

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

Clients should send a stable `request_id` and reuse it when retrying the same logical operation. An exact retry returns the cached result and does not dispatch a second time. Reusing the same ID with a different payload returns a conflict. Receipts left in `processing` after a process crash are not automatically reclaimed in this version and require operator investigation.

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
- The mock execution adapter does not prove that a real tool cannot be called directly. A production adapter must enforce authorization at the actual tool boundary.
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
