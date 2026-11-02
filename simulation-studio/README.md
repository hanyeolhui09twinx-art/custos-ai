# Custos AI — Corporate Website, Simulation Lab, and Local Control Room

## Corporate website

The main GitHub Pages entry point is the bilingual corporate website:

https://hanyeolhui09twinx-art.github.io/custos-ai/

It contains dedicated pages for:
- Home — project overview, control architecture, and interactive policy concept demo
- Platform — request validation, policy decisions, approvals, idempotency, and audit
- Technology — identity, scope, policy, dispatch revalidation, and implementation status
- Security & Trust — implemented controls, limitations, and the five-lens threat model
- Research — research questions, roadmap, and engineering records
- About — project purpose and current prototype status
- Contact — structured bug reports and research/collaboration proposals
- Privacy — data handling for the static site and browser tools
- Terms of Use — usage boundaries and prototype limitations
- Updates — engineering milestones, verification scope, and next gates
- Developer Docs — local API setup, request schema, approval flow, routes, and prototype caveats

The corporate site is static HTML/CSS/JavaScript. It has no hosted application backend and is not a commercial SaaS service.

## Simulation Lab

The original bilingual browser simulator is preserved at:

https://hanyeolhui09twinx-art.github.io/custos-ai/lab.html

It is a browser-only simulation with predefined scenarios, policy decisions, human approval/denial simulations, sequential and Multi-Agent experiments, pause/resume, browser-local history, and trace/report export. It does not call real agents or external tools.

## Local Control Room

The separate Local Control Room is at:

https://hanyeolhui09twinx-art.github.io/custos-ai/local-console.html

It connects to a Python API that must be running on the user's own computer.

### Start the local API

Requires Python 3.10+. In PowerShell, from the repository root, create temporary development tokens:

~~~powershell
$agentToken = python -c "import secrets; print(secrets.token_urlsafe(32))"
$reviewerToken = python -c "import secrets; print(secrets.token_urlsafe(32))"
$env:CUSTOS_AGENT_TOKENS = '{"research_agent":"' + $agentToken + '"}'
$env:CUSTOS_REVIEWER_TOKEN = $reviewerToken
Write-Host "Agent token: $agentToken"
Write-Host "Reviewer token: $reviewerToken"
python custos_api.py
~~~

Keep the terminal open. Enter the two tokens into the matching fields in the Local Control Room and select **Test connection**. The browser may ask for Loopback network permission for the Custos GitHub Pages origin.

Tokens are not intentionally persisted by the console, but the public page is still part of the credential trust path. Use temporary development tokens only; never use production credentials.

### Important technical boundaries

- The local API binds to loopback only and rejects remote binding.
- CORS is limited to the official Custos GitHub Pages origin.
- The local backend uses a mock execution adapter. It does not access a real database or send email.
- The hosted Simulation Lab and corporate website do not run the Python backend.
- The current prototype is not production security software.

## Feedback and collaboration

The Contact page links to structured GitHub issue forms for:
- Reproducible bug reports (steps, expected behavior, actual behavior, environment)
- Research and collaboration proposals (question, approach, evidence, and contribution area)

Public issues must not contain credentials, customer data, or confidential information.

See the root README for API routes and docs/THREAT_MODEL.md for assumptions, blind spots, counterarguments, edge cases, and self-critique.


## Contribution guide

See the repository root's CONTRIBUTING.md for local setup, engineering standards, test commands, and security expectations. Pull requests use .github/PULL_REQUEST_TEMPLATE.md.
