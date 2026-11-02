# Contributing to Custos AI

Thank you for considering a contribution.

Custos is an early-stage research project exploring an independent authorization layer for autonomous AI agents. Contributions should improve the clarity, correctness, testability, or security boundaries of the prototype without overstating what it can currently enforce.

## Current project boundaries

- The public website and Simulation Lab are static/browser-side interfaces.
- The Python gateway runs locally and binds to loopback by default.
- The only execution adapter is a mock. It does not access a real database, send email, or call external tools.
- The current token model is for local development, not production identity management.
- Passing tests does not prove that a real autonomous agent cannot bypass the gateway.

Do not describe the project as production-ready security software or claim capabilities that are not implemented and tested.

## Before making a change

1. Read the root README and the relevant engineering notes.
2. For security-related work, read SECURITY.md and docs/THREAT_MODEL.md.
3. Open or reference a GitHub issue when the change is more than a small correction.
4. Keep the change focused and explain the threat model or user problem it addresses.

## Local setup

Requires Python 3.10+ and Node.js 22 for all repository checks.

Run the Python unit/API tests:

~~~bash
python -m unittest discover -s tests -v
~~~

Run the browser console source checks:

~~~bash
node tests/check_studio_console.js
~~~

Run the corporate website route, content, and interaction checks:

~~~bash
node tests/check_corporate_site.js
~~~

The same commands run in GitHub Actions on pushes and pull requests to main.

## Engineering expectations

### Python gateway and API

- Preserve deny-by-default behavior.
- Derive agent identity from authenticated credentials; do not trust an agent ID supplied by the request body.
- Validate request shape, payload bounds, and idempotency behavior.
- Re-check current policy at the execution boundary.
- Preserve single-use approval claims and requester binding.
- Treat crashes, retries, duplicate requests, concurrency, and partial failures as first-class test cases.
- Never connect a real tool merely by replacing the mock adapter. Authorization must be enforced by the actual tool adapter, and direct bypass paths must be tested in an isolated environment.

### Audit and security

- Do not log raw credentials, access tokens, personal information, or customer data.
- Do not weaken the audit chain or silently suppress integrity failures.
- A local hash chain is not immutable storage; document its limits.
- Security changes should update tests, SECURITY.md, or docs/THREAT_MODEL.md when the threat assumptions change.

### Website and documentation

- Keep Korean and English content in sync for shared page controls.
- Preserve canonical URLs, descriptive metadata, keyboard navigation, and working local links.
- Keep the sitemap and route validation tests in sync when adding pages.
- Do not invent customers, certifications, deployments, legal status, or performance claims.
- Update the relevant development log when a meaningful engineering milestone is completed.

## Pull request checklist

Before requesting review, confirm that:

- The change has a clear problem statement and limited scope.
- Relevant Python and Node checks pass.
- New behavior has regression tests.
- Security assumptions and remaining limitations are documented.
- Public documentation accurately describes what is implemented and what is simulated.
- No tokens, secrets, customer data, personal data, or confidential details are included.
- The PR does not claim production guarantees that the code does not provide.

## Reporting security issues

Do not publish exploit instructions or sensitive vulnerability details in a public issue. Follow [SECURITY.md](SECURITY.md) and use a private reporting path only if GitHub makes it available for this repository.

## License and contribution terms

Before submitting code, review the repository's license and ensure that you have the right to contribute the material. Do not submit third-party code or assets without compatible permissions.
