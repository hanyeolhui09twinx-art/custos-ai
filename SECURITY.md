# Security Policy

## Project status

Custos AI is an early-stage independent research project. The current Python gateway uses a mock execution adapter and is not a production security service. There is no formal security operations team, paid bug bounty, guaranteed response window, or service-level agreement.

## Where to report a vulnerability

1. Open the repository's [GitHub Security page](https://github.com/hanyeolhui09twinx-art/custos-ai/security).
2. If GitHub shows a **Report a vulnerability** or private vulnerability reporting option, use that private route and include only the details necessary for responsible investigation.
3. If private reporting is not enabled or is not available to you, do not publish exploit steps, proof-of-concept code, credentials, customer data, or other sensitive details in a public issue. You may open a minimal non-sensitive issue asking for a private reporting channel, without describing the vulnerability itself.

The availability of GitHub's private reporting option depends on repository settings and is not guaranteed by this policy.

## Scope

This policy covers security issues in:
- Source code in this repository.
- The static Custos GitHub Pages website and its published browser tools.
- The local Python API and gateway when run in the documented loopback-only prototype configuration.

The policy does not authorize testing against systems, accounts, networks, or data that you do not own or have explicit permission to test.

## Safe testing expectations

- Use an isolated local environment and temporary development credentials.
- Do not access, modify, destroy, or exfiltrate another person's data.
- Do not attempt denial-of-service testing against GitHub Pages or GitHub infrastructure.
- Do not place secrets, tokens, personal information, or customer data in public issues, screenshots, logs, or pull requests.
- Stop testing if you encounter data or systems that are not yours.

## Response and disclosure

Reports will be reviewed on a best-effort basis as project capacity allows. No response time, fix timeline, bounty, or coordinated disclosure agreement is promised. Please allow an opportunity to review and address a privately reported issue before public disclosure.

## Current security limitations

The project is not production-ready. The local API uses static development Bearer tokens, a shared reviewer credential, loopback-only HTTP, SQLite local state, a local hash-chained audit log, and a mock execution adapter. Real agent integration, tool-boundary enforcement, production credential management, remote immutable audit storage, independent security review, and operational monitoring are not yet in place.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and the [Security & Trust page](https://hanyeolhui09twinx-art.github.io/custos-ai/security.html) for the current design assumptions and limitations.
