# Custos AI Simulation Studio (Browser Edition)

한국어 / English 지원 독립 실행형 시뮬레이터입니다.

## Open

Open `index.html` in a modern browser. No Python, Node.js, package installation, or local server is required.

## Included

- Korean and English interface switching
- 13 predefined policy scenarios
- Agent identity, action, resource, scope, and policy decision simulation
- Human approval and denial flows
- Sequential experiment builder
- Multi-Agent interaction and conflict simulation
- Pause/resume controls and browser-local run history
- Trace and report export

## Important boundary

This is a **browser-only simulation sandbox**. It does not connect to the Custos Python gateway, real agents, local Workers, external APIs, email systems, or production databases. All actions and side effects are simulated in the page. Run history and language preference may be stored in the current browser's local storage.

The browser edition is intended for exploration and demonstrations. It is not a production security control or a substitute for the server-side execution and authorization checks.

## Files

- `index.html` — complete self-contained bilingual application
- `SHA256SUMS.txt` — SHA-256 checksum for the HTML file
