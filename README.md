# Custos AI

**An independent control and visibility layer for autonomous AI.**

**Never trust. Always verify.**

Custos is an early-stage defensive prototype exploring how autonomous AI actions can be independently verified before execution, while making security decisions visible to humans.

## Browser Simulation Studio (Korean / English)

A self-contained browser edition is available in [`simulation-studio/`](simulation-studio/).

Open [`simulation-studio/index.html`](simulation-studio/index.html) in a modern browser. It requires no Python, Node.js, package installation, or local server.

The browser edition includes 13 preset scenarios, policy and authority decision simulations, human approval/denial flows, sequential experiments, Multi-Agent conflict simulations, pause/resume controls, and browser-local run history.

**Boundary:** this is a browser-only sandbox. It does not connect to real agents, the Python gateway, local Workers, external APIs, email systems, or production databases. All actions are simulated. See [the browser edition guide](simulation-studio/README.md).

## Current server-side prototype

The control gateway evaluates an autonomous AI request through multiple checks:

1. ingress authorization
2. policy integrity
3. request freshness
4. whole-request identity/signature verification
5. action/resource scope verification
6. pre-execution re-check
7. final dispatch-time re-check
8. post-execution result validation

Decisions are:

- `ALLOW` — execution may proceed after the required checks
- `HUMAN_APPROVAL` — execution pauses for explicit human approval
- `BLOCK` — execution is stopped

Stage 5 adds a broader security visibility layer for human, AI, and external actors. It evaluates observable signals such as compromised identities, repeated authentication failures, policy-violation history, suspicious behaviors, sensitive targets, and attempts to disable Custos. Suspicious activity can generate `ALERT`; high-confidence or explicitly denied threat states are `BLOCK`ed.

Custos does **not** treat someone as malicious simply because their actor type is `HUMAN` or because they are a security researcher. The prototype evaluates the current identity and observable behavior instead.

## Repository layout

```text
custos-ai/
├── simulation-studio/
│   ├── index.html
│   ├── README.md
│   └── SHA256SUMS.txt
├── custos_gateway.py
├── audit_log.py
├── devlog/
└── tests/
```

Runtime artifacts such as local databases, audit logs, and outbox files are intentionally not committed.

## Run the server-side prototype

```bash
python -m unittest discover -s tests -p 'test_*.py' -v
python demo_security.py
```

## Important limitations

This is a local research prototype, not a production security product. Identity/key management, execution isolation, durable approvals, telemetry ingestion, policy management, threat intelligence, and adversarial testing against real autonomous-agent environments are still incomplete. The browser simulation is illustrative and does not provide the server-side security guarantees.
