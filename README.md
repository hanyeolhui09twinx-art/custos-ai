# Custos AI

**An independent control and visibility layer for autonomous AI.**

**Never trust. Always verify.**

Custos is an early-stage defensive prototype exploring how autonomous AI actions can be independently verified before execution, while making security decisions visible to humans.

## Current prototype

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
├── custos_gateway.py
├── custos_security_gateway.py
├── threat_actor_engine.py
├── custos_policy.json
├── custos_policy.lock
├── audit_log.py
├── demo_security.py
├── tests/
│   ├── test_custos_gateway.py
│   ├── test_custos_security_gateway.py
│   └── test_threat_actor_engine.py
└── devlog/
    ├── day-001.md
    ├── day-003.md
    ├── day-004.md
    └── day-005.md
```

Runtime artifacts such as local databases, audit logs, and outbox files are intentionally not committed.

## Run

```bash
python -m unittest discover -s tests -p 'test_*.py' -v
python demo_security.py
```

## Important limitations

This is a local research prototype, not a production security product. Identity/key management, execution isolation, durable approvals, telemetry ingestion, policy management, threat intelligence, and adversarial testing against real autonomous-agent environments are still incomplete.
