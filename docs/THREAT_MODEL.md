# Custos AI — Threat Model and Engineering Self-Critique

This document describes the current v0.2 prototype boundary. It is intentionally conservative: a passing test suite is evidence for tested behavior, not proof that Custos cannot be bypassed.

## /ASSUMPTIONS — What the prototype assumes

1. Every privileged agent tool call is routed through the Custos gateway. An agent that can reach a database, email provider, shell, or cloud API directly can bypass this prototype.
2. The operator securely provisions agent and reviewer Bearer tokens and does not commit, log, screenshot, or disclose them.
3. The machine, Python process, operating system account, SQLite database, and audit-log directory are trusted.
4. The HTTP API runs on loopback only. The current service is not designed to be exposed to another machine or the public internet.
5. The configured policy is the authority for the current demonstration. Policies are code-defined; there is no remote policy administration service.
6. The only tool implementation is still a mock adapter with no external side effect. An optional loopback Tool Provider process owns that mock registry.

## /BLINDSPOT — What is not protected yet

- **Credential lifecycle:** Bearer tokens are static environment configuration. There is no token expiry, automated rotation, per-tool credential, asymmetric agent identity, key revocation service, or signed request envelope. The browser console does not persist pasted tokens, but its public JavaScript is still in the credential trust path; only development tokens belong there.
- **Secret detection:** common credential-looking parameter key names are rejected before persistence. This is not general-purpose DLP and cannot reliably detect secrets hidden in arbitrary free-text values.
- **Human identity:** The reviewer is represented by one shared token and a fixed reviewer label. There are no individual reviewer accounts, role separation, MFA, quorum approval, or reviewer audit identity verification.
- **Policy administration:** There is no signed policy bundle, policy version approval, policy rollback workflow, or policy-integrity monitor.
- **Tool boundary:** The gateway can now send a signed permit and exact request to a separate loopback Tool Provider process. That process independently verifies the HMAC, request digest, validity window, and one-time nonce; its SQLite nonce ledger is durable across provider restarts and atomically rejects concurrent replay. Its only handler registry is still the mock adapter, with no database/email client or external credentials. This is a same-host process-separation test, not an OS sandbox: local HTTP is unauthenticated apart from the signed permit, the two processes share a development HMAC key, and a privileged host attacker can inspect or alter both. A real provider needs process/container isolation, separate service identity, authenticated transport, scoped tool credentials unavailable to agent code, and enforcement at the actual side-effect boundary.
- **Dispatch capability lifecycle:** The gateway requires a 15-second HMAC-signed permit bound to the exact request digest and re-checks current policy and, for approval-backed dispatch, the exact SQLite row in `executing` state. When the separate provider is configured, it independently validates the permit and atomically records its nonce in a provider-side SQLite ledger that survives provider restarts. The gateway still has an in-memory consumer, and the provider key is shared through local environment configuration. There is no key rotation, KMS, mutual TLS, distributed policy version, or high-availability replay service.
- **Distributed execution:** The SQLite store coordinates one local service instance. There is no distributed lock, queue, cross-region consistency, or transaction shared with a downstream tool.
- **Audit storage:** The JSONL hash chain detects edits that break the recorded chain. It is not immutable; an attacker who can rewrite the whole file can recompute the hashes. There is no remote/WORM copy, independent signing key, or external timestamp anchor.
- **Browser integration:** GitHub Pages hosts a separate static simulation. It does not call the local API. The hosted page is not a remote dashboard for this backend.
- **Operational controls:** There is no rate limiting, alert delivery, service supervision, backup/restore procedure, metrics, tracing, retention policy, or automated receipt cleanup.

## /COUNTER — Strong counterarguments to the design

1. **Custos can become the new single point of failure.** If the gateway host, reviewer credential, or policy source is compromised, the control layer may be subverted. The gateway itself needs isolation, least privilege, independent monitoring, and a recovery strategy.
2. **A request label is not proof of an action.** An agent can call a request read_database, but a faulty or malicious adapter could perform a different operation. Authorization must be checked against the actual tool, arguments, target, and side effect at dispatch time.
3. **Human approval is not automatically meaningful oversight.** Reviewers can rubber-stamp prompts, misunderstand context, or be socially engineered. Approval screens need bounded, structured context and reviewer accountability.
4. **Static deny/allow rules can be wrong.** They can block legitimate work or allow risky work that happens to match a permitted action/resource pair. Policy quality needs domain review and adversarial tests.
5. **A hash chain is not a tamper-proof audit system.** It offers integrity evidence against ordinary edits, not protection against a privileged attacker who controls the file and implementation.

## /EDGECASE — Cases the tests should continue to pressure

- A client retries the same request after a timeout. A stable request_id returns the cached result; a different payload with that same ID conflicts.
- Two workers attempt to execute one approval concurrently. The SQLite state transition permits only one execution claim.
- A reviewer denies an approval. The cached request result is updated so a same-ID retry reports the denied state.
- An approval expires before review or execution. It must not be executed.
- The requester identity differs from the identity bound to the approval. Execution is rejected.
- Policy scope changes after approval. The dispatch-time policy check blocks the action if current policy denies it.
- The stored approval payload changes. The payload digest check rejects it before execution is claimed.
- A process crashes while a request receipt is marked processing. In this version, the key remains locked and requires operator investigation; it is not automatically reclaimed.
- A process crashes after a real external tool succeeds but before Custos records completion. This outcome could be uncertain. Production adapters need downstream idempotency keys and a reconciliation/status-query mechanism.
- A request contains a raw credential under a common sensitive field name. It should be rejected; a managed reference such as credential_ref can be passed instead. Secret strings hidden in ordinary text are not detected.
- The machine clock moves or is incorrect. Approval expiry depends on the local wall clock; production needs a trusted time source and clock-skew policy.
- The audit file is truncated, replaced, or rewritten by a privileged actor. The current local hash chain cannot independently recover the lost history.

## /SELFCRITIQUE — What this version does and does not prove

The local prototype now includes deny-by-default policy evaluation, strict request validation, bearer-token identity mapping, SQLite-persisted approvals, approval expiry, requester binding, single-use execution claims, request idempotency, a hash-chained local audit trail, and a guarded adapter boundary with an exact action/resource registry. In optional separate-provider mode, a second local process independently verifies the 15-second HMAC permit and uses a durable SQLite nonce ledger before invoking that mock registry. The gateway re-evaluates current policy and verifies an approval-backed SQLite execution claim before forwarding the permit.

The tests also launch the mock provider as a separate operating-system process and check normal ALLOW and human-approved dispatch, missing/forged permits, request substitution, concurrent replay, replay rejection after provider restart, non-loopback endpoint rejection, and fail-closed behavior during provider outage. The gateway's exact mock handler registry also rejects unregistered action/resource pairs when called directly. These tests exercise a same-host process boundary, not a security sandbox. CI passing would show only that these defined scenarios passed on the runner; it would not demonstrate resistance to unknown attacks, production load, compromised hosts, malicious adapters, or direct agent-to-real-tool bypass.

The most important missing proof is an end-to-end test with a real agent framework and an OS-isolated tool runtime, where the agent has no alternate route to the actual tool or credentials. The current provider is another local process on the same trusted machine and still invokes only a mock adapter. Until that proof exists, Custos should be described as a local research prototype, not a production enforcement layer.

## Next verification gates

1. Place the provider in an OS/container boundary with a dedicated service identity and authenticated transport; keep tool credentials out of the agent and gateway processes.
2. Connect one real agent framework and one non-production tool, then prove there is no alternate direct-call route.
3. Add downstream idempotency and crash reconciliation for the case where a tool succeeds but its response is lost.
4. Add request-receipt recovery/retention and provider health supervision.
5. Replace shared static reviewer credentials with individual authenticated reviewer identities and roles.
6. Add signed, versioned policy bundles, key rotation/revocation, and remote audit anchoring.
7. Commission an independent security review before production use.
