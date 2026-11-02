# Custos AI — Threat Model and Engineering Self-Critique

This document describes the current v0.2 prototype boundary. It is intentionally conservative: a passing test suite is evidence for tested behavior, not proof that Custos cannot be bypassed.

## /ASSUMPTIONS — What the prototype assumes

1. Every privileged agent tool call is routed through the Custos gateway. An agent that can reach a database, email provider, shell, or cloud API directly can bypass this prototype.
2. The operator securely provisions agent and reviewer Bearer tokens and does not commit, log, screenshot, or disclose them.
3. The machine, Python process, operating system account, SQLite database, and audit-log directory are trusted.
4. The HTTP API runs on loopback only. The current service is not designed to be exposed to another machine or the public internet.
5. The configured policy is the authority for the current demonstration. Policies are code-defined; there is no remote policy administration service.
6. The mock adapter is the only execution implementation. It performs no external side effect.

## /BLINDSPOT — What is not protected yet

- **Credential lifecycle:** Bearer tokens are static environment configuration. There is no token expiry, automated rotation, per-tool credential, asymmetric agent identity, key revocation service, or signed request envelope. The browser console does not persist pasted tokens, but its public JavaScript is still in the credential trust path; only development tokens belong there.
- **Secret detection:** common credential-looking parameter key names are rejected before persistence. This is not general-purpose DLP and cannot reliably detect secrets hidden in arbitrary free-text values.
- **Human identity:** The reviewer is represented by one shared token and a fixed reviewer label. There are no individual reviewer accounts, role separation, MFA, quorum approval, or reviewer audit identity verification.
- **Policy administration:** There is no signed policy bundle, policy version approval, policy rollback workflow, or policy-integrity monitor.
- **Tool boundary:** The mock delegate now has an exact `(action, resource)` handler registry, but it still does not prove that a real tool cannot be called directly. The registry and its handlers live in the same trusted Python process. A real provider must enforce authorization at the provider boundary, with scoped credentials that agent code cannot access, rather than trusting a prior UI decision.
- **Dispatch capability lifecycle:** The local guarded adapter now requires a 15-second HMAC-signed permit bound to the exact request digest. It re-checks current policy and, for approval-backed dispatch, the exact SQLite row in `executing` state. Nonce replay tracking is in process memory and is not shared across workers or restarts. The signing key is ephemeral per process. These are prototype controls, not a production key-management or distributed replay service.
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

The local prototype now includes deny-by-default policy evaluation, strict request validation, bearer-token identity mapping, SQLite-persisted approvals, approval expiry, requester binding, single-use execution claims, request idempotency, a hash-chained local audit trail, and a guarded adapter boundary, and an exact action/resource registry in the mock delegate. The boundary requires a 15-second HMAC-signed permit bound to the exact request digest; it consumes the permit once, re-evaluates current policy, and verifies an approval-backed SQLite execution claim before invoking the configured delegate. The mock registry refuses unregistered action/resource pairs even when called directly.

The tests exercise these behaviors, including concurrent approval execution, modified approval payloads, CORS origin restrictions, oversized/deep JSON rejection, raw credential field rejection, forged, malformed, expired, sequentially and concurrently replayed dispatch permits, policy changes at the adapter boundary (including a last-moment policy change that returns BLOCK), approval-ID/request binding, and direct calls to unregistered mock tool pairs. The CI result only says that these specific automated tests passed in GitHub's runner. It does not demonstrate resistance to unknown attacks, production load, compromised hosts, malicious adapters, or direct agent-to-tool bypass. Python in-process object boundaries are not a sandbox: code with access to the gateway process, signing authority, or underlying delegate can bypass conventions such as underscore-prefixed attributes.

The most important missing proof is an end-to-end test with a real agent framework and an isolated tool sandbox, where the agent has no alternate path to the tool. Until that exists, Custos should be described as a local research prototype with a mock execution adapter, not a production enforcement layer.

## Next verification gates

1. Add a dedicated local console or safely connect the browser interface to the local API without exposing credentials to a public page.
2. Connect one real agent framework to an isolated tool sandbox where the agent never receives the raw tool client or credentials; test direct-call bypass at the tool provider boundary.
3. Add request-receipt recovery/retention and crash reconciliation.
4. Replace shared static reviewer credentials with individual authenticated reviewer identities and roles.
5. Add signed, versioned policy bundles and explicit key rotation/revocation.
6. Store audit events remotely with independent integrity anchoring.
7. Commission an independent security review before production use.
