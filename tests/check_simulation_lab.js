const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const assert = require("node:assert/strict");

const root = path.resolve(__dirname, "..");
const lab = fs.readFileSync(path.join(root, "simulation-studio", "lab.html"), "utf8");
const scriptMatches = [...lab.matchAll(/<script>([\\s\\S]*?)<\\/script>/gi)];
assert.equal(scriptMatches.length, 1, "Simulation Lab should keep one self-contained script.");
const source = scriptMatches[0][1];
new vm.Script(source, { filename: "simulation-lab-inline.js" });

function between(startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.ok(start >= 0 && end > start, `Missing source boundary: ${startMarker}`);
  return source.slice(start, end);
}

function makeState(overrides = {}) {
  return {
    runs: [],
    gate: true,
    approval: true,
    strict: true,
    paused: false,
    policies: {
      read_database: "allow",
      send_email: "approval",
      generate_report: "allow",
      delete_record: "deny",
      modify_policy: "deny",
      execute_shell: "deny"
    },
    agents: {
      researcher: {
        name: "Research Agent",
        status: "active",
        scopes: ["read_database:research_db", "generate_report:analytics_workspace"]
      },
      operator: {
        name: "Operator Agent",
        status: "active",
        scopes: ["send_email:company_email"]
      },
      analyst: {
        name: "Analyst Agent",
        status: "active",
        scopes: ["read_database:research_db"]
      }
    },
    ...overrides
  };
}

const decideSource = between("function decide(", "function scenarioById(");
function evaluate(state, request) {
  const context = {
    state,
    now: () => "2026-11-03T00:00:00.000Z",
    uid: () => "LAB-TEST-ID"
  };
  vm.runInNewContext(decideSource, context, { filename: "simulation-lab-decide.js" });
  return context.decide(request);
}

assert.equal(
  evaluate(makeState(), { agent: "researcher", action: "read_database", resource: "research_db" }).decision,
  "ALLOW",
  "A scoped read request should be allowed."
);
assert.equal(
  evaluate(makeState(), { agent: "operator", action: "send_email", resource: "company_email" }).decision,
  "PENDING_APPROVAL",
  "A high-impact action should pause for human approval when the control is enabled."
);
assert.equal(
  evaluate(makeState({ approval: false }), { agent: "operator", action: "send_email", resource: "company_email" }).decision,
  "ALLOW",
  "The simulator's global approval switch should disable the approval requirement for a fresh evaluation."
);
assert.equal(
  evaluate(makeState({ gate: false }), { agent: "researcher", action: "read_database", resource: "research_db" }).decision,
  "STOPPED",
  "A closed execution gate should stop new requests."
);
assert.equal(
  evaluate(makeState(), { agent: "researcher", action: "read_database", resource: "production_db" }).decision,
  "BLOCK",
  "An out-of-scope resource must be blocked."
);
assert.equal(
  evaluate(makeState({ agents: { ...makeState().agents, researcher: { ...makeState().agents.researcher, status: "suspended" } } }), { agent: "researcher", action: "read_database", resource: "research_db" }).decision,
  "BLOCK",
  "A suspended agent must be blocked."
);
const strictState = makeState();
strictState.agents.researcher.scopes.push("unlisted_action:unlisted_resource");
assert.equal(
  evaluate(strictState, { agent: "researcher", action: "unlisted_action", resource: "unlisted_resource" }).decision,
  "BLOCK",
  "Unknown actions should default to deny when strict mode is enabled, even when the scope exists."
);
strictState.strict = false;
assert.equal(
  evaluate(strictState, { agent: "researcher", action: "unlisted_action", resource: "unlisted_resource" }).decision,
  "ALLOW",
  "Disabling strict mode should use the configured permissive fallback only for explicitly scoped requests."
);

const reviewSource = between("function reviewRun(", "function wirePending(");
function runReview({ approval = true, gate = true, policy = "approval", decision = "approve" } = {}) {
  const state = makeState({ approval, gate });
  state.policies.send_email = policy;
  const run = {
    id: "PENDING-1",
    decision: "PENDING_APPROVAL",
    agent: "operator",
    action: "send_email",
    resource: "company_email",
    traces: []
  };
  state.runs.push(run);
  const context = {
    state,
    pending: null,
    selectedRun: null,
    updateRun: () => {},
    renderPendingResult: () => {},
    showRun: () => {},
    toast: () => {},
    now: () => "2026-11-03T00:00:00.000Z"
  };
  vm.runInNewContext(reviewSource, context, { filename: "simulation-lab-review.js" });
  context.reviewRun("PENDING-1", decision);
  return run;
}
const approved = runReview();
assert.equal(approved.decision, "ALLOW", "A valid pending request should be approvable.");
assert.ok(approved.traces.some(t => t.name === "Final revalidation"), "Approval must append a final revalidation trace.");
assert.ok(approved.traces.some(t => t.name === "Dispatch simulation"), "Approved simulation must record mock dispatch.");
assert.equal(runReview({ approval: false }).reason, "FINAL_REVALIDATION_FAILED", "Turning off mandatory approval while a request is pending must invalidate that approval path.");
assert.equal(runReview({ gate: false }).reason, "FINAL_REVALIDATION_FAILED", "A paused gate must prevent approval from proceeding to simulated dispatch.");
assert.equal(runReview({ policy: "allow" }).reason, "FINAL_REVALIDATION_FAILED", "A changed policy must invalidate the old approval path.");
assert.equal(runReview({ decision: "deny" }).reason, "HUMAN_DENIED", "A denied request must remain unexecuted.");

const scenarioSource = between("function runScenario(", "function reviewRun(");
function runScenarioCase({ paused = false, researcherStatus = "active", scenario }) {
  const state = makeState({ paused });
  state.agents.researcher.status = researcherStatus;
  const elements = {
    "#scenarioParams": { value: "{}" },
    "#scenarioAgent": { value: "researcher" },
    "#scenarioResource": { value: scenario.resource },
    "#requestId": { value: "SCENARIO-TEST" },
    "#scenarioRunId": { textContent: "" },
    "#scenarioResult": { className: "", innerHTML: "" }
  };
  const context = {
    state,
    selectedScenario: scenario.id,
    pending: null,
    scenarioById: () => scenario,
    decide: (request) => {
      const decisionContext = {
        state,
        now: () => "2026-11-03T00:00:00.000Z",
        uid: () => "LAB-TEST-ID"
      };
      vm.runInNewContext(decideSource, decisionContext);
      return decisionContext.decide(request);
    },
    $: selector => elements[selector],
    uid: () => "SCENARIO-RUN-ID",
    now: () => "2026-11-03T00:00:00.000Z",
    record: run => state.runs.unshift(run),
    resultHtml: () => "<div>result</div>",
    wirePending: () => {},
    toast: () => {}
  };
  vm.runInNewContext(scenarioSource, context, { filename: "simulation-lab-run-scenario.js" });
  context.runScenario();
  return { state, run: state.runs[0] };
}

const pausedScenario = runScenarioCase({
  paused: true,
  scenario: { id: "paused", name: "Paused", action: "read_database", resource: "research_db", gate: "paused" }
});
assert.equal(pausedScenario.run.decision, "STOPPED");
assert.equal(pausedScenario.state.paused, true, "A temporary paused scenario must preserve a pre-existing global pause.");

const suspendedScenario = runScenarioCase({
  researcherStatus: "suspended",
  scenario: { id: "suspended", name: "Suspended", action: "read_database", resource: "research_db", agent: "suspended" }
});
assert.equal(suspendedScenario.run.decision, "BLOCK");
assert.equal(suspendedScenario.state.agents.researcher.status, "suspended", "A scenario must not silently reinstate a previously suspended agent.");

const longScenario = runScenarioCase({
  scenario: { id: "long", name: "Long operation", action: "generate_report", resource: "analytics_workspace", long: true }
});
assert.equal(longScenario.run.decision, "STOPPED");
assert.ok(longScenario.run.traces.some(t => t.name === "Long-running operation"), "Long-running simulation must record entry into a running state.");
assert.ok(!longScenario.run.traces.some(t => t.name === "Dispatch simulation"), "A stopped long-running operation must not claim it completed before the stop checkpoint.");

assert.ok(source.includes("id=\"approveHistory\"") && source.includes("id=\"denyHistory\""), "Run History must expose approval actions for persisted pending requests.");
assert.ok(source.includes("DETERMINISTIC EVALUATION"), "Multi-Agent UI must identify its deterministic evaluation model.");
assert.ok(source.includes("실제 병렬 실행, 경쟁 상태, 동시 승인, 분산 트랜잭션을 시험하지 않습니다."), "Multi-Agent UI must disclose that it does not run real concurrency tests.");
assert.ok(source.includes("state.approval&&state.agents.operator.status==='active'"), "Sequential experiments must re-check the global approval switch.");
console.log("Simulation Lab checks passed: policy decisions, approval revalidation and persistence, temporary scenario state, long-run traces, and concurrency disclosures.");
