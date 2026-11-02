const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.resolve(__dirname, "..");
const site = path.join(root, "simulation-studio");
const corporatePages = [
  "index.html", "platform.html", "technology.html", "security.html",
  "research.html", "company.html", "contact.html", "privacy.html", "terms.html", "updates.html", "developers.html", "404.html"
];
const toolPages = ["lab.html", "local-console.html"];
const allPages = [...corporatePages, ...toolPages];
const available = new Set(fs.readdirSync(site));
const missing = allPages.filter(file => !available.has(file));
if (missing.length) throw new Error("Missing site page(s): " + missing.join(", "));

for (const asset of ["corporate.css", "corporate.js", "favicon.svg", "robots.txt", "sitemap.xml"]) {
  if (!available.has(asset)) throw new Error("Missing corporate asset: " + asset);
}

for (const file of allPages) {
  const html = fs.readFileSync(path.join(site, file), "utf8");
  if (!/<title>[^<]+<\/title>/i.test(html)) throw new Error(file + ": missing title");
  if (!/name="description"/i.test(html)) throw new Error(file + ": missing meta description");
  if (!/<html lang="(?:ko|en)"/i.test(html)) throw new Error(file + ": missing document language.");
  if (corporatePages.includes(file) && (html.match(/<h1\b/gi) || []).length !== 1) throw new Error(file + ": expected exactly one primary h1 heading.");
  for (const imageTag of (html.match(/<img\b[^>]*>/gi) || [])) {
    if (!/\balt="/i.test(imageTag)) throw new Error(file + ": image missing alternative text.");
  }
  for (const anchor of (html.match(/<a\b[^>]*target="_blank"[^>]*>/gi) || [])) {
    if (!/\brel="[^"]*(?:noopener)[^"]*"/i.test(anchor)) {
      throw new Error(file + ": new-tab links must include rel=noopener.");
    }
  }
  if (file !== "404.html" && (!/rel="canonical"/.test(html) || !/rel="icon"/.test(html))) {
    throw new Error(file + ": missing canonical URL or branded favicon");
  }
  if (file !== "404.html") {
    const canonical = file === "index.html"
      ? "https://hanyeolhui09twinx-art.github.io/custos-ai/"
      : "https://hanyeolhui09twinx-art.github.io/custos-ai/" + file;
    if (!html.includes('rel="canonical" href="' + canonical + '"')) {
      throw new Error(file + ": canonical URL does not match the published route.");
    }
  }

  if (corporatePages.includes(file)) {
    if (!/href="\.\/corporate\.css"/.test(html)) throw new Error(file + ": missing shared stylesheet");
    if (!/src="\.\/corporate\.js"/.test(html)) throw new Error(file + ": missing shared script");
    if (!/data-lang-button="ko"/.test(html) || !/data-lang-button="en"/.test(html)) {
      throw new Error(file + ": missing bilingual language controls");
    }
    if (!/class="skip-link"/.test(html) || !/id="main-content"/.test(html)) {
      throw new Error(file + ": missing keyboard skip link or main landmark");
    }
    if (file !== "404.html" && !html.includes('href="./terms.html"')) {
      throw new Error(file + ": global footer is missing Terms of Use.");
    }
    if (file !== "404.html") {
      if (!/aria-controls="mobile-navigation"/.test(html) || !/id="mobile-navigation"/.test(html)) {
        throw new Error(file + ": mobile menu button and navigation are not programmatically connected");
      }
      if (!html.includes('data-ko="플랫폼"') || !html.includes('data-en="Platform"')) {
        throw new Error(file + ": mobile navigation's primary links must be bilingual.");
      }
      if (!/rel="canonical"/.test(html)) throw new Error(file + ": missing canonical URL");
    }
    if (file !== "404.html") {
      if (!/class="header-cta" href="\.\/local-console\.html"/.test(html) || !html.includes("Local Control Room")) {
        throw new Error(file + ": header must clearly label its local-only Control Room link.");
      }
    }
  }

  const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);
  const duplicates = ids.filter((id, index) => ids.indexOf(id) !== index);
  if (duplicates.length) throw new Error(file + ": duplicate id(s): " + [...new Set(duplicates)].join(", "));

  const links = [...html.matchAll(/\b(?:href|src)="([^"]+)"/g)].map(match => match[1]);
  for (const link of links) {
    if (/^(?:https?:|mailto:|tel:|#|data:|javascript:)/i.test(link)) continue;
    const clean = link.split("#")[0].split("?")[0];
    if (!clean) continue;
    const relative = clean.startsWith("./") ? clean.slice(2) : clean;
    const target = path.resolve(site, relative);
    if (!target.startsWith(site + path.sep) && target !== site) {
      throw new Error(file + ": local link escapes site root: " + link);
    }
    if (!fs.existsSync(target)) throw new Error(file + ": broken local link: " + link);
  }
}

const js = fs.readFileSync(path.join(site, "corporate.js"), "utf8");
new vm.Script(js, {filename: "corporate.js"});
const css = fs.readFileSync(path.join(site, "corporate.css"), "utf8");
const accentMatch = css.match(/--accent-dark:\s*(#[0-9a-f]{6})/i);
if (!accentMatch) throw new Error("Missing accessible dark accent token.");
function luminance(hex) {
  const rgb = hex.slice(1).match(/../g).map(pair => parseInt(pair, 16) / 255).map(value =>
    value <= 0.04045 ? value / 12.92 : Math.pow((value + 0.055) / 1.055, 2.4));
  return 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2];
}
const contrast = 1.05 / (luminance(accentMatch[1]) + 0.05);
if (contrast < 4.5) throw new Error("Dark accent fails 4.5:1 contrast against white.");
if (!css.includes(".btn:not(.btn-secondary):not(.btn-dark),.header-cta,.run-case{background:var(--accent-dark)")) {
  throw new Error("Primary controls must use the contrast-safe dark accent.");
}
if (!css.includes(".btn-secondary{background:transparent") || !css.includes(".btn-dark{background:var(--navy)")) {
  throw new Error("Secondary and dark button variants must preserve their own styling.");
}
if (!css.includes(".cta .btn{background:var(--navy)")) {
  throw new Error("The CTA button must retain its dark-on-accent treatment.");
}

if (/@import\s+url/i.test(css)) throw new Error("Corporate CSS must not depend on external font imports.");
if (!js.includes("review.hidden=!pending")) throw new Error("Human-approval demo does not reveal its review controls.");
if (!js.includes("data-lang-button")) throw new Error("Bilingual control handler is missing.");
if (!js.includes("syncDemoLanguage();")) throw new Error("Changing language must re-render the current demo state.");
for (const state of ['demoState="idle"', 'demoState="decision"', 'demoState=approved?"approved":"denied"']) {
  if (!js.includes(state)) throw new Error("Demo language synchronization is missing state: " + state);
}
if (!js.includes('event.key==="Escape"')) throw new Error("Mobile navigation must close on Escape.");
if (!js.includes('toggle.focus()')) throw new Error("Escape handling must restore focus to the menu toggle.");

const security = fs.readFileSync(path.join(site, "security.html"), "utf8");
if (!security.includes("SECURITY.md")) throw new Error("Security page must link the responsible disclosure policy.");
for (const lens of ["/ASSUMPTIONS", "/BLINDSPOT", "/COUNTER", "/EDGECASE", "/SELFCRITIQUE"]) {
  if (!security.includes(lens)) throw new Error("Security page is missing threat-model section " + lens);
}
const home = fs.readFileSync(path.join(site, "index.html"), "utf8");
if (!home.includes("TARGET ARCHITECTURE") || !home.includes("the current Python execution adapter is a mock")) {
  throw new Error("Homepage architecture diagram must be labeled as a conceptual target, not live enforcement.");
}
if (!home.includes('class="flow-routing"') || !home.includes("CONDITIONAL ROUTING")) {
  throw new Error("Homepage architecture must show conditional policy routing.");
}
for (const phrase of ["ALLOW", "HUMAN_APPROVAL", "BLOCK", "Only ALLOW", "BLOCK stops here", "ALLOW + APPROVED REVIEW ONLY", "DISPATCH RE-CHECK", "LOCAL TRACE"]) {
  if (!home.includes(phrase)) throw new Error("Homepage conditional flow is missing: " + phrase);
}
if (home.includes("<strong>HUMAN AUTHORITY</strong>")) {
  throw new Error("Homepage must not present human review as mandatory for every request.");
}
if (!css.includes(".flow-routing{") || !css.includes(".flow-outcomes{") || !css.includes(".flow-route-continue{") ||
    !css.includes("@media(max-width:460px){.flow-outcomes{grid-template-columns:1fr}")) {
  throw new Error("Conditional routing diagram is missing responsive layout styles.");
}
for (const phrase of ["CURRENT BUILD / 03 NOV 2026", "IMPLEMENTED LOCALLY", "SIMULATED", "NOT YET INTEGRATED", "MockExecutionAdapter", "real agent framework"]) {
  if (!home.toLowerCase().includes(phrase.toLowerCase())) throw new Error("Homepage prototype-status panel is missing: " + phrase);
}
const platform = fs.readFileSync(path.join(site, "platform.html"), "utf8");
for (const term of ["Agent", "Action", "Resource", "Policy", "Reviewer", "Execution Adapter", "shared development Reviewer token", "MockExecutionAdapter"]) {
  if (!platform.includes(term)) throw new Error("Platform glossary is missing a core term or implementation caveat: " + term);
}
if (!platform.includes('class="term-grid"') || !css.includes(".term-grid{")) {
  throw new Error("Platform glossary cards are missing their responsive UI styling.");
}
for (const phrase of ["ALLOW", "HUMAN_APPROVAL", "BLOCK", "research_agent", "read_database", "company_email"]) {
  if (!platform.includes(phrase)) throw new Error("Platform decision guide is missing: " + phrase);
}
for (const outcome of ['data-en="Allow"', 'data-en="Human approval required"', 'data-en="Block"']) {
  if (!platform.includes(outcome)) throw new Error("Platform outcome card is missing bilingual copy: " + outcome);
}
if (!platform.includes('class="decision-cards"') || !platform.includes("CONTROL PLANE / RESEARCH PROTOTYPE")) {
if (!platform.includes('class="journey-grid"') || !platform.includes("01 / EXPLORE") || !platform.includes("02 / PREPARE") || !platform.includes("03 / CONNECT")) {
  throw new Error("Platform page is missing the guided Lab → Docs → Local Control Room journey.");
}
for (const page of ['./lab.html', './developers.html', './local-console.html']) {
  if (!platform.includes('href="' + page + '"')) throw new Error("Guided product journey is missing " + page);
}
if (!home.includes('href="./developers.html"') || !home.includes("Developer quick start")) {
  throw new Error("Homepage prototype status must link to the developer quick start.");
}

  throw new Error("Platform page must show its prototype status and decision-card UI.");
}
const technology = fs.readFileSync(path.join(site, "technology.html"), "utf8");
for (const phrase of ["DISPATCH PERMIT / RE-CHECK", "MOCK TOOL PROVIDER + RECEIPT LEDGER", "Dispatch permit boundary", "15-second HMAC request-bound permit", "Exact tool binding", "explicitly registered Action/Resource pairs", "durable SQLite nonce ledger", "Provider process boundary", "MOCK TOOL PROVIDER + RECEIPT LEDGER", "Execution receipt ledger", "Gateway restart recovery", "completed results are cached", "indeterminate", "not an OS sandbox", "HMAC-authenticated receipt reads", "Manual key rotation", "key_id", "overlapping old/new keys", "Production execution adapter"]) {
  if (!technology.includes(phrase)) throw new Error("Technology page is missing the guarded adapter boundary description: " + phrase);
}
const threatModel = fs.readFileSync(path.join(root, "docs", "THREAT_MODEL.md"), "utf8");
for (const phrase of ["Dispatch capability lifecycle", "HMAC-signed permit", "in-memory consumer", "no automatic retirement schedule", "direct agent-to-real-tool bypass", "same-host process separation", "unregistered action/resource pairs", "indeterminate", "never automatically replayed", "at-most-once local dispatch behavior", "single gateway instance", "processing", "request-bound approval", "X-Custos-Receipt-Signature", "domain-separated key", "mutual TLS", "overlapping key ring", "automatic retirement schedule", "KMS/HSM"]) {
  if (!threatModel.includes(phrase)) throw new Error("Threat model is missing the adapter-boundary limitation: " + phrase);
}
const developerDocs = fs.readFileSync(path.join(site, "developers.html"), "utf8");
for (const phrase of ['action = "send_email"', 'request_id = "docs-email-001"', '$emailResponse.approval_id', 'decision -ne "HUMAN_APPROVAL"', 'Bearer $reviewerToken', 'Bearer $agentToken', '-Body "{}"']) {
if (!developerDocs.includes('"decision": "HUMAN_APPROVAL"') || !developerDocs.includes('"executed": false') || !developerDocs.includes('generated-by-server')) {
  throw new Error("Developer Docs must show the expected human-approval response payload.");
}
if (!developerDocs.includes("It does not mean approval or external execution is complete.") && !developerDocs.includes("승인 완료나 외부 행동 실행을 뜻하지 않습니다.")) {
  throw new Error("Developer Docs must distinguish HTTP acceptance from approval/execution.");
}
if (!developerDocs.includes('class="response-preview"') || !css.includes(".response-preview{")) {
  throw new Error("Expected API response must be shown in a distinct explanatory panel.");
}

  if (!developerDocs.includes(phrase)) throw new Error("Developer walkthrough is incomplete: " + phrase);
}
if (!developerDocs.includes('class="walkthrough-steps"') || !css.includes(".prototype-grid") || !css.includes(".decision-cards")) {
  throw new Error("The product explanation UI styles are missing.");
}

for (const page of ["platform.html", "technology.html", "security.html", "research.html", "company.html", "contact.html", "privacy.html", "terms.html", "updates.html", "developers.html", "lab.html", "local-console.html"]) {
  if (!home.includes("./" + page)) throw new Error("Homepage is missing navigation to " + page);
}

const updates = fs.readFileSync(path.join(site, "updates.html"), "utf8");
for (const phrase of ["DAY 001", "DAY 002", "DAY 003", "DAY 004", "DAY 005", "DAY 006", "DAY 007", "DAY 008", "DAY 009", "DAY 010", "DAY 011", "DAY 012", "DAY 013", "56 TESTS IN SUITE", "NOT VERIFIED", "mock execution adapter", "real-agent bypass resistance"]) {
  if (!updates.toLowerCase().includes(phrase.toLowerCase())) throw new Error("Updates page is missing factual status item: " + phrase);
}
for (const log of ["day-001.md", "day-002.md", "day-003.md", "day-004.md", "day-005.md", "day-006.md", "day-007.md", "day-008.md", "day-009.md", "day-010.md", "day-011.md", "day-012.md", "day-013.md"]) {
  if (!updates.includes(log)) throw new Error("Updates page is missing the source development log: " + log);
}

const apiSource = fs.readFileSync(path.join(root, "custos_api.py"), "utf8");
if (!apiSource.includes("dispatch_signing_keys=dispatch_signing_keys") || !apiSource.includes("active_dispatch_key_id=active_dispatch_key_id")) {
  throw new Error("Gateway API must pass the active key ring to the gateway.");
}
if (!apiSource.includes("receipt_signing_key=dispatch_signing_key")) {
  throw new Error("Gateway API must pass the dispatch key to authenticated provider receipt lookups.");
}
for (const fragment of ['path == "/health"', 'path == "/v1/requests"', 'path == "/v1/approvals"', 'operation == "review"', 'operation == "execute"']) {
  if (!apiSource.includes(fragment)) throw new Error("API implementation route is missing: " + fragment);
}
if (!apiSource.includes('origin != "https://hanyeolhui09twinx-art.github.io"')) {
  throw new Error("API implementation must enforce the documented browser Origin allowlist.");
}
const providerSource = fs.readFileSync(path.join(root, "custos_provider.py"), "utf8");
for (const phrase of ["DurableDispatchPermitVerifier", "BEGIN IMMEDIATE", "consumed_permits", "ExecutionReceiptStore", "execution_receipts", "recover_interrupted", "execute_with_permit", "get_receipt", "execution_outcome_unknown", "RECEIPT_SIGNATURE_HEADER", "RECEIPT_KEY_ID_HEADER", "receipt_lookup_signature", "verify_receipt_lookup", "CUSTOS_DISPATCH_KEYS", "CUSTOS_ACTIVE_DISPATCH_KEY_ID", "key_id", "PROVIDER_PATH"]) {
  if (!providerSource.includes(phrase)) throw new Error("Provider process is missing a required verification control: " + phrase);
}
const providerTests = fs.readFileSync(path.join(root, "tests", "test_provider_process.py"), "utf8");
for (const phrase of ["subprocess.Popen", "test_provider_permit_is_single_use_under_concurrent_replay", "test_provider_replay_record_survives_process_restart", "test_human_approved_dispatch_uses_the_separate_provider", "test_gateway_fails_closed_when_provider_is_unavailable", "test_same_request_id_returns_persisted_result_without_second_execution", "test_same_request_id_with_different_digest_is_rejected", "test_interrupted_execution_becomes_indeterminate_after_restart", "test_gateway_reconciles_a_lost_response_from_provider_receipt", "test_approved_gateway_reconciles_a_lost_provider_response", "test_gateway_restart_reconciles_provider_completion_before_request_receipt_commit", "test_gateway_restart_without_provider_receipt_stays_unknown_and_never_redispatches", "test_gateway_restart_recovers_existing_pending_approval_without_duplicate", "test_approved_execution_restart_reconciles_provider_receipt", "test_provider_receipt_lookup_requires_a_valid_hmac_signature", "test_gateway_uses_configured_active_key_id_and_key_ring", "test_provider_accepts_previous_receipt_lookup_key_during_rotation", "test_provider_accepts_previous_and_active_keys_during_rotation", "test_provider_rejects_retired_key_after_rotation_window", "test_provider_rejects_permit_key_id_substitution", "test_provider_accepts_previous_receipt_lookup_key_during_rotation", "test_provider_accepts_previous_and_active_keys_during_rotation", "test_provider_rejects_retired_key_after_rotation_window", "test_provider_rejects_permit_key_id_substitution", "test_provider_supports_legacy_single_key_environment_configuration"]) {
  if (!providerTests.includes(phrase)) throw new Error("Separate-process integration test is missing: " + phrase);
}
const gatewaySource = fs.readFileSync(path.join(root, "custos_gateway.py"), "utf8");
for (const phrase of ["recover_interrupted_requests", "GATEWAY_RECOVERED_INCOMPLETE_REQUESTS", "get_for_request", "EXECUTION_UNKNOWN", "status='indeterminate'"]) {
  if (!gatewaySource.includes(phrase)) throw new Error("Gateway restart recovery control is missing: " + phrase);
}
for (const status of ["pending", "approved", "denied", "expired", "executing", "executed", "blocked", "failed", "indeterminate"]) {
  if (!gatewaySource.includes("'" + status + "'") && !gatewaySource.includes('"' + status + '"')) {
    throw new Error("Approval state is missing from gateway implementation: " + status);
  }
}
const openApiPath = path.join(site, "openapi.json");
const openApi = JSON.parse(fs.readFileSync(openApiPath, "utf8"));
if (openApi.openapi !== "3.1.0") throw new Error("OpenAPI contract must use version 3.1.0.");
for (const route of ["/health", "/v1/requests", "/v1/approvals", "/v1/approvals/{approval_id}/review", "/v1/approvals/{approval_id}/execute"]) {
  if (!openApi.paths[route]) throw new Error("OpenAPI contract is missing route " + route);
}
if (!openApi.servers.some(server => server.url === "http://127.0.0.1:8765")) {
  throw new Error("OpenAPI contract must describe the local loopback server.");
}
if (!openApi.info.description.includes("https://hanyeolhui09twinx-art.github.io")) {
  throw new Error("OpenAPI contract must document the strict browser CORS origin allowlist.");
}
if (!developerDocs.includes("other browser origins") && !developerDocs.includes("다른 도메인")) {
  throw new Error("Developer Docs must disclose the browser CORS origin limitation.");
}
if (!openApi.components.securitySchemes.AgentBearer || !openApi.components.securitySchemes.ReviewerBearer) {
  throw new Error("OpenAPI contract must distinguish Agent and Reviewer credentials.");
}
if (!openApi.paths["/v1/approvals/{approval_id}/execute"].post.requestBody.required) {
  throw new Error("OpenAPI contract must preserve the required execute request body.");
}
if (JSON.stringify(openApi.paths["/v1/approvals/{approval_id}/execute"].post.requestBody).indexOf("{}") < 0) {
  throw new Error("OpenAPI execute request must document an empty JSON object.");
}
if (!developerDocs.includes('Invoke-RestMethod -Method Post') || !developerDocs.includes('Bearer $reviewerToken') || !developerDocs.includes('$emailResponse.approval_id')) {
  throw new Error("Developer Docs must contain a complete request-to-approval walkthrough.");
}
if (!developerDocs.includes('-Body "{}"')) throw new Error("Execute example must send the required JSON request body.");
for (const code of ["200", "400", "401", "403", "404", "409", "410", "413", "500"]) {
  if (!developerDocs.includes(">" + code + "<")) throw new Error("Developer Docs is missing HTTP status code " + code);
}
if (!developerDocs.includes("BLOCK") || !developerDocs.includes("HTTP 200")) throw new Error("Developer Docs must distinguish policy decisions from HTTP response status.");
for (const phrase of ["custos_provider.py", "CUSTOS_TOOL_PROVIDER_URL", "CUSTOS_DISPATCH_KEYS", "CUSTOS_ACTIVE_DISPATCH_KEY_ID", "CUSTOS_DISPATCH_SIGNING_KEY", "Manual key rotation sequence", "same trusted machine", "OS sandboxing"]) {
  if (!developerDocs.includes(phrase)) throw new Error("Developer Docs must disclose provider-process setup: " + phrase);
}
for (const phrase of ["/v1/requests", "/v1/approvals", "request_id", "research_db", "mock execution adapter", "Do not enter production credentials"]) {
  if (!developerDocs.toLowerCase().includes(phrase.toLowerCase())) throw new Error("Developer Docs is missing an implementation detail: " + phrase);
}
if (!css.includes(".reveal{opacity:1;transform:none}") || !css.includes(".js-motion .reveal{opacity:0")) {
  throw new Error("Reveal animations must not hide content when JavaScript is unavailable.");
}
if (!js.includes('root.classList.add("js-motion")')) {
  throw new Error("Motion enhancement must be enabled only after JavaScript starts.");
}
if (!css.includes(".reveal,.js-motion .reveal{opacity:1;transform:none;transition:none}")) {
  throw new Error("Reduced-motion mode must override the JavaScript reveal state.");
}
if (!css.includes("@media(prefers-reduced-motion:reduce)")) {
  throw new Error("Reduced-motion preference must remain supported.");
}
if (!css.includes("@media(forced-colors:active)") || !css.includes("outline:2px solid Highlight")) {
  throw new Error("Forced-colors mode must retain visible keyboard focus.");
}
if (!css.includes(".code-panel pre{") || !css.includes("@media(max-width:760px){.code-head")) {
  throw new Error("Developer Docs code panels must support responsive horizontal scrolling.");
}
for (const selector of ['#setup-code', '#request-code', '#approval-code']) {
  if (!developerDocs.includes('data-copy-code="' + selector + '"') || !developerDocs.includes('id="' + selector.slice(1) + '"')) {
    throw new Error("Developer Docs is missing its code copy control for " + selector);
  }
}
if (!js.includes('querySelectorAll("[data-copy-code]")') || !js.includes("window.navigator.clipboard.writeText") || !js.includes("selectFallback")) {
  throw new Error("Code copy controls must provide clipboard and selection fallback behavior.");
}
if (!developerDocs.includes('class="code-panel"') || !developerDocs.includes('class="doc-note"')) {
  throw new Error("Developer Docs is missing styled code or safety-note panels.");
}
const terms = fs.readFileSync(path.join(site, "terms.html"), "utf8");
for (const phrase of ["Simulation Lab", "Local Control Room", "commercial SaaS", "development"]) {
  if (!terms.toLowerCase().includes(phrase.toLowerCase())) throw new Error("Terms of Use is missing boundary disclosure: " + phrase);
}
const robots = fs.readFileSync(path.join(site, "robots.txt"), "utf8");
if (!robots.includes("sitemap.xml")) throw new Error("robots.txt must reference the sitemap.");
const sitemap = fs.readFileSync(path.join(site, "sitemap.xml"), "utf8");
for (const page of ["platform.html", "technology.html", "security.html", "research.html", "company.html", "contact.html", "privacy.html", "terms.html", "updates.html", "developers.html"]) {
  if (!sitemap.includes("/" + page)) throw new Error("Sitemap is missing " + page);
}
console.log("Custos website validation passed: corporate pages, standalone tools, local links, bilingual controls, threat model, sitemap, and demo behavior.");

const lab = fs.readFileSync(path.join(site, "lab.html"), "utf8");
if (!lab.includes("img-src 'self' data:")) throw new Error("Lab CSP must permit its same-origin brand icon.");
if (!lab.includes('href="./index.html"')) throw new Error("Lab is missing a return link to the corporate website.");
const localConsole = fs.readFileSync(path.join(site, "local-console.html"), "utf8");
const contributionGuide = fs.readFileSync(path.join(root, "CONTRIBUTING.md"), "utf8");
const pullRequestTemplate = fs.readFileSync(path.join(root, ".github", "PULL_REQUEST_TEMPLATE.md"), "utf8");
for (const command of ["python -m unittest discover -s tests -v", "node tests/check_studio_console.js", "node tests/check_simulation_lab.js", "node tests/check_corporate_site.js"]) {
  if (!contributionGuide.includes(command) || !pullRequestTemplate.includes(command)) {
    throw new Error("Contribution docs must include the required check: " + command);
  }
}
if (!pullRequestTemplate.includes("No credentials, tokens") || !pullRequestTemplate.includes("actual tool boundary")) {
  throw new Error("Pull request template is missing security scope checks.");
}
if (!developerDocs.includes("CONTRIBUTING.md")) throw new Error("Developer Docs must link the contribution guide.");
if (!developerDocs.includes("./openapi.json")) throw new Error("Developer Docs must link the machine-readable OpenAPI contract.");
const issueTemplates = path.join(root, ".github", "ISSUE_TEMPLATE");
for (const template of ["bug_report.yml", "research_proposal.yml", "config.yml"]) {
  if (!fs.existsSync(path.join(issueTemplates, template))) throw new Error("Missing GitHub issue template: " + template);
}
const bugTemplate = fs.readFileSync(path.join(issueTemplates, "bug_report.yml"), "utf8");
const researchTemplate = fs.readFileSync(path.join(issueTemplates, "research_proposal.yml"), "utf8");
if (!bugTemplate.includes("Steps to reproduce") || !bugTemplate.includes("Public disclosure check")) {
  throw new Error("Bug report template must collect reproduction steps and a disclosure check.");
}
if (!researchTemplate.includes("Problem or research question") || !researchTemplate.includes("Proposed approach")) {
  throw new Error("Research proposal template must separate the problem from the proposed approach.");
}
const securityPolicy = fs.readFileSync(path.join(root, "SECURITY.md"), "utf8");
if (!securityPolicy.includes("Report a vulnerability") || !securityPolicy.includes("private reporting")) {
  throw new Error("SECURITY.md must explain private vulnerability reporting availability and limitations.");
}
const issueConfig = fs.readFileSync(path.join(issueTemplates, "config.yml"), "utf8");
if (!issueConfig.includes("SECURITY.md")) throw new Error("Issue intake config must link the security reporting policy.");
const contact = fs.readFileSync(path.join(site, "contact.html"), "utf8");
if (!contact.includes("template=bug_report.yml") || !contact.includes("template=research_proposal.yml") || !contact.includes("SECURITY.md")) {
  throw new Error("Contact page must link to the structured issue templates.");
}

if (!localConsole.includes("img-src 'self'")) throw new Error("Local Control Room CSP must permit its same-origin brand icon.");
if (!localConsole.includes('href="./index.html"')) throw new Error("Local Control Room is missing its corporate website return link.");
if (!localConsole.includes('href="./lab.html"') || !localConsole.includes('href="./index.html"')) {
  throw new Error("Local Control Room must link back to both the Lab and corporate website.");
}
for (const phrase of ["EXECUTION_UNKNOWN", "executed=null", "same request ID", "setRequestLocked", 'classList.add("uncertain")']) {
  if (!localConsole.includes(phrase)) throw new Error("Local Control Room is missing unknown-outcome UX: " + phrase);
}


// Exercise the actual corporate UI handlers with a tiny deterministic DOM harness.
class FakeElement {
  constructor(attributes = {}) {
    this.attributes = {...attributes};
    this.listeners = {};
    this.classNames = new Set();
    this.classList = {
      add: name => this.classNames.add(name),
      remove: name => this.classNames.delete(name),
      contains: name => this.classNames.has(name),
      toggle: (name, force) => {
        const enabled = force === undefined ? !this.classNames.has(name) : Boolean(force);
        if (enabled) this.classNames.add(name);
        else this.classNames.delete(name);
        return enabled;
      }
    };
    this.textContent = "";
    this.placeholder = "";
    this.hidden = false;
    this.className = "";
    this.focused = false;
  }
  getAttribute(name) { return this.attributes[name] ?? null; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  addEventListener(name, callback) { this.listeners[name] = callback; }
  click() { if (this.listeners.click) this.listeners.click({type: "click"}); }
  focus() { this.focused = true; }
  querySelectorAll() { return []; }
}
const demoElements = {
  demoAction: new FakeElement(),
  demoResource: new FakeElement(),
  demoScope: new FakeElement(),
  demoEffect: new FakeElement(),
  demoDecision: new FakeElement(),
  demoLed: new FakeElement(),
  demoDescription: new FakeElement(),
  demoReview: new FakeElement()
};
demoElements.demoReview.hidden = true;
const langKo = new FakeElement({"data-lang-button": "ko"});
const langEn = new FakeElement({"data-lang-button": "en"});
const menuToggle = new FakeElement({"aria-expanded": "false"});
const mobileNav = new FakeElement();
const demoRead = new FakeElement({"data-demo-case": "read"});
const demoEmail = new FakeElement({"data-demo-case": "email"});
const demoDisable = new FakeElement({"data-demo-case": "disable"});
const copyButton = new FakeElement({"data-copy-code": "#setup-code", "data-ko": "코드 복사", "data-en": "Copy code"});
const setupCode = new FakeElement();
setupCode.innerText = "$env:CUSTOS_AGENT_TOKENS = 'test-token'";
const fallbackButton = new FakeElement({"data-copy-code": "#fallback-code", "data-ko": "코드 복사", "data-en": "Copy code"});
const fallbackCode = new FakeElement();
fallbackCode.innerText = "fallback snippet";
let selectedCopyNode = null;
let copiedSnippet = "";
const demoRun = new FakeElement();
const demoApprove = new FakeElement();
const demoDeny = new FakeElement();
const selectorResults = {
  "[data-lang-button]": [langKo, langEn],
  "[data-ko][data-en]": [copyButton, fallbackButton],
  "[data-placeholder-ko][data-placeholder-en]": [],
  "[data-menu-toggle]": [menuToggle],
  "[data-mobile-nav]": [mobileNav],
  "[data-nav]": [],
  ".reveal": [],
  "[data-demo-case]": [demoRead, demoEmail, demoDisable],
  "[data-copy-code]": [copyButton, fallbackButton]
};
const singleResults = {
  "[data-menu-toggle]": menuToggle,
  "[data-mobile-nav]": mobileNav,
  "[data-demo-run]": demoRun,
  "[data-demo-approve]": demoApprove,
  "[data-demo-deny]": demoDeny,
  "#setup-code": setupCode,
  "#fallback-code": fallbackCode
};
const keyListeners = {};
const fakeDocument = {
  documentElement: {lang: "ko", classList: {add: function() {}}},
  body: {getAttribute: name => name === "data-page" ? "home" : null},
  querySelectorAll: selector => selectorResults[selector] || [],
  querySelector: selector => singleResults[selector] || null,
  getElementById: id => demoElements[id] || null,
  createRange: () => ({selectNodeContents: node => { selectedCopyNode = node; }}),
  addEventListener: (name, callback) => { keyListeners[name] = callback; }
};
const fakeSession = {getItem: () => null, setItem: () => {}};
vm.runInNewContext(js, {
  document: fakeDocument,
  window: {
    navigator: {clipboard: {writeText: value => {
      if (value === "fallback snippet") return {then: () => ({catch: callback => { callback(); }})};
      copiedSnippet = value;
      return {then: callback => { callback(); return {catch: () => {}}; }};
    }}},
    getSelection: () => ({removeAllRanges: () => {}, addRange: () => {}})
  },
  sessionStorage: fakeSession
});

demoEmail.click();
if (demoEmail.getAttribute("aria-pressed") !== "true" || demoRead.getAttribute("aria-pressed") !== "false") {
  throw new Error("Selecting a scenario must update the accessible pressed state.");
}
demoRun.click();
if (demoElements.demoDecision.textContent !== "인간 승인 필요" || demoElements.demoReview.hidden) {
  throw new Error("Email scenario must require a visible human approval step.");
}
demoApprove.click();
if (demoElements.demoDecision.textContent !== "승인됨 · 모의 실행" || !demoElements.demoReview.hidden) {
  throw new Error("Approval action must transition to approved mock state and hide review controls.");
}
langEn.click();
if (demoElements.demoDecision.textContent !== "APPROVED · MOCK" ||
    !demoElements.demoDescription.textContent.includes("mock execution")) {
  throw new Error("Switching to English must re-render the already approved demo state.");
}
langKo.click();
if (demoElements.demoDecision.textContent !== "승인됨 · 모의 실행") {
  throw new Error("Switching back to Korean must retain the current demo state.");
}

demoEmail.click();
demoRun.click();
demoDeny.click();
if (demoElements.demoDecision.textContent !== "거부됨 · 실행 차단") {
  throw new Error("Denial action must transition to the denied state.");
}
demoDisable.click();
demoRun.click();
if (demoElements.demoDecision.textContent !== "차단") {
  throw new Error("Protected system action must produce a block decision.");
}
demoRead.click();
demoRun.click();
if (demoElements.demoDecision.textContent !== "허용") {
  throw new Error("Permitted research read scenario must produce an allow decision.");
}

menuToggle.click();
if (menuToggle.getAttribute("aria-expanded") !== "true" || menuToggle.getAttribute("aria-label") !== "메뉴 닫기" || !mobileNav.classList.contains("open")) {
  throw new Error("Mobile menu toggle must expose the open state.");
}
if (!keyListeners.keydown) throw new Error("Escape key handler was not installed.");
keyListeners.keydown({key: "Escape"});
if (menuToggle.getAttribute("aria-expanded") !== "false" || menuToggle.getAttribute("aria-label") !== "메뉴 열기" || mobileNav.classList.contains("open") || !menuToggle.focused) {
  throw new Error("Escape must close the mobile menu and restore focus to the toggle.");
}
copyButton.click();
if (copiedSnippet !== setupCode.innerText || copyButton.textContent !== "복사됨") {
  throw new Error("Developer code copy control must write the selected snippet and announce success.");
}
fallbackButton.click();
if (selectedCopyNode !== fallbackCode || fallbackButton.textContent !== "선택됨 · Ctrl+C") {
  throw new Error("Developer code copy control must select the snippet when clipboard access is denied.");
}
console.log("Corporate UI behavior checks passed: policy states, approval flow, bilingual state retention, keyboard menu control, and code-copy behavior.");
