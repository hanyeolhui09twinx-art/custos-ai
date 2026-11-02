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
if (!home.includes('role="status" aria-live="polite"')) throw new Error("Policy demo decision must be announced to assistive technology.");
if (!home.includes('data-demo-case="read" aria-pressed="true"')) throw new Error("Policy demo needs an accessible selected scenario state.");
if (!home.includes('data-demo-approve class="run-case" data-ko="승인 · 모의 실행"')) throw new Error("Approval demo action must be bilingual.");
for (const page of ["platform.html", "technology.html", "security.html", "research.html", "company.html", "contact.html", "privacy.html", "terms.html", "updates.html", "developers.html", "lab.html", "local-console.html"]) {
  if (!home.includes("./" + page)) throw new Error("Homepage is missing navigation to " + page);
}

const updates = fs.readFileSync(path.join(site, "updates.html"), "utf8");
for (const phrase of ["DAY 001", "DAY 002", "DAY 003", "DAY 004", "NOT VERIFIED", "mock execution adapter", "real-agent bypass resistance"]) {
  if (!updates.toLowerCase().includes(phrase.toLowerCase())) throw new Error("Updates page is missing factual status item: " + phrase);
}
for (const log of ["day-001.md", "day-002.md", "day-003.md", "day-004.md"]) {
  if (!updates.includes(log)) throw new Error("Updates page is missing the source development log: " + log);
}
const developerDocs = fs.readFileSync(path.join(site, "developers.html"), "utf8");
const apiSource = fs.readFileSync(path.join(root, "custos_api.py"), "utf8");
for (const fragment of ['path == "/health"', 'path == "/v1/requests"', 'path == "/v1/approvals"', 'operation == "review"', 'operation == "execute"']) {
  if (!apiSource.includes(fragment)) throw new Error("API implementation route is missing: " + fragment);
}
if (!apiSource.includes('origin != "https://hanyeolhui09twinx-art.github.io"')) {
  throw new Error("API implementation must enforce the documented browser Origin allowlist.");
}
const gatewaySource = fs.readFileSync(path.join(root, "custos_gateway.py"), "utf8");
for (const status of ["pending", "approved", "denied", "expired", "executing", "executed", "blocked", "failed"]) {
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
if (!developerDocs.includes('Invoke-RestMethod -Method Post') || !developerDocs.includes('Bearer $reviewerToken') || !developerDocs.includes('PASTE_APPROVAL_ID_HERE')) {
  throw new Error("Developer Docs must contain a working-style local request and approval walkthrough.");
}
if (!developerDocs.includes('-Body "{}"')) throw new Error("Execute example must send the required JSON request body.");
for (const code of ["200", "400", "401", "403", "404", "409", "410", "413", "500"]) {
  if (!developerDocs.includes(">" + code + "<")) throw new Error("Developer Docs is missing HTTP status code " + code);
}
if (!developerDocs.includes("BLOCK") || !developerDocs.includes("HTTP 200")) throw new Error("Developer Docs must distinguish policy decisions from HTTP response status.");
for (const phrase of ["/v1/requests", "/v1/approvals", "request_id", "research_db", "mock execution adapter", "Do not enter production credentials"]) {
  if (!developerDocs.toLowerCase().includes(phrase.toLowerCase())) throw new Error("Developer Docs is missing an implementation detail: " + phrase);
}
if (!css.includes(".reveal{opacity:1;transform:none}") || !css.includes(".js-motion .reveal{opacity:0")) {
  throw new Error("Reveal animations must not hide content when JavaScript is unavailable.");
}
if (!js.includes('root.classList.add("js-motion")')) {
  throw new Error("Motion enhancement must be enabled only after JavaScript starts.");
}
if (!css.includes("@media(forced-colors:active)") || !css.includes("outline:2px solid Highlight")) {
  throw new Error("Forced-colors mode must retain visible keyboard focus.");
}
if (!css.includes(".code-panel pre{") || !css.includes("@media(max-width:760px){.code-head")) {
  throw new Error("Developer Docs code panels must support responsive horizontal scrolling.");
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
for (const command of ["python -m unittest discover -s tests -v", "node tests/check_studio_console.js", "node tests/check_corporate_site.js"]) {
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
const demoRun = new FakeElement();
const demoApprove = new FakeElement();
const demoDeny = new FakeElement();
const selectorResults = {
  "[data-lang-button]": [langKo, langEn],
  "[data-ko][data-en]": [],
  "[data-placeholder-ko][data-placeholder-en]": [],
  "[data-menu-toggle]": [menuToggle],
  "[data-mobile-nav]": [mobileNav],
  "[data-nav]": [],
  ".reveal": [],
  "[data-demo-case]": [demoRead, demoEmail, demoDisable]
};
const singleResults = {
  "[data-menu-toggle]": menuToggle,
  "[data-mobile-nav]": mobileNav,
  "[data-demo-run]": demoRun,
  "[data-demo-approve]": demoApprove,
  "[data-demo-deny]": demoDeny
};
const keyListeners = {};
const fakeDocument = {
  documentElement: {lang: "ko", classList: {add: function() {}}},
  body: {getAttribute: name => name === "data-page" ? "home" : null},
  querySelectorAll: selector => selectorResults[selector] || [],
  querySelector: selector => singleResults[selector] || null,
  getElementById: id => demoElements[id] || null,
  addEventListener: (name, callback) => { keyListeners[name] = callback; }
};
const fakeSession = {getItem: () => null, setItem: () => {}};
vm.runInNewContext(js, {document: fakeDocument, window: {}, sessionStorage: fakeSession});

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
console.log("Corporate UI behavior checks passed: policy states, approval flow, bilingual state retention, and keyboard menu control.");
