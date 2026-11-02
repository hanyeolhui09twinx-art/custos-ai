const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.resolve(__dirname, "..");
const site = path.join(root, "simulation-studio");
const corporatePages = [
  "index.html", "platform.html", "technology.html", "security.html",
  "research.html", "company.html", "contact.html", "privacy.html", "404.html"
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

  if (corporatePages.includes(file)) {
    if (!/href="\.\/corporate\.css"/.test(html)) throw new Error(file + ": missing shared stylesheet");
    if (!/src="\.\/corporate\.js"/.test(html)) throw new Error(file + ": missing shared script");
    if (!/data-lang-button="ko"/.test(html) || !/data-lang-button="en"/.test(html)) {
      throw new Error(file + ": missing bilingual language controls");
    }
    if (!/class="skip-link"/.test(html) || !/id="main-content"/.test(html)) {
      throw new Error(file + ": missing keyboard skip link or main landmark");
    }
    if (file !== "404.html") {
      if (!/aria-controls="mobile-navigation"/.test(html) || !/id="mobile-navigation"/.test(html)) {
        throw new Error(file + ": mobile menu button and navigation are not programmatically connected");
      }
      if (!/rel="canonical"/.test(html)) throw new Error(file + ": missing canonical URL");
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
if (!css.includes(".btn,.header-cta,.run-case{background:var(--accent-dark)")) {
  throw new Error("Primary controls must use the contrast-safe dark accent.");
}

if (/@import\s+url/i.test(css)) throw new Error("Corporate CSS must not depend on external font imports.");
if (!js.includes("review.hidden=!pending")) throw new Error("Human-approval demo does not reveal its review controls.");
if (!js.includes("data-lang-button")) throw new Error("Bilingual control handler is missing.");
if (!js.includes('event.key==="Escape"')) throw new Error("Mobile navigation must close on Escape.");
if (!js.includes('toggle.focus()')) throw new Error("Escape handling must restore focus to the menu toggle.");

const security = fs.readFileSync(path.join(site, "security.html"), "utf8");
for (const lens of ["/ASSUMPTIONS", "/BLINDSPOT", "/COUNTER", "/EDGECASE", "/SELFCRITIQUE"]) {
  if (!security.includes(lens)) throw new Error("Security page is missing threat-model section " + lens);
}
const home = fs.readFileSync(path.join(site, "index.html"), "utf8");
if (!home.includes('role="status" aria-live="polite"')) throw new Error("Policy demo decision must be announced to assistive technology.");
if (!home.includes('data-demo-case="read" aria-pressed="true"')) throw new Error("Policy demo needs an accessible selected scenario state.");
if (!home.includes('data-demo-approve class="run-case" data-ko="승인 · 모의 실행"')) throw new Error("Approval demo action must be bilingual.");
for (const page of ["platform.html", "technology.html", "security.html", "research.html", "company.html", "contact.html", "privacy.html", "lab.html", "local-console.html"]) {
  if (!home.includes("./" + page)) throw new Error("Homepage is missing navigation to " + page);
}

const sitemap = fs.readFileSync(path.join(site, "sitemap.xml"), "utf8");
for (const page of ["platform.html", "technology.html", "security.html", "research.html", "company.html", "contact.html", "privacy.html"]) {
  if (!sitemap.includes("/" + page)) throw new Error("Sitemap is missing " + page);
}
console.log("Custos website validation passed: corporate pages, standalone tools, local links, bilingual controls, threat model, sitemap, and demo behavior.");

const lab = fs.readFileSync(path.join(site, "lab.html"), "utf8");
if (!lab.includes('href="./index.html"')) throw new Error("Lab is missing a return link to the corporate website.");
const localConsole = fs.readFileSync(path.join(site, "local-console.html"), "utf8");
if (!localConsole.includes('href="./lab.html"') || !localConsole.includes('href="./index.html"')) {
  throw new Error("Local Control Room must link back to both the Lab and corporate website.");
}
