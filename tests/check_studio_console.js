const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.resolve(__dirname, "..");
const consolePath = path.join(root, "simulation-studio", "local-console.html");
const studioPath = path.join(root, "simulation-studio", "index.html");
const apiPath = path.join(root, "custos_api.py");
const html = fs.readFileSync(consolePath, "utf8");
const studio = fs.readFileSync(studioPath, "utf8");
const api = fs.readFileSync(apiPath, "utf8");

const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/gi)].map(match => match[1]);
if (scripts.length !== 1) {
  throw new Error("Expected exactly one inline console script.");
}
scripts.forEach((source, index) => {
  new vm.Script(source, { filename: "local-console-inline-" + index + ".js" });
});

if (!html.includes('targetAddressSpace:"loopback"')) {
  throw new Error("Local console must explicitly declare the loopback address space.");
}
if (/localStorage\s*\.\s*setItem\s*\(/.test(html)) {
  throw new Error("Console must not persist credentials or state in localStorage.");
}
if (!studio.includes('href="./local-console.html"')) {
  throw new Error("Simulation Studio sidebar must link to Local API Console.");
}
if (!api.includes('https://hanyeolhui09twinx-art.github.io')) {
  throw new Error("API CORS allowlist must include the official Studio origin.");
}
for (const phrase of ["EXECUTION_UNKNOWN", "executed=null", "Keep this request ID", "Do not create a new ID", "setRequestLocked", 'decision==="EXECUTION_UNKNOWN"']) {
  if (!html.includes(phrase)) throw new Error("Local Control Room must explain and preserve an unknown execution outcome: " + phrase);
}
if (!html.includes('["action","resource","requestId","params","newId"]')) {
  throw new Error("Request fields and new-ID generation must remain locked until reconciliation.");
}
if (/Access-Control-Allow-Origin["']?\s*[,=:]\s*["']\*/.test(api)) {
  throw new Error("Wildcard CORS origin is forbidden.");
}

console.log("Local API Console JavaScript syntax and security wiring checks passed.");
