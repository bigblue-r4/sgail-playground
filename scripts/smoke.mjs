// Loads the built browser package in Node and checks every example button
// against examples.json, using the page's own hidden-text rule.
import { readFileSync } from "node:fs";
import { initSync, xray } from "../site/pkg/xray.js";

initSync({ module: readFileSync(new URL("../site/pkg/xray_bg.wasm", import.meta.url)) });
const examples = JSON.parse(readFileSync(new URL("../site/examples.json", import.meta.url)));
const withHidden = (e) =>
  e.text + [...(e.hidden || "")].map((c) => String.fromCodePoint(0xe0000 + c.codePointAt(0))).join("");

let bad = 0;
for (const e of examples) {
  const r = JSON.parse(xray(withHidden(e)));
  const steps = r.steps.map((s) => s.kind);
  const ok = r.verdict === e.expect.verdict && JSON.stringify(steps) === JSON.stringify(e.expect.steps);
  console.log(`${ok ? "ok  " : "FAIL"} ${e.id.padEnd(10)} ${r.verdict.padEnd(5)} ${steps.join(",")}`);
  if (!ok) bad++;
}
if (bad) { console.error(`${bad} example(s) disagree with the page`); process.exit(1); }
console.log(`all ${examples.length} examples match`);
