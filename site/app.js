// Hidden Text X-Ray page. All analysis happens in pkg/xray_bg.wasm; this file
// only draws the result. Visitor text is only ever inserted as text nodes.
import init, { xray } from "./pkg/xray.js";

const GROUPS = [
  ["tricks", "Hiding tricks"],
  ["normal", "Normal text"],
  ["limits", "Where it stops"],
];

// Plain-English names for deobfuscate's steps. Unknown kinds show their own name.
const STEP_NAMES = {
  "homoglyph": "Swapped look-alike letters back",
  "script-intrusion": "Found a letter from another alphabet inside a word",
  "skeleton-match": "Matched a disguised keyword by its shape",
  "invisible-strip": "Removed invisible characters",
  "bidi-control": "Removed zero-width and direction characters",
  "base64": "Decoded a base64 payload",
  "fullwidth-chars": "Converted wide letters to normal letters",
  "split-string": "Rejoined a keyword split apart",
  "entropy-bigram": "Noticed text that doesn't read like language",
  "rot13": "Decoded a letter-shift (ROT13) cipher",
  "leetspeak": "Converted number-for-letter spelling",
  "url-encoding": "Decoded %-encoded text",
  "html-entities": "Decoded HTML character codes",
  "unicode-escape": "Decoded \\u escape sequences",
  "backslash-escape": "Removed backslash escaping",
  "morse-code": "Decoded Morse code",
  "punycode": "Decoded a disguised web address (punycode)",
  "pre-scan-nfc": "Normalized combined characters",
  "cjk-superposition": "Stopped: an injection seam between alphabets",
};

const VERDICTS = {
  clean: ["Clean", "Nothing hidden was found."],
  flag: ["Flag for review", "Something unusual is here. A person should look before an AI model acts on it."],
  block: ["Block", "Hidden content found. This should not reach an AI model as-is."],
};

const $ = (id) => document.getElementById(id);
function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k === "style") n.style.cssText = v;
    else n.setAttribute(k, v);
  }
  for (const k of kids) if (k != null) n.append(k);
  return n;
}

// Same rule as the Rust tests: each hidden character becomes its invisible tag twin.
const withHidden = (e) =>
  e.text + [...(e.hidden || "")].map((c) => String.fromCodePoint(0xe0000 + c.codePointAt(0))).join("");

function hex(cp) {
  return "U+" + cp.toString(16).toUpperCase().padStart(4, "0");
}

// Characters a person can't see become visible chips. A run of hidden tags is
// one chip that spells out the hidden message.
function drawStrip(chars) {
  const strip = el("div", { class: "strip" });
  let plain = "";
  const flush = () => { if (plain) { strip.append(el("span", { class: "c" }, plain)); plain = ""; } };
  for (let i = 0; i < chars.length; i++) {
    const c = chars[i];
    if (c.invisible && c.invisible.startsWith("hidden tag '")) {
      let msg = "";
      while (i < chars.length && chars[i].invisible && chars[i].invisible.startsWith("hidden tag '")) {
        msg += String.fromCodePoint(chars[i].cp - 0xe0000);
        i++;
      }
      i--;
      flush();
      strip.append(el("span", { class: "inv", title: `${msg.length} invisible tag characters` },
        "hidden message: ", el("b", {}, `“${msg}”`)));
    } else if (c.invisible) {
      flush();
      strip.append(el("span", { class: "inv", title: `${hex(c.cp)} ${c.invisible}` }, c.invisible));
    } else if (c.imitates) {
      flush();
      strip.append(el("span", { class: "mark look", title: `${hex(c.cp)} ${c.script} letter imitating “${c.imitates}”` },
        el("span", { class: "g" }, c.ch), el("span", { class: "n" }, `${c.script} ≠ ${c.imitates}`)));
    } else if (c.intrusion) {
      flush();
      strip.append(el("span", { class: "mark other", title: `${hex(c.cp)} ${c.script} letter` },
        el("span", { class: "g" }, c.ch)));
    } else {
      plain += c.ch;
    }
  }
  flush();
  return strip;
}

function drawVerdict(r) {
  const [label, text] = VERDICTS[r.verdict];
  const pct = (v) => `${Math.round(Math.min(1, Math.max(0, v)) * 100)}%`;
  const meter = el("div", { class: "meter", role: "img",
    "aria-label": `score ${r.score.toFixed(2)}; flag at ${r.flag_threshold}, block at ${r.block_threshold}` },
    el("div", { class: "fill", style: `width:${pct(r.score)}` }),
    el("div", { class: "tick", style: `left:${pct(r.flag_threshold)}`, title: "flag threshold" }),
    el("div", { class: "tick", style: `left:${pct(r.block_threshold)}`, title: "block threshold" }));
  let why = text;
  if (r.verdict !== "clean" && r.steps.length === 0) {
    why += " No single trick was found; the overall score crossed the line on its own.";
  }
  return el("div", { class: `panel verdict v-${r.verdict}` },
    el("span", { class: "badge" }, label), meter,
    el("p", { class: "verdict-text", style: "margin:0" }, `${why} Score ${r.score.toFixed(2)}.`));
}

// Display only: the same ranges as invisible_name() in xray/src/lib.rs.
function isInvisible(cp) {
  return cp === 0xad || (cp >= 0x200b && cp <= 0x200f) || (cp >= 0x202a && cp <= 0x202e) ||
    (cp >= 0x2060 && cp <= 0x2064) || (cp >= 0x2066 && cp <= 0x2069) || cp === 0xfeff ||
    (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0000 && cp <= 0xe007f) || (cp >= 0xe0100 && cp <= 0xe01ef);
}

// "before" text with what the step changed made visible: letters that differ
// from "after" are highlighted, and invisible characters become a marker.
function showChanges(before, after) {
  const b = [...before], a = [...after];
  const sameLength = b.length === a.length;
  const dd = el("dd");
  let plain = "";
  const flush = () => { if (plain) { dd.append(plain); plain = ""; } };
  for (let i = 0; i < b.length; i++) {
    if (isInvisible(b[i].codePointAt(0))) {
      let n = 0;
      while (i < b.length && isInvisible(b[i].codePointAt(0))) { n++; i++; }
      i--;
      flush();
      dd.append(el("span", { class: "inv small" }, n === 1 ? "1 invisible" : `${n} invisible`));
    } else if (sameLength && b[i] !== a[i]) {
      flush();
      dd.append(el("span", { class: "diff" }, b[i]));
    } else {
      plain += b[i];
    }
  }
  flush();
  return dd;
}

function drawSteps(steps) {
  if (!steps.length) return el("p", { class: "empty" }, "Nothing to undo.");
  const wrap = el("div", { class: "steps" });
  steps.forEach((s, i) => {
    const ba = el("dl", { class: "ba" });
    if (s.original !== s.normalized) {
      ba.append(el("dt", {}, "before"), s.original ? showChanges(s.original, s.normalized) : el("dd", {}, "∅"),
        el("dt", {}, "after"), el("dd", {}, s.normalized || "(removed)"));
    }
    wrap.append(el("div", { class: "step" },
      el("h3", {}, `${i + 1}. ${STEP_NAMES[s.kind] || s.kind}`,
        el("span", { class: "conf" }, `${Math.round(s.confidence * 100)}% confidence`)),
      el("p", { class: "detail" }, s.detail), ba));
  });
  return wrap;
}

function render(r) {
  const out = $("results");
  const legend = el("div", { class: "legend" },
    el("span", { class: "l1" }, "look-alike letter"), el("span", { class: "l2" }, "invisible character"),
    el("span", { class: "l3" }, "letter from another alphabet"));
  out.replaceChildren(...[
    el("h2", {}, "Verdict"), drawVerdict(r),
    el("h2", {}, "What's actually there"), el("div", { class: "panel" }, drawStrip(r.chars), legend),
    el("h2", {}, "Step by step"), el("div", { class: "panel" }, drawSteps(r.steps)),
    el("h2", {}, "What the AI model would receive"),
    el("div", { class: "panel" }, r.halted
      ? el("p", { class: "empty" }, "Nothing. This text is refused outright.")
      : el("pre", { class: "out" }, r.normalized || " ")),
    r.truncated ? el("p", { class: "notice" }, "Only the first 4,000 characters were inspected.") : null,
  ].filter(Boolean));
}

async function main() {
  await init();
  const examples = await (await fetch("examples.json")).json();
  const input = $("input");
  const buttons = [];
  const buttonFor = new Map();

  const run = () => {
    if (!input.value) { $("results").replaceChildren(); return; }
    render(JSON.parse(xray(input.value)));
  };
  const pick = (e, btn) => {
    input.value = withHidden(e);
    $("blurb").textContent = e.blurb;
    buttons.forEach((b) => b.setAttribute("aria-pressed", String(b === btn)));
    run();
  };

  for (const [id, name] of GROUPS) {
    const row = el("div", { class: "group" }, el("span", { class: "group-label" }, name));
    for (const e of examples.filter((x) => x.group === id)) {
      const b = el("button", { class: "ex", type: "button", "aria-pressed": "false" }, e.label);
      b.addEventListener("click", () => pick(e, b));
      buttons.push(b);
      buttonFor.set(e, b);
      row.append(b);
    }
    $("groups").append(row);
  }

  let timer;
  input.addEventListener("input", () => {
    buttons.forEach((b) => b.setAttribute("aria-pressed", "false"));
    $("blurb").textContent = "";
    clearTimeout(timer);
    timer = setTimeout(run, 120);
  });

  // A link like …/#tags opens straight onto that example.
  const start = Math.max(0, examples.findIndex((e) => e.id === location.hash.slice(1)));
  pick(examples[start], buttonFor.get(examples[start]));
}

main().catch((err) => {
  $("results").replaceChildren(el("p", { class: "notice" }, `The detector failed to load: ${err.message}`));
});
