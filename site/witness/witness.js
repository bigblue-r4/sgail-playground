// Tamper-Evident Farm Log page. The log, the hashing and both checks live in
// witness.wasm (Go); this file only draws the state it returns. Entry text is
// only ever inserted as text nodes.

const $ = (id) => document.getElementById(id);
function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else n.setAttribute(k, v);
  }
  for (const k of kids) if (k != null) n.append(k);
  return n;
}
const SVG = "http://www.w3.org/2000/svg";
function sv(tag, attrs = {}, text) {
  const n = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  if (text != null) n.textContent = text;
  return n;
}

// Entry 3 (index 2) is the remote change everyone wants to hide.
const KEY = 2;
const ATTACKS = [
  { id: "edit", label: "Change who did it",
    story: "Rewrote the 21:02 entry so the change looks like the crew's, not a remote login.",
    run: (w, s) => w.edit(KEY, JSON.stringify({ ...s.entries[KEY].data, by: "crew:ana" })) },
  { id: "erase", label: "Erase the remote change",
    story: "Deleted the 21:02 entry from the log file.",
    run: (w) => w.remove(KEY) },
  { id: "cut", label: "Cut off the end of the night",
    story: "Cut the last four entries off the log file, alarm included.",
    run: (w) => w.truncate(4) },
  { id: "nohead", label: "Delete the signed head",
    story: "Deleted the witness's signed head file, so there's nothing to check the log against.",
    run: (w) => w.deleteHead() },
  { id: "full", label: "Full cover-up on the machine",
    story: "Erased the 21:02 entry, then used the farm computer's own keys to sign a fresh head for the edited log.",
    run: (w) => { w.remove(KEY); return w.resign(); } },
];

let state;
let editing = -1;
let editError = "";

function call(json) {
  const r = JSON.parse(json);
  state = r.state;
  return r.error;
}

// Plain words for one farm-feed entry.
function describe(e) {
  const d = e.data || {};
  switch (d.kind) {
    case "heartbeat": return "Controller heartbeat";
    case "reading":
      return `${d.metric === "ammonia_ppm" ? "Ammonia" : d.metric[0].toUpperCase() + d.metric.slice(1)} ${d.value} ${d.unit || ""}`.trim();
    case "setting_change": {
      const name = d.setting === "min_ventilation_pct" ? "Minimum ventilation" : d.setting;
      const pct = d.setting.endsWith("_pct") ? "%" : "";
      return `${name} ${d.from}${pct} → ${d.to}${pct}, by ${d.by}`;
    }
    case "alarm": return `ALARM: ${String(d.alarm).replace(/_/g, " ")}, ${d.value} ${d.unit || ""} (${d.severity})`;
    case "access": return `${d.person} ${d.direction === "in" ? "entered" : "left"} ${d.door}`;
    default: return e.event;
  }
}

function time(ts) {
  return ts.slice(11, 16);
}

function changedLeaves(node, out = new Set()) {
  if (!node) return out;
  if (node.leaf >= 0 && node.changed) out.add(node.leaf);
  (node.children || []).forEach((c) => changedLeaves(c, out));
  return out;
}

function drawChecks() {
  const v = state.verify, a = state.audit;
  const box = (where, cmd, c, okText, badText) => {
    const cls = c.ok ? (c.status === "behind" ? "warn" : "ok") : "bad";
    return el("div", { class: `check ${cls}` },
      el("p", { class: "where" }, where, " ", el("span", { class: "cmd" }, cmd)),
      el("p", { class: "verdict" }, c.ok ? okText : badText),
      el("p", { class: "msg" }, c.message));
  };
  $("checks").replaceChildren(
    box("On the farm computer", "witness verify", v, "✓ Log is intact", "✗ Tampering detected"),
    box("Copy kept elsewhere", "witness audit", a, "✓ Mirror agrees", "✗ Mirror disagrees"));

  let text;
  if (!v.ok) text = "The witness refuses this log. Its signed head no longer matches what the log file says, so the change is caught on the farm computer itself.";
  else if (!a.ok) text = "The farm computer is fooled: with its keys, the rewritten log carries a valid signature. But the copy of the head kept elsewhere still has the original, and it disagrees. That's why the mirror belongs on a different machine.";
  else if (a.status === "behind") text = "The log has new entries the mirror hasn't seen yet. That's normal lag, not tampering.";
  else text = "Nothing has been changed. Pick a cover-up above, or edit or delete an entry yourself.";
  $("explain").textContent = text;
}

function drawLog() {
  const changed = changedLeaves(state.tree);
  const rows = state.entries.map((e, i) => {
    const row = el("div", { class: `row${changed.has(i) ? " changed" : ""}${e.level === "WARN" ? " warnrow" : ""}` },
      el("span", { class: "time" }, time(e.ts)),
      el("div", {}, el("div", { class: "what" }, describe(e)),
        el("div", { class: "src" }, `#${e.seq} · ${(e.data && e.data.source) || e.source}`)));
    const edit = el("button", { type: "button", "aria-label": `Edit entry ${e.seq}` }, "Edit");
    const del = el("button", { type: "button", "aria-label": `Delete entry ${e.seq}` }, "Delete");
    edit.addEventListener("click", () => { editing = i; editError = ""; drawLog(); });
    del.addEventListener("click", () => { pressed(null); call(window.witness.remove(i)); editing = -1; draw(); });
    row.append(el("div", { class: "tools" }, edit, del));
    if (editing === i) {
      const ta = el("textarea", { spellcheck: "false", "aria-label": "Entry data (JSON)" });
      ta.value = JSON.stringify(e.data, null, 1);
      const save = el("button", { type: "button" }, "Save change");
      const cancel = el("button", { type: "button" }, "Cancel");
      save.addEventListener("click", () => {
        const err = call(window.witness.edit(i, ta.value));
        if (err) { editError = err; drawLog(); return; }
        pressed(null); editing = -1; draw();
      });
      cancel.addEventListener("click", () => { editing = -1; drawLog(); });
      row.append(el("div", { class: "editor" }, ta, el("div", { class: "btns" }, save, cancel),
        editError ? el("div", { class: "err" }, editError) : null));
    }
    return row;
  });
  if (!rows.length) rows.push(el("p", { class: "loading" }, "The log file is empty."));
  $("log").replaceChildren(...rows);
}

function drawTools() {
  const tool = (label, fn) => {
    const b = el("button", { type: "button" }, label);
    b.addEventListener("click", () => { pressed(null); call(fn()); editing = -1; draw(); });
    return b;
  };
  $("tools").replaceChildren(
    tool("Re-sign the head with the machine's keys", () => window.witness.resign()),
    tool("Delete the head file", () => window.witness.deleteHead()),
    tool("Cut off the last entry", () => window.witness.truncate(1)));
}

function short(h) { return h ? h.slice(0, 12) + "…" : "—"; }

function drawHeads() {
  const now = state.tree ? state.tree.hash : "";
  const head = state.head;
  const mark = (h) => el("span", { class: h && h === now ? "match" : "nomatch" },
    short(h), h && h === now ? "  ✓ matches" : "  ✗ doesn't match");
  $("heads").replaceChildren(
    el("dt", {}, "Log now hashes to"), el("dd", {}, short(now), `  (${state.entries.length} entries)`),
    el("dt", {}, "Signed head says"), el("dd", {}, head ? mark(head.root) : el("span", { class: "nomatch" }, "head file missing")),
    el("dt", {}, "Mirror copy says"), el("dd", {}, mark(state.mirror.root), `  (${state.mirror.size} entries)`));
}

// Leaves along the bottom, each parent centred over its children.
function drawTree() {
  const root = state.tree;
  if (!root) { $("tree").replaceChildren(el("p", { class: "loading" }, "No entries, no tree.")); return; }
  const leaves = [];
  let depth = 0;
  (function walk(n, d) { depth = Math.max(depth, d); if (n.leaf >= 0) leaves.push(n); (n.children || []).forEach((c) => walk(c, d + 1)); })(root, 0);
  const gap = 84, top = 26, rowH = 62, W = Math.max(leaves.length * gap, 340);
  const H = top + depth * rowH + 46;
  const svg = sv("svg", { class: "tree", viewBox: `0 0 ${W} ${H}`, role: "img",
    "aria-label": `Merkle tree of ${leaves.length} entries; red nodes changed since the witness signed it` });
  const pos = new Map();
  leaves.forEach((n, i) => pos.set(n, { x: (i + 0.5) * (W / leaves.length), y: top + depth * rowH }));
  (function place(n, d) {
    if (n.leaf >= 0) return pos.get(n);
    const kids = n.children.map((c) => place(c, d + 1));
    const p = { x: (kids[0].x + kids[kids.length - 1].x) / 2, y: top + d * rowH };
    pos.set(n, p);
    return p;
  })(root, 0);
  const lines = [], nodes = [];
  (function draw(n) {
    const p = pos.get(n);
    for (const c of n.children || []) {
      const q = pos.get(c);
      lines.push(sv("line", { x1: p.x, y1: p.y, x2: q.x, y2: q.y, class: c.changed ? "changed" : "" }));
      draw(c);
    }
    const cls = (n.changed ? "changed " : "") + (n === root ? "root" : "");
    nodes.push(sv("circle", { cx: p.x, cy: p.y, r: n === root ? 11 : 8, class: cls.trim() }));
    if (n === root) nodes.push(sv("text", { x: p.x, y: p.y - 16, class: n.changed ? "changed" : "" }, `root ${n.hash.slice(0, 8)}`));
    if (n.leaf >= 0) {
      const e = state.entries[n.leaf];
      nodes.push(sv("text", { x: p.x, y: p.y + 24, class: "leaf" + (n.changed ? " changed" : "") }, time(e.ts)));
      nodes.push(sv("text", { x: p.x, y: p.y + 38, class: n.changed ? "changed" : "" }, n.hash.slice(0, 6)));
    }
  })(root);
  svg.append(...lines, ...nodes);
  $("tree").replaceChildren(svg);
}

function draw() {
  drawChecks();
  drawLog();
  drawHeads();
  drawTree();
}

const buttons = new Map();
function pressed(id) {
  for (const [k, b] of buttons) b.setAttribute("aria-pressed", String(k === id));
  if (id === null) $("story").textContent = "Your own change. Here's what the witness makes of it:";
}

function runAttack(a) {
  call(window.witness.reset());
  a.run(window.witness, state);
  call(window.witness.state());
  editing = -1;
  pressed(a.id);
  $("story").textContent = a.story;
  draw();
}

async function main() {
  const go = new Go();
  const { instance } = await WebAssembly.instantiateStreaming(fetch("witness.wasm"), go.importObject);
  go.run(instance);
  call(window.witness.state());

  for (const a of ATTACKS) {
    const b = el("button", { class: "atk", type: "button", "aria-pressed": "false" }, a.label);
    b.addEventListener("click", () => runAttack(a));
    buttons.set(a.id, b);
    $("attacks").append(b);
  }
  const reset = el("button", { class: "reset", type: "button" }, "Reset");
  reset.addEventListener("click", () => {
    call(window.witness.reset()); editing = -1; pressed("none"); $("story").textContent = ""; draw();
  });
  $("attacks").append(reset);
  drawTools();

  const start = ATTACKS.find((a) => a.id === location.hash.slice(1));
  if (start) runAttack(start); else draw();
}

main().catch((err) => {
  $("checks").replaceChildren(el("p", { class: "loading" }, `The witness failed to load: ${err.message}`));
});
