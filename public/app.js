// CVSS calculator front end. All scoring happens on the server via POST /v1/score.
const BASE = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];
const TEMPORAL = ["E", "RL", "RC"];
const state = {};
const $ = (id) => document.getElementById(id);

function vectorString() {
  const parts = BASE.filter((k) => state[k]).map((k) => `${k}:${state[k]}`);
  for (const k of TEMPORAL) if (state[k] && state[k] !== "X") parts.push(`${k}:${state[k]}`);
  return `CVSS:3.1/${parts.join("/")}`;
}

function fromVector(v) {
  for (const k of [...BASE, ...TEMPORAL]) state[k] = undefined;
  for (const part of v.replace(/^CVSS:3\.1\//, "").split("/")) {
    const [k, val] = part.split(":");
    if (k && val) state[k] = val;
  }
}

function render(result) {
  $("base-score").textContent = result.baseScore.toFixed(1);
  $("base-sev").textContent = result.baseSeverity;
  $("base-sev").dataset.sev = result.baseSeverity;
  $("temporal-score").textContent = result.temporalScore.toFixed(1);
  $("temporal-sev").textContent = result.temporalSeverity;
  $("temporal-sev").dataset.sev = result.temporalSeverity;
  $("impact").textContent = result.impactSubscore.toFixed(1);
  $("exploit").textContent = result.exploitabilitySubscore.toFixed(1);
}

function clearScores(message) {
  for (const id of ["base-score", "temporal-score", "impact", "exploit"]) $(id).textContent = "-";
  $("base-sev").textContent = message;
  $("temporal-sev").textContent = "";
  delete $("base-sev").dataset.sev;
}

async function scoreNow() {
  const vector = vectorString();
  $("vector").value = vector;
  syncButtons();
  const missing = BASE.filter((k) => !state[k]);
  if (missing.length) return clearScores(`Choose ${missing.join(", ")}`);
  try {
    const res = await fetch("/v1/score", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ vector }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
    $("error").hidden = true;
    render(data);
  } catch (e) {
    $("error").textContent = e.message;
    $("error").hidden = false;
  }
}

function syncButtons() {
  document.querySelectorAll("button[data-metric]").forEach((b) => {
    const sel = state[b.dataset.metric] === b.dataset.value || (!state[b.dataset.metric] && b.dataset.value === "X");
    b.setAttribute("aria-pressed", String(sel));
  });
}

function group(key, def, temporal) {
  const fs = document.createElement("fieldset");
  const lg = document.createElement("legend");
  lg.textContent = `${def.name} (${key})`;
  fs.append(lg);
  const row = document.createElement("div");
  row.className = "options";
  for (const [value, v] of Object.entries(def.values)) {
    const b = document.createElement("button");
    b.type = "button";
    b.dataset.metric = key;
    b.dataset.value = value;
    b.textContent = v.label;
    b.title = `${key}:${value}`;
    b.addEventListener("click", () => {
      state[key] = value;
      scoreNow();
    });
    row.append(b);
  }
  fs.append(row);
  if (temporal) fs.classList.add("temporal");
  return fs;
}

async function init() {
  try {
    const [defs, health] = await Promise.all([fetch("/v1/metrics").then((r) => r.json()), fetch("/healthz").then((r) => r.json())]);
    $("version").textContent = `SecureShip v${health.version}`;
    const root = $("metrics");
    root.textContent = "";
    const baseSec = document.createElement("section");
    baseSec.innerHTML = "<h2>Base metrics</h2>";
    for (const k of BASE) baseSec.append(group(k, defs.base[k], false));
    const tSec = document.createElement("section");
    tSec.innerHTML = "<h2>Temporal metrics <span class=\"muted small\">optional</span></h2>";
    for (const k of TEMPORAL) tSec.append(group(k, defs.temporal[k], true));
    root.append(baseSec, tSec);
    fromVector($("vector").value);
    scoreNow();
  } catch {
    $("metrics").innerHTML = '<p class="error">Could not load metric definitions from the API.</p>';
  }
}

$("vector-form").addEventListener("submit", (e) => {
  e.preventDefault();
  fromVector($("vector").value.trim());
  scoreNow();
});
init();
