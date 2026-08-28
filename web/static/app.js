/* ===================== RACEMAP front-end (vanilla JS) ===================== */
"use strict";

// Theme is held in a JS variable (NO localStorage — not permitted in this app).
let THEME = "light";
let LAST = null;          // last scan payload
let PAGE = 1, PER = 10;   // pagination state

const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g,
  c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const trunc = (s, n = 14) => { s = String(s ?? ""); return s.length > n ? s.slice(0, n) + "…" : s; };

/* ---------- inline SVG icons (currentColor; render in headless Chromium) ---------- */
const ICON = {
  sun: '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M19.1 4.9l-1.4 1.4M6.3 17.7l-1.4 1.4"/></svg>',
  moon: '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z"/></svg>',
  download: '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12"/><path d="M7 11l5 5 5-5"/><path d="M5 21h14"/></svg>',
  check: '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M5 13l4 4L19 7"/></svg>',
  chevron: '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>',
  warn: '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l9 16H3z"/><path d="M12 10v4"/><path d="M12 17h.01"/></svg>',
};

/* ---------- theme ---------- */
function applyTheme() {
  document.documentElement.setAttribute("data-theme", THEME);
  const dark = THEME === "dark";
  $("#themeToggle").innerHTML = (dark ? ICON.sun : ICON.moon) +
    `<span class="lbl-text">${dark ? "Light" : "Dark"}</span>`;
  if (LAST) { renderChart(LAST.by_subsystem); drawGraphIfOpen(); }
}
function toggleTheme() { THEME = THEME === "dark" ? "light" : "dark"; applyTheme(); }
$("#themeToggle").onclick = toggleTheme;

/* ---------- tab + subtab nav ---------- */
$$("#nav a").forEach(a => a.onclick = () => {
  $$("#nav a").forEach(x => x.classList.remove("active"));
  a.classList.add("active");
  const t = a.dataset.tab;
  $$(".tab").forEach(s => s.classList.toggle("active", s.dataset.tab === t));
});
$$("#scanTabs a").forEach(a => a.onclick = () => {
  $$("#scanTabs a").forEach(x => x.classList.remove("active"));
  a.classList.add("active");
  const s = a.dataset.sub;
  $$(".subpane").forEach(p => p.classList.toggle("active", p.dataset.sub === s));
  if (s === "analysis") drawGraphIfOpen();
});

/* ---------- helpers ---------- */
const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
function verdictClass(v) {
  if (v === "likely_race")  return "race";
  if (v === "likely_safe")  return "safe";
  if (v === "triage_error") return "err";
  return "review";
}
function rowClass(v) {
  if (v === "likely_race") return "v-race";
  if (v === "likely_safe") return "v-safe";
  return "v-review";
}
const bool = (b) => b ? `<span style="color:var(--safe)">${ICON.check}</span>` : "·";

function setBusy(sel, label, done) {
  const b = $(sel); b.disabled = !done;
  const t = b.querySelector(".lbl-text");
  if (t) t.textContent = label; else b.textContent = label;
}
/* ---------- session log: capped, newest-on-top, dimmed history ---------- */
let SCAN_LOG = [];
const LOG_CAP = 5;
function startLogEntry(cmd) {
  $("#scanTerminal").classList.remove("hidden");
  SCAN_LOG.unshift({ ts: new Date().toLocaleTimeString(), cmd, lines: [] });
  if (SCAN_LOG.length > LOG_CAP) SCAN_LOG.length = LOG_CAP;   // drop old from array + DOM
  renderLog();
}
function logLine(line) {
  if (!SCAN_LOG.length) startLogEntry("");
  SCAN_LOG[0].lines.push(line);
  renderLog();
}
function renderLog() {
  const t = $("#scanTerminal");
  t.innerHTML = SCAN_LOG.map((e, i) => `
    <div class="log-entry ${i === 0 ? "top" : "dim"}">
      <div class="ts">${esc(e.ts)}</div>
      <div class="cmd">${esc(e.cmd)}</div>
      ${e.lines.map(l => `<div class="res">${esc(l)}</div>`).join("")}
    </div>`).join("");
  t.scrollTop = 0;   // snap to the newest (top) entry
}

/* ===================== SCAN ===================== */
$("#runScan").onclick = async () => {
  const kver = $("#kver").value.trim();
  if (!kver) { alert("Kernel version is required."); return; }   // never empty
  const body = {
    path: $("#kpath").value.trim() || "tests/sample_kernel",
    llm: $("#llm").value,
    kernel_version: kver,
    patch_gap: $("#patchGap").checked,
  };
  setBusy("#runScan", "Scanning…");
  startLogEntry(`$ racemap scan ${body.path} --llm ${body.llm} --kernel-version ${kver}`);
  try {
    const r = await fetch("/api/scan", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await r.json();
    if (!r.ok) { logLine("error: " + (data.error || r.status)); return; }
    LAST = data; PAGE = 1;
    renderScan(data);
  } catch (e) { logLine("error: " + e.message); }
  finally { setBusy("#runScan", "Run Scan", true); }
};

function renderScan(d) {
  $("#scanEmpty").classList.add("hidden");
  $("#scanMetrics").classList.remove("hidden");
  $("#scanTabs").classList.remove("hidden");
  const s = d.summary;
  $("#scanMetrics").innerHTML = [
    ["Candidates", s.candidates, ""],
    ["Likely races", s.races, "danger"],
    ["Exonerated", s.exonerated, "safe"],
    ["FP filtered", s.fp_filtered, "accent"],
    ["FP rate", s.fp_rate + "%", ""],
  ].map(([k, v, c]) =>
    `<div class="metric ${c}"><div class="k">${k}</div><div class="v">${esc(v)}</div></div>`
  ).join("");
  renderBackend(d.backend);
  logLine(`+ ${s.candidates} candidates · ${s.races} likely races · ${s.exonerated} exonerated`);
  renderChart(d.by_subsystem);
  renderTable();
  renderAnalysis(d.results);
  renderExport(d);
}

/* ---------- effective backend note (no silent fallback) ---------- */
function renderBackend(b) {
  const el = $("#backendNote");
  if (!b) { el.classList.add("hidden"); return; }
  el.classList.remove("hidden");
  el.classList.toggle("warn", !!b.fell_back);
  el.innerHTML = `<span class="dot"></span><span>backend: <b>${esc(b.effective)}</b> — ${esc(b.note)}</span>`;
  logLine(`backend: ${b.effective}${b.fell_back ? "  (requested " + b.requested + ", fell back)" : ""}`);
}

/* ---------- bar chart (theme-aware, fixed viewBox so it never collapses) ---------- */
function renderChart(by) {
  const subs = Object.keys(by || {});
  const wrap = $("#chartWrap");
  if (!subs.length) { wrap.innerHTML = ""; return; }
  // Fixed coordinate space; scales to container via width:100% + viewBox.
  const W = 760, H = 240, pad = 34, bw = 30;
  const maxV = Math.max(1, ...subs.map(k =>
    (by[k].likely_race || 0) + (by[k].likely_safe || 0) + (by[k].needs_review || 0)));
  const colW = (W - pad * 2) / subs.length;
  // race=danger, needs_review=warning, safe=accent — read live so theme toggle redraws.
  const cols = { likely_race: css("--danger"), needs_review: css("--warning"), likely_safe: css("--accent") };
  const axis = css("--text2"), line = css("--line");
  let bars = "", grid = "";
  for (let g = 1; g <= 3; g++) {
    const y = (H - pad) - (g / 3) * (H - pad * 2);
    grid += `<line x1="${pad}" y1="${y}" x2="${W - pad}" y2="${y}" stroke="${line}" stroke-dasharray="2 4" opacity="0.6"/>`;
    grid += `<text x="${pad - 6}" y="${y + 3}" text-anchor="end" font-size="9" fill="${axis}">${Math.round(maxV * g / 3)}</text>`;
  }
  subs.forEach((k, i) => {
    const x = pad + i * colW + colW / 2;
    let yBase = H - pad;
    ["likely_safe", "needs_review", "likely_race"].forEach(seg => {
      const val = by[k][seg] || 0;
      const h = (val / maxV) * (H - pad * 2);
      if (h > 0) {
        bars += `<rect x="${x - bw / 2}" y="${yBase - h}" width="${bw}" height="${h}" fill="${cols[seg]}" rx="2"/>`;
        yBase -= h;
      }
    });
    bars += `<text x="${x}" y="${H - pad + 15}" text-anchor="middle" font-size="10" fill="${axis}">${esc(trunc(k, 12))}</text>`;
  });
  const lg = (c, t) => `<span><i style="background:${css(c)}"></i>${t}</span>`;
  wrap.innerHTML = `<div class="ctitle">Candidates by subsystem</div>
    <svg width="100%" viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet" style="display:block">
      ${grid}
      <line x1="${pad}" y1="${H - pad}" x2="${W - pad}" y2="${H - pad}" stroke="${axis}"/>
      ${bars}</svg>
    <div class="legend">${lg("--danger", "likely race")}${lg("--warning", "needs review")}${lg("--accent", "likely safe")}</div>`;
}

/* ---------- results table + pagination ---------- */
function renderTable() {
  if (!LAST) return;
  const rows = LAST.results, total = rows.length;
  const pages = Math.max(1, Math.ceil(total / PER));
  if (PAGE > pages) PAGE = pages;
  const start = (PAGE - 1) * PER, slice = rows.slice(start, start + PER);
  const end = Math.min(start + PER, total);

  $("#pager").innerHTML = total ? `
    <button ${PAGE <= 1 ? "disabled" : ""} id="prev">&lsaquo;</button>
    <span>Showing ${total ? start + 1 : 0}–${end} of ${total} · Page ${PAGE}/${pages}</span>
    <button ${PAGE >= pages ? "disabled" : ""} id="next">&rsaquo;</button>
    <span>Rows: <select id="per">
      ${[10, 25, 50].map(n => `<option ${n === PER ? "selected" : ""}>${n}</option>`).join("")}
    </select></span>` : "";
  if (total) {
    $("#prev").onclick = () => { PAGE--; renderTable(); };
    $("#next").onclick = () => { PAGE++; renderTable(); };
    $("#per").onchange = e => { PER = +e.target.value; PAGE = 1; renderTable(); };
  }

  const head = ["Rank", "Pattern", "Location", "Verdict", "Conf",
    "ESC", "LOCK", "BARR", "ANN", "IRQ", "WQ", "GIT"];
  const escIcon = b => b ? `<span style="color:var(--danger)">${ICON.warn}</span>` : "·";
  const body = slice.map(r => {
    const vc = verdictClass(r.verdict), loc = `${r.file}:${r.line}`;
    return `<tr class="${rowClass(r.verdict)}">
      <td>${(r.rank_score ?? 0).toFixed(2)}</td>
      <td><span class="chip">${esc(r.pattern_name || "—")}</span></td>
      <td class="loc" title="${esc(loc)}">${esc(loc)}</td>
      <td><span class="badge ${vc}">${esc((r.verdict || "").replace("likely_", "").replace("_", " "))}</span></td>
      <td>${r.confidence != null ? (r.confidence * 100).toFixed(0) + "%" : "—"}</td>
      <td class="ic" title="container escape">${escIcon(r.container_escape_potential)}</td>
      <td class="ic" title="caller lock held">${bool(r.caller_lock_held)}</td>
      <td class="ic" title="memory barrier">${bool(r.barrier_protected)}</td>
      <td class="ic" title="sparse annotation">${bool(r.annotation_protected)}</td>
      <td class="ic" title="interrupt context">${bool(!!r.interrupt_context_note)}</td>
      <td class="ic" title="workqueue async">${bool(r.workqueue_async)}</td>
      <td class="ic" title="recently modified (git)">${bool(r.recently_modified)}</td>
    </tr>`;
  }).join("");
  $("#resultsTable").innerHTML =
    `<table><thead><tr>${head.map(h => `<th>${h}</th>`).join("")}</tr></thead><tbody>${body}</tbody></table>`;
}

/* ---------- analysis cards + call graph ---------- */
let OPEN_IDX = -1;
function renderAnalysis(rows) {
  $("#analysisCards").innerHTML = rows.map((r, i) => {
    const vc = verdictClass(r.verdict);
    const steps = (r.reasoning_steps || []).map((s, n) => `${n + 1}. ${s}`).join("\n");
    return `<div class="acard" data-i="${i}">
      <div class="head">
        <div><span class="badge ${vc}">${esc((r.verdict || "").replace("likely_", ""))}</span>
          <b>&nbsp;${esc(r.pattern_name || "candidate")}</b>
          <span class="muted">&nbsp;${esc(r.file)}:${r.line}</span></div>
        <span class="muted">${ICON.chevron}</span>
      </div>
      <div class="body">
        <p>${esc(r.reasoning || r.message || "")}</p>
        ${steps ? `<pre>${esc(steps)}</pre>` : ""}
        <div class="graph-wrap"><button class="graph-reset" data-i="${i}">reset view</button>
          <svg id="graph" data-i="${i}"></svg></div>
        <div style="margin-top:10px"><a class="semgrep-btn" href="/api/semgrep/${i}">${ICON.download} Export as Semgrep Rule</a></div>
      </div></div>`;
  }).join("");
  $$(".acard .head").forEach(h => h.onclick = () => {
    const card = h.parentElement, i = +card.dataset.i;
    const wasOpen = card.classList.contains("open");
    $$(".acard").forEach(c => c.classList.remove("open"));
    if (!wasOpen) { card.classList.add("open"); OPEN_IDX = i; drawGraph(i); }
    else OPEN_IDX = -1;
  });
  $$(".graph-reset").forEach(btn => btn.onclick = (ev) => {
    ev.stopPropagation();
    const svg = $(`#graph[data-i="${btn.dataset.i}"]`);
    if (svg && svg.__fit) svg.__fit();
  });
}
function drawGraphIfOpen() { if (OPEN_IDX >= 0) drawGraph(OPEN_IDX); }

function graphData(r) {
  const nodes = [{ id: "candidate", t: "cand", label: r.pattern_name || "candidate" }];
  const links = [];
  if (r.zero_copy_primitive) { nodes.push({ id: "async", t: "async", label: r.zero_copy_primitive }); links.push(["candidate", "async"]); }
  if (r.shared_field)        { nodes.push({ id: "taint", t: "taint", label: r.shared_field }); links.push(["candidate", "taint"]); }
  if (r.taint_callee)        { nodes.push({ id: "callee", t: "taint", label: r.taint_callee }); links.push(["taint", "callee"]); }
  if (r.caller_lock_name)    { nodes.push({ id: "lock", t: "lock", label: r.caller_lock_name }); links.push(["candidate", "lock"]); }
  if (r.function)            { nodes.push({ id: "caller", t: "caller", label: r.function }); links.push(["caller", "candidate"]); }
  return { nodes, links };
}
const NODE_FILL = { cand: "--node-cand", async: "--node-async", taint: "--node-taint", lock: "--node-lock", caller: "--node-caller" };

function drawGraph(i) {
  const svg = $(`#graph[data-i="${i}"]`);
  if (!svg || !LAST) return;
  const r = LAST.results[i], g = graphData(r);
  if (window.d3) drawGraphD3(svg, g);
  else drawGraphStatic(svg, g);
}

/* D3 force-directed: draggable, zoom/pan, auto fit-to-view, spaced-out labels */
function drawGraphD3(svgEl, g) {
  const d3 = window.d3;
  const W = (svgEl.getBoundingClientRect().width || svgEl.clientWidth || 700), H = 380;
  d3.select(svgEl).selectAll("*").remove();
  const svg = d3.select(svgEl).attr("viewBox", `0 0 ${W} ${H}`);
  const root = svg.append("g");
  const zoom = d3.zoom().scaleExtent([0.2, 3]).on("zoom", e => root.attr("transform", e.transform));
  svg.call(zoom);
  const nodes = g.nodes.map(d => ({ ...d })), links = g.links.map(([s, t]) => ({ source: s, target: t }));
  const sim = d3.forceSimulation(nodes)
    .force("link", d3.forceLink(links).id(d => d.id).distance(220))
    .force("charge", d3.forceManyBody().strength(-600))
    .force("collide", d3.forceCollide().radius(64))
    .force("center", d3.forceCenter(W / 2, H / 2));
  const link = root.append("g").attr("stroke", css("--line")).attr("stroke-width", 1.5)
    .selectAll("line").data(links).join("line");
  const node = root.append("g").selectAll("g").data(nodes).join("g")
    .call(d3.drag()
      .on("start", (e, d) => { if (!e.active) sim.alphaTarget(.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on("drag", (e, d) => { d.fx = e.x; d.fy = e.y; })
      .on("end", (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }));
  node.append("circle").attr("r", d => d.t === "cand" ? 14 : 10)
    .attr("fill", d => css(NODE_FILL[d.t]));
  // EXACTLY ONE visible <text> per node (truncated). The full name lives only
  // in a <title> on the node group, so it is a hover tooltip and never rendered.
  node.append("text").text(d => trunc(d.label, 12))
    .attr("x", 0).attr("y", d => (d.t === "cand" ? 28 : 24))
    .attr("text-anchor", "middle").attr("dominant-baseline", "middle")
    .attr("font-size", 11).attr("font-family", "ui-monospace,monospace")
    .attr("fill", css("--node-label"));
  node.append("title").text(d => d.label);

  // Fit the rendered content (including labels) into the box via the zoom
  // transform, so all nodes are visible AND subsequent pan/zoom stay consistent.
  function fit(animate) {
    const b = root.node().getBBox();
    if (!b.width || !b.height) return;
    const pad = 28;
    const k = Math.min((W - pad * 2) / b.width, (H - pad * 2) / b.height, 1.4);
    const tX = (W - k * (2 * b.x + b.width)) / 2;
    const tY = (H - k * (2 * b.y + b.height)) / 2;
    const t = d3.zoomIdentity.translate(tX, tY).scale(k);
    (animate ? svg.transition().duration(400) : svg).call(zoom.transform, t);
  }
  svgEl.__fit = () => fit(true);   // reset-view button hook

  sim.on("tick", () => {
    link.attr("x1", d => d.source.x).attr("y1", d => d.source.y)
        .attr("x2", d => d.target.x).attr("y2", d => d.target.y);
    node.attr("transform", d => `translate(${d.x},${d.y})`);
  });
  // Fit once on the next frame (first open is not cut off) and again on settle.
  requestAnimationFrame(() => fit(false));
  sim.on("end", () => fit(true));
}

/* deterministic static SVG fallback (no d3 available) */
function drawGraphStatic(svgEl, g) {
  const W = svgEl.clientWidth || 700, H = 380, cx = W / 2, cy = H / 2;
  const others = g.nodes.filter(n => n.id !== "candidate");
  const pos = { candidate: [cx, cy] };
  others.forEach((nd, i) => {
    const a = (i / Math.max(1, others.length)) * 2 * Math.PI - Math.PI / 2;
    pos[nd.id] = [cx + 200 * Math.cos(a), cy + 120 * Math.sin(a)];
  });
  const lines = g.links.map(([s, t]) =>
    `<line x1="${pos[s][0]}" y1="${pos[s][1]}" x2="${pos[t][0]}" y2="${pos[t][1]}" stroke="${css("--line")}" stroke-width="1.5"/>`).join("");
  const circ = g.nodes.map(nd =>
    `<g><title>${esc(nd.label)}</title><circle cx="${pos[nd.id][0]}" cy="${pos[nd.id][1]}" r="${nd.t === "cand" ? 14 : 10}" fill="${css(NODE_FILL[nd.t])}"/>
       <text x="${pos[nd.id][0]}" y="${pos[nd.id][1] + (nd.t === "cand" ? 28 : 24)}" text-anchor="middle" dominant-baseline="middle" font-size="11" font-family="ui-monospace,monospace" fill="${css("--node-label")}">${esc(trunc(nd.label, 12))}</text></g>`).join("");
  svgEl.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svgEl.innerHTML = `<g class="graph-fallback">${lines}${circ}</g>`;
}

/* ---------- export pane ---------- */
function renderExport(d) {
  const s = d.summary;
  $("#exportPane").innerHTML = `
    <div class="export-row">
      <a href="/api/export/json">${ICON.download} JSON</a>
      <a href="/api/export/csv">${ICON.download} CSV</a>
      <a href="/api/export/sarif">${ICON.download} SARIF</a>
    </div>
    <div class="arsenal">racemap surfaced ${s.races} likely race(s) across ${s.candidates} candidate(s) — FP rate ${s.fp_rate}% — ground-truth validation retained.</div>`;
}

/* ===================== DIFF ===================== */
$("#runDiff").onclick = async () => {
  const body = { old: $("#diffOld").value.trim(), new: $("#diffNew").value.trim() };
  setBusy("#runDiff", "Diffing…");
  try {
    const r = await fetch("/api/diff", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json();
    if (!r.ok) { $("#diffResult").innerHTML = `<p class="badge err">${esc(d.error)}</p>`; return; }
    const s = d.summary;
    const cards = `<div class="cards3">
      <div class="metric danger"><div class="k">New</div><div class="v">${s.new}</div></div>
      <div class="metric safe"><div class="k">Resolved</div><div class="v">${s.resolved}</div></div>
      <div class="metric accent"><div class="k">Persistent</div><div class="v">${s.persistent}</div></div></div>`;
    const rows = d.results.map(e => `<tr>
      <td class="loc" title="${esc(e.file)}:${e.line}">${esc(e.file)}:${e.line}</td>
      <td><span class="chip">${esc(e.pattern || "—")}</span></td>
      <td><span class="pill ${e.status.toLowerCase()}">${esc(e.status)}</span></td>
      <td>${(e.score ?? 0).toFixed(2)}</td>
      <td>${esc(e.cve_id || "—")}</td></tr>`).join("");
    $("#diffResult").innerHTML = cards +
      `<table><thead><tr><th>Location</th><th>Pattern</th><th>Status</th><th>Score</th><th>CVE</th></tr></thead><tbody>${rows}</tbody></table>`;
  } catch (e) { $("#diffResult").innerHTML = `<p class="badge err">${esc(e.message)}</p>`; }
  finally { setBusy("#runDiff", "Run Diff", true); }
};

/* ===================== LIVE SCAN ===================== */
const dz = $("#dropzone"), fi = $("#fileInput");
let LIVE_FILE = null;
dz.onclick = () => fi.click();
fi.onchange = () => { if (fi.files[0]) { LIVE_FILE = fi.files[0]; dz.textContent = "Selected: " + LIVE_FILE.name; } };
["dragover", "dragenter"].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.add("drag"); }));
["dragleave", "drop"].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove("drag"); }));
dz.addEventListener("drop", e => {
  const f = e.dataTransfer.files[0]; if (f) { LIVE_FILE = f; dz.textContent = "Selected: " + f.name; }
});
$("#runLive").onclick = async () => {
  const fd = new FormData();
  if (LIVE_FILE) fd.append("file", LIVE_FILE);
  fd.append("preset", $("#livePreset").value);
  if (!LIVE_FILE && !$("#livePreset").value) { alert("Choose a preset or upload a .c file."); return; }
  setBusy("#runLive", "Scanning…");
  try {
    const r = await fetch("/api/live-scan", { method: "POST", body: fd });
    const d = await r.json();
    if (!r.ok) { $("#liveResult").innerHTML = `<p class="badge err">${esc(d.error)}</p>`; return; }
    const s = d.summary;
    $("#liveResult").innerHTML = `<div class="acard open"><div class="head"><b>${esc(d.filename)}</b>
      <span class="muted">${d.elapsed_ms} ms</span></div>
      <div class="body"><div class="cards3">
        <div class="metric"><div class="k">Candidates</div><div class="v">${s.candidates}</div></div>
        <div class="metric danger"><div class="k">Likely races</div><div class="v">${s.races}</div></div>
        <div class="metric safe"><div class="k">Exonerated</div><div class="v">${s.exonerated}</div></div>
      </div>${d.results.map(x => `<div style="margin:6px 0"><span class="badge ${verdictClass(x.verdict)}">${esc((x.verdict||"").replace("likely_",""))}</span> <b>${esc(x.pattern_name||"candidate")}</b> <span class="muted">${esc(x.file)}:${x.line}</span></div>`).join("")}</div></div>`;
  } catch (e) { $("#liveResult").innerHTML = `<p class="badge err">${esc(e.message)}</p>`; }
  finally { setBusy("#runLive", "Initialize Scan", true); }
};

/* ===================== PATCH GAP ===================== */
$$("#nav a").forEach(a => { if (a.dataset.tab === "patch") a.addEventListener("click", loadPatchGap); });
async function loadPatchGap() {
  const r = await fetch("/api/patch-gap"); const d = await r.json();
  if (!d.missing || !d.missing.length) {
    $("#patchResult").innerHTML = LAST
      ? `<p class="badge safe">No missing upstream patches detected.</p>`
      : `<p class="muted">Run a scan first — missing patches appear here.</p>`;
    return;
  }
  const rows = d.missing.map(m => `<tr>
    <td><span class="chip">${esc(m.signature_for || "—")}</span></td>
    <td>${m.count ?? 0}</td>
    <td>${esc((m.subsystems || []).join(", ") || "—")}</td></tr>`).join("");
  $("#patchResult").innerHTML =
    `<p class="muted small">Candidates whose known upstream patch signature is absent in the scanned tree.</p>
     <table><thead><tr><th>Missing signature</th><th>Count</th><th>Subsystems</th></tr></thead><tbody>${rows}</tbody></table>`;
}

/* ===================== CACHE ===================== */
$$("#nav a").forEach(a => { if (a.dataset.tab === "cache") a.addEventListener("click", loadCache); });
async function loadCache() {
  const r = await fetch("/api/cache-status"); const d = await r.json();
  $("#cacheStatus").innerHTML = `Cached triage responses: <b>${d.count}</b><br><span class="small mono">${esc(d.path)}</span>`;
}
$("#clearCache").onclick = async () => {
  const r = await fetch("/api/clear-cache", { method: "POST" }); const d = await r.json();
  $("#cacheStatus").innerHTML = `Cleared <b>${d.cleared}</b> cached response(s).`;
};

/* ===================== DATABASE (sidebar) ===================== */
async function loadDb() {
  try {
    const r = await fetch("/api/db-status"); const d = await r.json();
    $("#dbStatus").textContent = "Last updated: " + (d.last_updated || "never")
      + (d.age_days != null ? ` (${Math.round(d.age_days)}d ago)` : "");
  } catch { $("#dbStatus").textContent = "Last updated: unknown"; }
}
$("#updateDb").onclick = async () => {
  setBusy("#updateDb", "Updating…");
  try {
    const r = await fetch("/api/update-db", { method: "POST" }); const d = await r.json();
    $("#dbStatus").textContent = `Updated: ${d.updated} sig(s), +${d.new} new — ${d.timestamp}`;
  } catch (e) { $("#dbStatus").textContent = "Update failed: " + e.message; }
  finally { setBusy("#updateDb", "Update Patch DB", true); }
};

/* ===================== INIT ===================== */
applyTheme();
loadDb();
