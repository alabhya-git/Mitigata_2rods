"use strict";
const $ = (id) => document.getElementById(id);
const roles = ["Recon", "Web", "Binary", "Correlator", "Falsifier", "Code", "Reporter"];
const state = { token: sessionStorage.getItem("mitigata-token") || "", run: null, report: null, stream: null, cursor: 0, timer: null, connected: false, loading: false, config: {} };
const esc = (v) => { const el = document.createElement("span"); el.textContent = String(v ?? ""); return el.innerHTML; };
const num = (v) => (v == null ? "—" : Number(v).toLocaleString());
function error(msg) { $("error").textContent = msg; $("error").hidden = !msg; }

async function api(path, options = {}) {
  const res = await fetch(path, { ...options, headers: { "Authorization": `Bearer ${state.token}`, "Content-Type": "application/json", ...(options.headers || {}) } });
  if (!res.ok) { let d = "request failed"; try { d = (await res.json()).detail || d; } catch (_) {} throw new Error(typeof d === "string" ? d : "invalid settings"); }
  return res;
}

function setView(view) {
  document.querySelectorAll(".view").forEach(el => el.classList.toggle("active", el.id === `${view}-view`));
  document.querySelectorAll(".tab").forEach(el => el.classList.toggle("selected", el.dataset.view === view));
}
document.querySelectorAll(".tab").forEach(el => el.addEventListener("click", () => setView(el.dataset.view)));
document.addEventListener("keydown", e => { const m = { F1: "overview", F2: "findings", F3: "graph", F4: "activity", F5: "report" }[e.key]; if (m) { e.preventDefault(); setView(m); } });

/* ----------------------------------------------------------- renderers */
function renderAgents(report) {
  $("agent-bars").innerHTML = roles.map(role => {
    const running = (report?.tasks || []).some(t => t.role === role && t.status === "running");
    const counts = report?.agent_stats?.[role] || {};
    const done = counts.completed ?? 0;
    const bar = running ? "▓▓▓▓" : done ? "▓▓░░" : "░░░░";
    return `<span class="ag ${running ? "on" : ""}" data-briefing="${role}" tabindex="0"><span class="nm">${role.toLowerCase()}</span><span class="bar">${bar}</span><span class="n">${done}</span></span>`;
  }).join("");
  document.querySelectorAll("[data-briefing]").forEach(el => el.onclick = () => showBriefing(el.dataset.briefing));
}
function markOf(status) { return status === "confirmed" ? ["ok", "✓"] : status === "rejected" ? ["bad", "✗"] : ["wait", "·"]; }
function sevClass(s) { return s === "high" ? "high" : s === "low" ? "low" : ""; }
function findingRow(f, big) {
  const [cls, mark] = markOf(f.data.status);
  const name = big ? `${esc(f.data.title)}<small>${esc(f.data.primitive)}</small>` : esc(f.data.primitive);
  const meta = big ? `<span class="meta">${f.evidence.length} rec ↗</span>` : "";
  return `<div class="row click" data-finding="${esc(f.id)}" tabindex="0"><span class="mark ${cls}">${mark}</span><span class="sev ${sevClass(f.data.severity)}">${esc(f.data.severity)}</span><span class="nm2">${name}</span><span class="tgt">${esc(f.data.target)}</span>${meta}</div>`;
}
function flagRow(f, big) {
  const d = f.data;
  const meta = big ? `<span class="meta">${(f.evidence || []).length} rec ↗</span>` : "";
  const shown = d.value ? `<code class="flagval">${esc(d.value)}</code>` : esc(d.source_url);
  return `<div class="row click flagrow" data-flag="${esc(f.id)}" tabindex="0"><span class="mark flag">★</span><span class="sev flag">flag</span><span class="nm2">captured flag ${big ? `<small>${esc(d.capture_basis || "")}</small>` : ""}<span class="badge ${esc(d.status)}">${esc(d.status)}</span></span><span class="tgt">${shown}</span>${meta}</div>`;
}
function wireFindings() {
  document.querySelectorAll("[data-finding]").forEach(el => { el.onclick = () => showFinding(el.dataset.finding); el.onkeydown = e => { if (e.key === "Enter") showFinding(el.dataset.finding); }; });
  document.querySelectorAll("[data-flag]").forEach(el => { el.onclick = () => showFlag(el.dataset.flag); el.onkeydown = e => { if (e.key === "Enter") showFlag(el.dataset.flag); }; });
}
function renderFindings() {
  const filter = $("finding-filter").value;
  const flags = (filter === "all" || filter === "confirmed") ? (state.report?.flags || []) : [];
  const list = (state.report?.findings || []).filter(f => filter === "all" || f.data.status === filter);
  $("findings-body").innerHTML = flags.map(f => flagRow(f, true)).join("") + list.map(f => findingRow(f, true)).join("");
  $("findings-empty").hidden = (flags.length + list.length) > 0;
  wireFindings();
}
function logLines(events) {
  return events.slice(-200).map(e => `<div class="row"><span class="ts">${new Date(e.created * 1000).toLocaleTimeString([], { hour12: false })}</span><span class="rl">${esc(e.role.toLowerCase())}</span><span class="kd">${esc(e.kind.replaceAll("_", " "))}</span><span class="lt">${esc(e.data.target || e.data.identity || e.data.status || "")}</span></div>`).join("");
}
function renderGraph(report) {
  const edges = report.graph.edges;
  if (!edges.length) { $("graph").innerHTML = '<p class="empty">an evidence path appears as prerequisites are established.</p>'; return; }
  const referenced = new Set(edges.flatMap(e => [e.data.from, e.data.to]));
  const records = [...report.findings, ...report.services, ...report.flags, ...report.graph.nodes];
  const W = 262, H = 80, COL = 334, ROWY = 122, X0 = 26, Y0 = 58;
  const positions = new Map(), columns = [[], [], []], seen = new Set();
  records.forEach(r => { const id = r.kind === "graph_node" ? r.identity : r.id; if (!referenced.has(id) || seen.has(id)) return; seen.add(id); const col = r.kind === "flag" ? 2 : r.kind === "graph_node" ? 1 : 0; columns[col].push({ ...r, nodeId: id }); });
  columns.forEach((items, col) => items.forEach((r, i) => positions.set(r.nodeId, { x: X0 + col * COL, y: Y0 + i * ROWY, record: r })));
  const rows = Math.max(...columns.map(c => c.length), 1);
  const height = Y0 + rows * ROWY + 8, width = X0 * 2 + 2 * COL + W;
  const heads = ["PREREQUISITES", "ACTION", "RESULT"].map((t, i) => `<text x="${X0 + i * COL}" y="36" class="graph-head">${t}</text>`).join("");
  const lines = edges.map(e => { const a = positions.get(e.data.from), b = positions.get(e.data.to); if (!a || !b) return ""; const v = e.data.state === "verified_authorized_transition"; const x1 = a.x + W, y1 = a.y + H / 2, x2 = b.x, y2 = b.y + H / 2; return `<path data-edge="${esc(e.id)}" class="gedge" d="M${x1} ${y1} C${x1 + 52} ${y1}, ${x2 - 52} ${y2}, ${x2} ${y2}" fill="none" stroke="${v ? "#6ec46e" : "#4a524d"}" stroke-width="${v ? 2.4 : 1.6}" ${v ? 'marker-end="url(#arrow)"' : 'stroke-dasharray="6 5"'}><title>${esc(e.data.relation)}</title></path>`; }).join("");
  const typeLabel = r => r.kind === "finding" ? "FINDING" : r.kind === "service" ? "SERVICE" : r.kind === "flag" ? "CAPTURED CODE" : "ACTION";
  const nodes = [...positions.values()].map(({ x, y, record: r }) => {
    const label = r.kind === "finding" ? r.data.primitive : r.kind === "service" ? `${r.data.protocol.toUpperCase()} :${r.data.port}` : r.kind === "flag" ? "validated code" : r.data.label;
    const sub = r.kind === "flag" ? r.data.status : r.kind === "service" ? r.data.address : r.kind === "finding" ? r.data.status : "requires all inputs";
    const accent = r.kind === "flag" ? "#6ec46e" : r.kind === "finding" ? "#d7a441" : r.kind === "service" ? "#5bb6b0" : "#8a93c9";
    return `<g transform="translate(${x},${y})"><rect width="${W}" height="${H}" rx="6" fill="#13171b" stroke="${accent}" stroke-opacity="0.4"/><rect width="4" height="${H}" rx="2" fill="${accent}"/><text x="18" y="23" class="graph-type" fill="${accent}">${typeLabel(r)}</text><text x="18" y="46" class="graph-label">${esc(String(label).slice(0, 30))}</text><text x="18" y="66" class="graph-sub">${esc(String(sub).slice(0, 34))}</text></g>`;
  }).join("");
  $("graph").innerHTML = `<svg viewBox="0 0 ${width} ${height}" aria-label="verified prerequisite and access graph"><defs><marker id="arrow" markerWidth="9" markerHeight="9" refX="7.5" refY="4" orient="auto"><path d="M0 0 L8 4 L0 8 z" fill="#6ec46e"/></marker></defs>${heads}${lines}${nodes}</svg>`;
  document.querySelectorAll("[data-edge]").forEach(el => el.onclick = () => { const e = edges.find(x => x.id === el.dataset.edge); dialog("transition evidence", `<p>${esc(e.data.relation)} · ${esc(e.data.state)}</p>${evidenceButtons(e.evidence)}`); });
}
function capRow(c) {
  const d = c.data || {};
  let word = "recorded", cls = "";
  if ("available" in d) { word = d.available ? "available" : (d.last_execution === "failed" ? "failed" : "unavailable"); cls = d.available ? "ok" : d.last_execution === "failed" ? "bad" : ""; }
  else if ("installed" in d || "live_allowed" in d) { word = d.live_allowed ? "live" : d.installed ? "present" : "absent"; cls = d.live_allowed ? "ok" : ""; }
  else if (c.identity === "runtime") { word = d.deterministic ? "deterministic" : "llm-assisted"; cls = "info"; }
  const bcls = cls === "ok" ? "confirmed" : cls === "bad" ? "failed" : "";
  return `<div class="row"><span class="badge ${bcls}">${esc(word)}</span><span class="nm2">${esc(c.identity)}</span><span class="tgt">${esc(d.reason || d.path || d.execution_profile || "")}</span></div>`;
}
function render(report) {
  state.report = report;
  const m = report.metrics, r = report.run;
  const external = r.manifest.mode !== "LOCAL_LAB";
  $("scope-label").textContent = external ? r.manifest.execution_profile.replaceAll("_", " ") : "loopback";
  $("run-name").textContent = r.manifest.name;
  $("run-status").textContent = r.status.replaceAll("_", " "); $("run-status").className = `tag ${r.status}`;
  $("elapsed-count").textContent = `${m.elapsed_seconds.toFixed(1)}s`;
  const ai = m.ai || {};
  $("ai-budget").textContent = ai.limit_usd ? `$${ai.spent_usd.toFixed(3)}/${ai.calls} calls` : "off";
  $("metrics").innerHTML = [
    ["svc", m.services_discovered, ""], ["endpoints", m.endpoints, ""],
    ["confirmed", m.confirmed, "ok"], ["rejected", m.rejected, "bad"],
    ["flags", m.captured_flags ?? m.validated_flags, "info"], ["cases", report.counts?.investigation_case || 0, ""],
  ].map(([k, v, c]) => `<span class="cell ${c}"><span class="k">${k}</span><span class="v">${num(v)}</span></span>`).join("");
  $("scope-cells").innerHTML = [
    ["req", num(m.requests_allowed), ""], ["blocked", num(m.blocked_attempts), m.blocked_attempts ? "warn" : "ok"],
    ["failed", num(m.failed_tasks), m.failed_tasks ? "bad" : "ok"],
    ["observer", m.independent_egress_observer, ""], ["briefing", `${num(m.max_briefing_bytes)}B`, ""],
  ].map(([k, v, c]) => `<span class="cell ${c}"><span class="k">${k}</span><span class="v">${esc(v)}</span></span>`).join("");
  $("task-summary").textContent = `${Object.values(report.agent_stats || {}).reduce((n, s) => n + (s.completed || 0), 0)} tasks complete`;
  renderAgents(report);

  const findings = report.findings || [];
  const ovFlags = (report.flags || []).map(f => flagRow(f, false)).join("");
  $("ov-findings").innerHTML = (ovFlags + findings.slice(0, 14).map(f => findingRow(f, false)).join("")) || '<p class="empty">no findings yet</p>';
  renderFindings();
  wireFindings();
  renderReport(report);

  $("ov-log").innerHTML = report.events.length ? logLines(report.events) : '<p class="empty">waiting for activity</p>';
  $("ov-log-count").textContent = `${report.events.length}`;
  $("ov-log").scrollTop = $("ov-log").scrollHeight;
  $("activity").innerHTML = report.events.length ? logLines(report.events) : '<p class="empty">no activity yet.</p>';
  $("event-count").textContent = `${report.events.length} events`;
  $("activity").scrollTop = $("activity").scrollHeight;

  const ho = report.handoffs || [];
  $("handoffs").innerHTML = ho.length ? ho.slice(-6).reverse().map(h => `<div class="ho"><b>${esc(h.data.from)}</b><span class="arr">→</span><b>${esc(h.data.to_role)}</b><p>${esc(h.data.suggested_action)}</p><small>${h.evidence.length} records</small></div>`).join("") : '<p class="empty">shared findings appear here</p>';

  $("integrity").innerHTML = [
    ["network actions", num(m.requests_allowed)], ["out-of-scope blocked", num(m.blocked_attempts)],
    ["packet observer", m.independent_egress_observer === "measured" ? `measured · ${m.independently_observed_scope_violations} viol` : m.independent_egress_observer],
    ["unresolved", num(m.unresolved)], ["failed tasks", num(m.failed_tasks)],
    ["largest briefing", `${num(m.max_briefing_bytes)} B`], ["elapsed", `${m.elapsed_seconds.toFixed(1)} s`],
  ].map(([k, v]) => `<div><dt>${k}</dt><dd>${esc(v)}</dd></div>`).join("");

  $("case-summary").textContent = `${report.counts?.investigation_case || 0} investigation cases · ${m.validated_flags} codes validated · unchecked candidates remain unvalidated.`;
  $("case-outcomes").innerHTML = (report.cases || []).map(c => { const d = c.data || {}; const [cls] = markOf(d.status === "completed" ? "confirmed" : d.status === "running" ? "x" : "rejected"); return `<div class="row"><span class="mark ${cls}">·</span><span class="nm2">${esc(d.role || c.producer)}</span><span class="tgt">${esc((d.target || "") + (d.reason ? " — " + d.reason : ""))}</span></div>`; }).join("");
  $("captured-codes").innerHTML = (report.flags || []).map(f => `<div class="row"><span class="badge ${esc(f.data.status)}">${esc(f.data.status)}</span>${f.data.value ? `<code class="flagval">${esc(f.data.value)}</code>` : `<span class="tgt">${esc(f.data.source_url)}</span>`}<span class="meta">${esc(f.data.capture_basis || "")}</span></div>`).join("") || '<p class="empty">no code candidates captured yet.</p>';
  $("export-codes").disabled = !(report.flags || []).length;
  $("surface-inventory").innerHTML = `<p class="sub">${report.counts?.artifact || 0} artifacts · ${report.counts?.authority || 0} same-IP hostname clues</p>` + (report.services || []).map(s => `<div class="row"><code>${esc(s.data.address)}:${esc(s.data.port)}</code><span class="meta">${esc(s.data.protocol)}</span></div>`).join("");
  const caps = new Map(); (report.capabilities || []).forEach(c => caps.set(c.identity, c));
  $("capabilities").innerHTML = [...caps.values()].map(capRow).join("");

  renderGraph(report);
  $("phases").innerHTML = Object.entries(report.phases).map(([n, s]) => `<span class="phase ${s}">${esc(n)}</span>`).join("");
  $("scope-progress").textContent = m.scope_pairs_planned ? `${num(m.scope_pairs_tested)} / ${num(m.scope_pairs_planned)} scoped TCP pairs tested · ${num(m.scope_pairs_untested)} untested. probe progress, not planted-service recall.` : "";

  $("cancel").disabled = r.status !== "running"; $("download").disabled = false;
  $("connection-label").textContent = r.status === "running" ? "live" : "connected";
}

/* ----------------------------------------------------------- data flow */
async function reload() { if (!state.run || !state.connected || state.loading) return; state.loading = true; try { render(await (await api(`/api/runs/${state.run}/progress`)).json()); } catch (e) { error(e.message); } finally { state.loading = false; } }
function scheduleReload() { if (!state.timer) state.timer = setTimeout(() => { state.timer = null; reload(); }, 1000); }
async function stream(run) {
  if (state.stream) state.stream.abort(); const ctrl = new AbortController(); state.stream = ctrl;
  try {
    const res = await api(`/api/runs/${run}/events?after=${state.cursor}`, { signal: ctrl.signal });
    const reader = res.body.getReader(), dec = new TextDecoder(); let buf = "";
    while (true) { const { done, value } = await reader.read(); if (done) break; buf += dec.decode(value, { stream: true }); const blocks = buf.split("\n\n"); buf = blocks.pop(); for (const b of blocks) { const c = b.match(/^id: (\d+)/m); if (c) state.cursor = Number(c[1]); if (b.includes("event: update") || b.includes("event: terminal")) scheduleReload(); } }
    if (state.run === run) await reload();
  } catch (e) { if (e.name !== "AbortError") { $("connection-label").textContent = "reconnecting"; if (state.run === run) setTimeout(() => stream(run), 1500); } }
}
async function selectRun(run) { state.run = run; state.cursor = 0; if (run) { await reload(); stream(run); } }
async function loadRuns(selectLatest = true) {
  const runs = await (await api("/api/runs")).json();
  $("run-select").innerHTML = '<option value="">— no run —</option>' + runs.map(r => `<option value="${esc(r.id)}">${esc(r.manifest.name)} · ${esc(r.status)}</option>`).join("");
  if (selectLatest && runs.length) { $("run-select").value = runs[0].id; await selectRun(runs[0].id); } else if (state.run) $("run-select").value = state.run;
}

/* ----------------------------------------------------------- dialogs */
function evidenceButtons(ids) { return ids.map(id => `<button class="evidence-button" data-evidence="${esc(id)}">evidence ${esc(id.slice(0, 10))} ↗</button>`).join(""); }
function dialog(title, content) {
  $("dialog-title").textContent = title; $("dialog-content").innerHTML = content;
  if (!$("evidence-dialog").open) $("evidence-dialog").showModal();
  document.querySelectorAll("[data-evidence]").forEach(el => el.onclick = async () => { try { const v = await (await api(`/api/runs/${state.run}/evidence/${el.dataset.evidence}`)).json(); dialog("captured evidence", `<p>sha-256: <code>${esc(v.data.sha256)}</code></p><pre>${esc(JSON.stringify(v.data.metadata, null, 2))}</pre><pre>${esc(v.preview)}</pre>`); } catch (e) { error(e.message); } });
}
function showFinding(id) {
  const f = state.report.findings.find(x => x.id === id), v = state.report.verifications.find(x => x.data.finding_id === id);
  dialog(f.data.title, `<span class="badge ${esc(f.data.status)}">${esc(f.data.status)}</span> <code>${esc(f.data.primitive)}</code><p>${esc(f.data.claim)}</p><p><b>target:</b> <code>${esc(f.data.target)}</code></p><p><b>fix:</b> ${esc(f.data.remediation)}</p>${v ? `<h3>independent check</h3><p>${esc(v.data.reason)}</p><pre>${esc(JSON.stringify(v.data.controls, null, 2))}</pre>` : "<p>independent proof pending.</p>"}${evidenceButtons(f.evidence)}`);
}
function showBriefing(role) { const b = state.report?.briefings.filter(x => x.producer === role).at(-1); dialog(`${role} briefing`, b ? `<p>${b.data.bytes} / ${b.data.budget_bytes} bytes · deterministic structured context, no LLM call.</p><pre>${esc(JSON.stringify(b.data, null, 2))}</pre>` : "<p>no task has activated this specialist yet.</p>"); }
function showFlag(id) {
  const f = (state.report.flags || []).find(x => x.id === id); if (!f) return; const d = f.data;
  const valueBlock = d.value
    ? `<p><b>flag:</b></p><p class="flagval big">${esc(d.value)}</p>`
    : `<p>The flag value is access-controlled. Use <b>export captured codes</b> on the overview to retrieve it locally.</p>`;
  dialog("captured flag", `<span class="badge ${esc(d.status)}">${esc(d.status)}</span>${valueBlock}<p><b>source:</b> <code>${esc(d.source_url)}</code></p><p><b>capture basis:</b> ${esc(d.capture_basis || "")}</p><pre>${esc(JSON.stringify(d.receipt || {}, null, 2))}</pre>${evidenceButtons(f.evidence || [])}`);
}

const PTES_MAP = {
  "Pre-engagement Interactions": "scope freeze, authorization reference, budgets",
  "Intelligence Gathering": "port scan, service identification, banners, crawl",
  "Threat Modeling": "attack-surface inventory, prerequisite graph",
  "Vulnerability Analysis": "deterministic checks, credential + injection probes",
  "Exploitation": "credential use, forwarding-header bypass, protocol drive",
  "Post-Exploitation": "protected-resource / flag retrieval",
  "Reporting": "unified report + evidence bundle",
};
function renderReport(rep) {
  const m = rep.metrics, r = rep.run;
  $("rpt-name").textContent = r.manifest.name;
  $("rpt-status").textContent = r.status.replaceAll("_", " "); $("rpt-status").className = `tag ${r.status}`;
  $("rpt-meta").textContent = `${m.elapsed_seconds.toFixed(1)}s · ${num(m.requests_allowed)} requests · ${num(m.blocked_attempts)} out-of-scope blocked`;
  const F = rep.findings || [];
  const web = F.some(f => f.data.surface === "web") || m.endpoints > 0;
  const bin = F.some(f => f.data.surface === "binary") || (rep.counts?.artifact || 0) > 0;
  const chained = (rep.graph?.edges || []).some(e => e.data.state === "verified_authorized_transition") || (m.captured_flags || 0) > 0;
  const phasesDone = Object.values(rep.phases).filter(x => x === "performed").length;
  const cov = [
    ["FR-1", "Network discovery", "met", `${m.services_discovered} services · ${num(m.scope_pairs_tested)} ports`],
    ["FR-2", "Web surface + checks", web ? "met" : "pend", `${num(m.endpoints)} endpoints`],
    ["FR-3", "Binary analysis", bin ? "met" : "pend", `${rep.counts?.artifact || 0} artifacts`],
    ["FR-4", "Multi-agent coordination", (rep.counts?.handoff || 0) ? "met" : "pend", `${rep.counts?.handoff || 0} handoffs`],
    ["FR-5", "PTES phase mapping", phasesDone ? "met" : "pend", `${phasesDone}/7 phases`],
    ["FR-6", "Verify, not just flag", (m.confirmed + m.rejected) ? "met" : "pend", `${m.confirmed} confirmed / ${m.rejected} rejected`],
    ["FR-7", "Unified report + API", "met", "report.html / .json / bundle"],
    ["B-1", "Capture planted flags", m.captured_flags > 0 ? "met" : "pend", `${m.captured_flags} captured`],
    ["B-2", "Chain to crown jewel", chained ? "met" : "pend", chained ? "verified transitions" : "—"],
    ["B-3", "Plain-English fixes", "met", "remediation per finding"],
    ["B-4", "Checks as config", "met", "checks.yaml recipes"],
    ["B-5", "Live dashboard", "met", "this console"],
  ];
  $("coverage").innerHTML = cov.map(([id, label, s, note]) => `<div class="cov-row ${s}"><span class="cov-mark">${s === "met" ? "✓" : "○"}</span><b>${id}</b><span class="cov-label">${label}</span><span class="cov-note">${esc(note)}</span></div>`).join("");
  const confirmed = F.filter(f => f.data.status === "confirmed");
  $("rpt-summary").innerHTML =
    (rep.flags || []).map(f => `<div class="row"><span class="mark flag">★</span><span class="sev flag">flag</span><span class="nm2">${esc(f.data.status)}</span><span class="tgt">${esc(f.data.source_url)}</span></div>`).join("")
    + (confirmed.length ? confirmed.map(f => `<div class="row"><span class="mark ok">✓</span><span class="sev ${sevClass(f.data.severity)}">${esc(f.data.severity)}</span><span class="nm2">${esc(f.data.title)}</span></div>`).join("") : '<p class="empty">no confirmed findings yet</p>');
  $("ptes-map").innerHTML = Object.entries(rep.phases).map(([n, s]) => `<div class="ptes-row ${s}"><span class="ptes-mark">${s === "performed" ? "●" : "○"}</span><span class="ptes-name">${esc(n)}</span><span class="ptes-desc">${esc(PTES_MAP[n] || "")}</span><span class="ptes-stat">${s === "performed" ? "recorded" : "not performed"}</span></div>`).join("");
}
async function openBlob(path, filename) {
  const res = await api(path); const url = URL.createObjectURL(await res.blob());
  if (filename) { const a = document.createElement("a"); a.href = url; a.download = filename; a.click(); }
  else window.open(url, "_blank");
  setTimeout(() => URL.revokeObjectURL(url), filename ? 3000 : 12000);
}
$("close-dialog").onclick = () => $("evidence-dialog").close();
$("finding-filter").onchange = renderFindings;
$("run-select").onchange = () => selectRun($("run-select").value);

/* ----------------------------------------------------------- controls */
function applyConfig(cfg) {
  state.config = cfg || {};
  const adhoc = !!cfg.adhoc;
  $("start-form").hidden = !adhoc;
  $("demo-btn").hidden = adhoc;
  $("demo-btn").textContent = cfg.frozen ? "restart" : "+ new run";
}
async function connect() {
  try {
    await api("/api/runs"); state.connected = true; sessionStorage.setItem("mitigata-token", state.token);
    $("connect-panel").hidden = true; $("connection-label").textContent = "connected"; $("connection-label").classList.add("on");
    error("");
    try { applyConfig(await (await api("/api/config/agents")).json()); } catch (_) {}
    await loadRuns();
  } catch (e) { error(e.message); $("connect-panel").hidden = false; }
}
$("connect-form").onsubmit = async e => { e.preventDefault(); state.token = $("token").value.trim(); await connect(); };
$("start-form").onsubmit = async e => {
  e.preventDefault(); const ip = $("target-ip").value.trim(); if (!ip) return;
  $("start-btn").disabled = true;
  try { const v = await (await api("/api/quickstart", { method: "POST", body: JSON.stringify({ ip }) })).json(); await loadRuns(false); $("run-select").value = v.run_id; await selectRun(v.run_id); setView("overview"); error(""); }
  catch (e) { error(e.message); } finally { $("start-btn").disabled = false; }
};
$("demo-btn").onclick = async () => {
  $("demo-btn").disabled = true;
  try { const path = state.config.frozen ? "/api/restart" : "/api/demo"; const body = state.config.frozen ? undefined : JSON.stringify({ seed: Date.now() % 1000000, layout: "script" }); const v = await (await api(path, { method: "POST", ...(body ? { body } : {}) })).json(); await loadRuns(false); $("run-select").value = v.run_id; await selectRun(v.run_id); setView("overview"); error(""); }
  catch (e) { error(e.message); } finally { $("demo-btn").disabled = false; }
};
$("cancel").onclick = async () => { try { await api(`/api/runs/${state.run}/cancel`, { method: "POST" }); await reload(); } catch (e) { error(e.message); } };
$("download").onclick = async () => { try { await openBlob(`/api/runs/${state.run}/bundle`, `mitigata-${state.run}.zip`); } catch (e) { error(e.message); } };
$("dl-html").onclick = async () => { try { await openBlob(`/api/runs/${state.run}/report?format=html`); } catch (e) { error(e.message); } };
$("dl-json").onclick = async () => { try { await openBlob(`/api/runs/${state.run}/report.json`, `mitigata-report-${state.run}.json`); } catch (e) { error(e.message); } };
$("dl-bundle").onclick = () => $("download").click();
$("export-codes").onclick = async () => { try { const res = await api(`/api/runs/${state.run}/flags/export`, { method: "POST" }), url = URL.createObjectURL(await res.blob()), a = document.createElement("a"); a.href = url; a.download = "protected-codes.json"; a.click(); setTimeout(() => URL.revokeObjectURL(url), 3000); } catch (e) { error(e.message); } };

/* ----------------------------------------------------------- boot */
renderAgents(null);
const frag = new URLSearchParams(location.hash.slice(1));
if (frag.has("token")) { state.token = frag.get("token"); history.replaceState(null, "", location.pathname); }
if (state.token) { $("token").value = state.token; connect(); } else { $("connect-panel").hidden = false; $("connection-label").textContent = "token required"; }
setInterval(() => { if (state.report?.run.status === "running") reload(); }, 4000);
