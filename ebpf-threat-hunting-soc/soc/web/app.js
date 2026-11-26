// eBPF SOC dashboard - polls /api/state once per second and renders every panel.
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
const tm = (ts) => ts ? new Date(ts * 1000).toLocaleTimeString([], {hour12: false}) : "";
const ms = (v) => v == null ? "–" : (v >= 1000 ? (v / 1000).toFixed(2) + " s" : v.toFixed(1) + " ms");
const post = (url, body) => fetch(url, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body || {})}).then(r => r.json());

let STATE = null;

async function init() {
  const sc = await fetch("/api/scenarios").then(r => r.json());
  $("scenario").innerHTML = sc.map(s => `<option value="${esc(s.name)}" title="${esc(s.description)}">${esc(s.title)}</option>`).join("");
  $("launch").onclick = () => post("/api/simulate", {scenario: $("scenario").value, speed: parseFloat($("speed").value)});
  $("reset").onclick = () => post("/api/reset");
  document.querySelectorAll("#mode button").forEach(b => b.onclick = () => post("/api/mode", {mode: b.dataset.mode}));
  $("closeModal").onclick = () => $("modal").classList.add("hidden");
  $("modal").onclick = (e) => { if (e.target.id === "modal") $("modal").classList.add("hidden"); };
  tick();
  setInterval(tick, 1000);
  if (location.hash.startsWith("#INC-")) setTimeout(() => openIncident(location.hash.slice(1)), 600);
}

async function tick() {
  try { STATE = await fetch("/api/state").then(r => r.json()); } catch (e) { return; }
  render(STATE);
}

function render(s) {
  document.querySelectorAll("#mode button").forEach(b => b.classList.toggle("on", b.dataset.mode === s.mode));
  const k = s.kpi;
  $("kpis").innerHTML = [
    ["acc", k.eps, "kernel events / sec"], ["", k.events_total.toLocaleString(), "events processed"],
    [k.critical ? "alert" : "", `${k.alerts}<small style="font-size:13px;color:var(--critical)"> / ${k.critical} crit</small>`, "alerts"],
    [k.incidents_open ? "alert" : "", k.incidents_open, "open incidents"], ["good", k.incidents_contained, "contained incidents"],
    [k.hosts_isolated ? "alert" : "", k.hosts_isolated, "hosts isolated"],
    ["", `${k.blocked_ips}<small style="font-size:13px;color:var(--muted)"> / ${k.blocked_connections} conns</small>`, "IPs blocked (eBPF)"],
    ["good", ms(k.avg_response_ms), "kernel event → containment"],
  ].map(([c, v, l]) => `<div class="kpi ${c}"><div class="v">${v}</div><div class="l">${l}</div></div>`).join("");

  // fleet
  $("hosts").innerHTML = s.hosts.map(h => `
    <div class="host ${h.isolated ? "isolated" : ""}">
      <div class="top" style="display:flex;justify-content:space-between;align-items:center">
        <span class="name">${esc(h.name)}</span>
        ${h.isolated ? '<span class="badge iso">ISOLATED</span>' : '<span class="badge ok">online</span>'}
      </div>
      <div class="meta">${esc(h.ip)} · ${esc(h.role)}</div>
      <div class="meta">${h.events.toLocaleString()} events · ${h.alerts} alerts${h.frozen ? ` · ${h.frozen} frozen` : ""}${h.killed ? ` · ${h.killed} killed` : ""}</div>
      ${h.isolated ? `<button style="margin-top:6px;font-size:12px;padding:3px 8px" onclick="post('/api/hosts/${esc(h.name)}/release')">Release host</button>` : ""}
    </div>`).join("");

  renderGraph(s);

  // heatmap
  $("heatmap").innerHTML = s.heatmap.map(col => `
    <div class="tcol"><h3>${esc(col.tactic)}</h3>
      ${col.techniques.map(t => `<div class="tech ${t.count ? (t.count >= 5 ? "h3" : t.count >= 2 ? "h2" : "h1") : ""}" title="${esc(t.name)}">
        <b>${esc(t.id)}${t.count ? " · " + t.count : ""}</b>${esc(t.name)}</div>`).join("")}
    </div>`).join("");

  // scenario run
  const run = s.runs[0];
  if (run) {
    const stopped = run.steps.filter(x => x.result !== "executed").length;
    $("runTitle").textContent = `${run.scenario} — ${run.steps.length} steps, ${stopped} stopped${run.finished ? " (finished)" : " (running…)"}`;
    $("run").innerHTML = run.steps.map(st => `
      <div class="step"><span class="n">${st.n}</span>
        <span>${esc(st.name)} <span class="h">${esc(st.host)}</span> ${st.technique ? `<span class="tag">${esc(st.technique)}</span>` : ""}
          <div class="d" style="color:var(--muted);font-size:11.5px">${esc(st.detail)}</div></span>
        <span class="st ${esc(st.result)}">${esc(st.result)}</span></div>`).join("");
    const box = $("run"); box.scrollTop = box.scrollHeight;
  }

  // actions
  $("actions").innerHTML = s.actions.length ? s.actions.map(a => `
    <div class="item"><div class="top">
      <span class="st ${esc(a.state)}">${esc(a.state).replace("_", " ")}</span>
      <b>${esc(a.type)}</b> <span class="mono">${esc(a.host || a.ip || "")}</span>
      <span class="tag">${esc(a.playbook)}</span>
      ${a.kernel_to_response_ms != null ? `<span class="hint">${ms(a.kernel_to_response_ms)} from kernel event</span>` : ""}
      ${(a.state === "awaiting_approval" || a.state === "recommended") && ["freeze_process_tree","kill_process_tree","isolate_host","block_ip"].includes(a.type)
        ? `<button style="padding:2px 8px;font-size:12px" onclick="post('/api/actions/${esc(a.action_id)}/approve')">Approve</button>` : ""}
    </div><div class="d">${esc(a.playbook_name)} ← ${esc(a.alert_title)}</div></div>`).join("")
    : '<div class="empty">No response actions yet.</div>';

  // incidents
  $("incidents").innerHTML = s.incidents.length ? s.incidents.map(i => `
    <div class="inc ${esc(i.severity)}" onclick="openIncident('${esc(i.id)}')">
      <div class="top" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <b>${esc(i.id)}</b><span class="sev ${esc(i.severity)}">${esc(i.severity)}</span>
        <span class="st ${i.status === "contained" ? "success" : "prevented"}">${esc(i.status)}</span>
        <span>${esc(i.title)}</span></div>
      <div class="m">hosts: <span class="mono">${esc(i.hosts.join(" → "))}</span> · ${i.alerts.length} alerts ·
        MTTD ${ms(i.metrics.mttd_ms)} · kernel→response ${ms(i.metrics.kernel_to_response_ms)} · dwell ${ms(i.metrics.time_to_contain_ms)}</div>
      <div class="m">${i.techniques.map(t => `<span class="tag">${esc(t)}</span>`).join(" ")}</div>
    </div>`).join("") : '<div class="empty">No incidents.</div>';

  // alerts
  $("alerts").innerHTML = s.alerts.length ? s.alerts.map(a => `
    <div class="item"><div class="top"><span class="sev ${esc(a.severity)}">${esc(a.severity)}</span>
      <b>${esc(a.title)}</b></div>
      <div class="d"><span class="mono">${esc(a.host)}</span> · ${tm(a.ts_epoch)} · ${esc(a.source)} · ${a.incident_id ? esc(a.incident_id) : "no incident"}
        ${a.techniques.map(t => `<span class="tag" title="${esc(t.name)}">${esc(t.id)}</span>`).join(" ")}</div>
      <div class="d mono">${esc(a.cmdline || "")}</div></div>`).join("")
    : '<div class="empty">No alerts — only benign background activity so far.</div>';

  // telemetry
  $("evtypes").textContent = Object.entries(s.event_types).map(([k, v]) => `${k}:${v}`).join("  ");
  $("events").innerHTML = s.recent_events.map(e => {
    let what = e.cmdline || "";
    if (e.type.startsWith("network")) what = `→ ${e.dst_ip}:${e.dst_port}  (${e.cmdline})`;
    if (e.type === "file_access") what = `${e.file_path}  (${e.cmdline})`;
    if (e.type === "privilege_change") what = `uid ${e.uid} → ${e.new_uid}  (${e.cmdline})`;
    if (e.type === "ptrace") what = `${e.ptrace_request}  (${e.cmdline})`;
    if (e.type === "memfd_create") what = `memfd_create('${e.memfd_name}')  (${e.cmdline})`;
    const hot = e.mitre.length && !["T1059.004"].includes(e.mitre[0]);
    return `<div class="ev ${hot ? "hot" : ""} ${e.type === "network_blocked" ? "blocked" : ""}">
      <span class="t">${tm(e.ts_epoch)}</span><span>${esc(e.host)}</span><span class="typ">${esc(e.type)}</span>
      <span>${esc(what)} ${e.mitre.map(t => `<span class="tag">${esc(t)}</span>`).join(" ")}</span></div>`;
  }).join("");
}

function renderGraph(s) {
  const hosts = s.hosts;
  const W = 640, H = 290, cx = W / 2, cy = H / 2 - 2, rx = 245, ry = 82;
  const pos = {};
  hosts.forEach((h, i) => {
    const a = Math.PI + (i / hosts.length) * 2 * Math.PI;
    pos[h.name] = [cx + rx * Math.cos(a), cy + ry * Math.sin(a)];
  });
  const compromised = new Set(); const edges = [];
  s.incidents.forEach(i => { i.hosts.forEach(h => compromised.add(h)); (i.lateral_edges || []).forEach(e => edges.push(e)); });
  let svg = `<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
    <path d="M0,0 L10,5 L0,10 z" fill="#ff3b5c"/></marker></defs>`;
  edges.forEach(e => {
    const a = pos[e.src_host], b = pos[e.dst_host]; if (!a || !b) return;
    const dx = b[0] - a[0], dy = b[1] - a[1], L = Math.hypot(dx, dy), ux = dx / L, uy = dy / L;
    svg += `<line x1="${a[0] + ux * 42}" y1="${a[1] + uy * 42}" x2="${b[0] - ux * 44}" y2="${b[1] - uy * 44}"
      stroke="#ff3b5c" stroke-width="2.5" stroke-dasharray="6 4" marker-end="url(#arr)"/>
      <text x="${(a[0] + b[0]) / 2}" y="${(a[1] + b[1]) / 2 - 8}" fill="#ffb4c0" font-size="11" text-anchor="middle">SSH ${tm(e.ts)}</text>`;
  });
  hosts.forEach(h => {
    const [x, y] = pos[h.name];
    const fill = compromised.has(h.name) ? "#4a1420" : "#16202c";
    const stroke = h.isolated ? "#ff3b5c" : compromised.has(h.name) ? "#ff7a45" : "#33d1c6";
    svg += `<g><circle cx="${x}" cy="${y}" r="38" fill="${fill}" stroke="${stroke}" stroke-width="${h.isolated ? 3 : 1.6}" ${h.isolated ? 'stroke-dasharray="5 3"' : ""}/>
      <text x="${x}" y="${y + 4}" fill="#d7e0ea" font-size="10.5" text-anchor="middle" font-family="monospace">${esc(h.name)}</text>
      <text x="${x}" y="${y + 54}" fill="${h.isolated ? "#ff3b5c" : "#7d8a9a"}" font-size="10.5" text-anchor="middle">${h.isolated ? "ISOLATED" : esc(h.ip)}</text></g>`;
  });
  if (!edges.length) svg += `<text x="${cx}" y="${cy + 4}" fill="#56627a" font-size="12" text-anchor="middle">no lateral movement detected</text>`;
  $("graph").innerHTML = svg;
}

function treeHtml(n) {
  if (!n) return "";
  const cls = n.alerts.length ? "alerted" : "";
  return `<li><span class="node ${cls} ${esc(n.status)}">${esc(n.binary)} <span style="color:var(--muted)">${esc(n.args).slice(0, 90)}</span>
    <span style="color:var(--muted)">pid ${n.pid} uid ${n.uid}${n.uid_after === 0 ? "→0" : ""}</span>
    ${n.status !== "running" && n.status !== "exited" ? `<span class="st prevented">${esc(n.status)}</span>` : ""}
    ${n.techniques.map(t => `<span class="tag">${esc(t)}</span>`).join(" ")} ${n.alerts.length ? `⚠ ${n.alerts.length}` : ""}</span>
    ${n.children.length ? `<ul>${n.children.map(treeHtml).join("")}</ul>` : ""}</li>`;
}

async function openIncident(id) {
  const b = await fetch(`/api/incidents/${id}`).then(r => r.json());
  const i = b.incident, m = b.metrics;
  const trees = Object.entries(b.process_trees).map(([host, roots]) =>
    `<h3 style="font-size:13px;margin:14px 0 6px">${esc(host)}</h3><div class="tree"><ul>${roots.map(treeHtml).join("")}</ul></div>`).join("");
  $("modalContent").innerHTML = `
    <h2 style="font-size:16px;text-transform:none;letter-spacing:0;color:var(--text)">${esc(i.id)} — ${esc(i.title)}</h2>
    <div><span class="sev ${esc(i.severity)}">${esc(i.severity)}</span> <span class="mono">${esc(i.hosts.join(" → "))}</span>
      &nbsp; <a class="btn" href="/api/incidents/${esc(i.id)}/timeline.md" target="_blank">Download forensic timeline (.md)</a></div>
    <div class="metrics">
      <div class="kpi"><div class="v">${ms(m.mttd_ms)}</div><div class="l">time to detect</div></div>
      <div class="kpi good"><div class="v">${ms(m.kernel_to_response_ms)}</div><div class="l">kernel event → response</div></div>
      <div class="kpi"><div class="v">${ms(m.time_to_contain_ms)}</div><div class="l">attacker dwell until contained</div></div>
      <div class="kpi"><div class="v">${b.alert_count}</div><div class="l">alerts</div></div>
    </div>
    ${b.evidence_path ? `<div class="hint">Evidence bundle written to <span class="mono">${esc(b.evidence_path)}</span></div>` : ""}
    <h2 style="margin-top:16px">Process execution trees</h2>${trees}
    <h2 style="margin-top:18px">Forensic timeline</h2>
    <table><thead><tr><th>Time</th><th>Host</th><th>Kind</th><th>Event</th><th>ATT&amp;CK</th></tr></thead><tbody>
    ${b.timeline.map(e => `<tr class="k-${esc(e.kind)}"><td class="mono">${tm(e.ts)}</td><td>${esc(e.host)}</td><td>${esc(e.kind)}</td>
      <td class="mono">${esc(e.text)}</td><td>${e.mitre.map(t => `<span class="tag">${esc(t)}</span>`).join(" ")}</td></tr>`).join("")}
    </tbody></table>
    <h2 style="margin-top:18px">Indicators of compromise</h2>
    <div class="mono" style="font-size:12px">${Object.entries(b.iocs).filter(([k, v]) => v.length && k !== "command_lines")
      .map(([k, v]) => `<div><b>${esc(k)}</b>: ${v.map(esc).join(", ")}</div>`).join("")}</div>`;
  $("modal").classList.remove("hidden");
}

init();
