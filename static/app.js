// SecureOps SOC dashboard front-end: polls the Flask API and renders KPIs, charts and tables.
const SEV_COLORS = { critical: "#dc2626", high: "#f97316", medium: "#facc15", low: "#38bdf8" };
const POLL_MS = 3000;
const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

// Logs contain attacker-controlled text (e.g. <script> payloads), so ALWAYS escape
// before inserting into the DOM - otherwise the SOC console itself becomes an XSS target.
const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString();
const fmtFull = (ts) => new Date(ts * 1000).toLocaleString();
const timeCell = (ts) => `<td class="mono nowrap" title="${esc(fmtFull(ts))}">${esc(fmtTime(ts))}</td>`;

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  return res.json();
}
const post = (path, body) =>
  api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });

// ------------------------------------------------------------------ views
const VIEWS = {
  dashboard: ["Security Overview", "Real-time view of events, detections and analyst activity"],
  alerts: ["Alerts", "Triage detections: acknowledge, resolve or block the source"],
  logs: ["Log Explorer", "Search the raw event stream collected from all sources"],
  blocked: ["Blocked IPs", "Addresses currently dropped by the simulated firewall"],
};
let currentView = "dashboard";

function setView(name) {
  if (!VIEWS[name]) name = "dashboard";
  currentView = name;
  $$(".view").forEach((v) => v.classList.toggle("hidden", v.id !== "view-" + name));
  $$(".nav-link").forEach((a) => a.classList.toggle("active", a.dataset.view === name));
  $("#page-title").textContent = VIEWS[name][0];
  $("#page-sub").textContent = VIEWS[name][1];
  $("#sidebar").classList.remove("open");
  if (location.hash !== "#" + name) history.replaceState(null, "", "#" + name);
  tick();
  if (name === "dashboard") Object.values(charts).forEach((c) => c.resize());
}

// ------------------------------------------------------------------ charts
Chart.defaults.color = "#64748b";
Chart.defaults.borderColor = "#edf0f6";
Chart.defaults.font.family = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif';
Chart.defaults.font.size = 12;
Chart.defaults.plugins.tooltip.backgroundColor = "#1e293b";
Chart.defaults.plugins.tooltip.padding = 10;
Chart.defaults.plugins.tooltip.cornerRadius = 8;

const centerText = {
  id: "centerText",
  afterDraw(chart) {
    const { ctx, chartArea: { left, right, top, bottom } } = chart;
    const total = chart.data.datasets[0].data.reduce((a, b) => a + b, 0);
    const x = (left + right) / 2, y = (top + bottom) / 2;
    ctx.save();
    ctx.textAlign = "center"; ctx.textBaseline = "middle";
    ctx.fillStyle = "#0f172a"; ctx.font = "700 26px system-ui, sans-serif";
    ctx.fillText(total, x, y - 8);
    ctx.fillStyle = "#64748b"; ctx.font = "12px system-ui, sans-serif";
    ctx.fillText("active alerts", x, y + 16);
    ctx.restore();
  },
};

const horizontalBar = (el, color) => new Chart(el, {
  type: "bar",
  data: { labels: [], datasets: [{ label: "Alerts", data: [], backgroundColor: color, borderRadius: 5, maxBarThickness: 22 }] },
  options: {
    indexAxis: "y", maintainAspectRatio: false, animation: false,
    plugins: { legend: { display: false } },
    scales: { x: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: "#edf0f6" } }, y: { grid: { display: false } } },
  },
});

const charts = {
  timeline: new Chart($("#c-timeline"), {
    type: "line",
    data: { labels: [], datasets: [
      { label: "Events", data: [], borderColor: "#2563eb", backgroundColor: "rgba(37,99,235,.10)", fill: true, tension: .35, pointRadius: 0, borderWidth: 2 },
      { label: "Alerts", data: [], borderColor: "#dc2626", backgroundColor: "rgba(220,38,38,.10)", fill: true, tension: .35, pointRadius: 2, borderWidth: 2 },
    ] },
    options: {
      maintainAspectRatio: false, animation: false, interaction: { mode: "index", intersect: false },
      plugins: { legend: { position: "top", align: "end", labels: { boxWidth: 12, boxHeight: 12, padding: 18 } } },
      scales: { y: { beginAtZero: true, ticks: { precision: 0 } }, x: { grid: { display: false }, ticks: { maxTicksLimit: 8 } } },
    },
  }),
  severity: new Chart($("#c-severity"), {
    type: "doughnut",
    data: { labels: ["Critical", "High", "Medium", "Low"], datasets: [{ data: [0, 0, 0, 0], backgroundColor: Object.values(SEV_COLORS), borderWidth: 3, borderColor: "#ffffff" }] },
    options: { maintainAspectRatio: false, animation: false, cutout: "68%", plugins: { legend: { position: "bottom", labels: { usePointStyle: true, boxWidth: 8 } } } },
    plugins: [centerText],
  }),
  ips: horizontalBar($("#c-ips"), "#f97316"),
  rules: horizontalBar($("#c-rules"), "#2563eb"),
};

// ------------------------------------------------------------------ renderers
function threatLevel(sev) {
  if ((sev.critical || 0) >= 1) return ["critical", "Critical"];
  if ((sev.high || 0) >= 3) return ["high", "High"];
  if ((sev.high || 0) >= 1 || (sev.medium || 0) >= 3) return ["elevated", "Elevated"];
  return ["low", "Low"];
}

async function refreshOverview() {
  const d = await api("/api/overview");
  const k = d.kpis;
  $("#k-open").textContent = k.open_alerts.toLocaleString();
  $("#k-crit").textContent = k.critical_open.toLocaleString();
  $("#k-hour").textContent = k.logs_hour.toLocaleString();
  $("#k-total").textContent = k.total_logs.toLocaleString();
  $("#k-alerts").textContent = k.total_alerts.toLocaleString();
  $("#k-blocked").textContent = k.blocked_ips.toLocaleString();
  $("#nav-alerts").textContent = k.open_alerts;
  $("#nav-alerts").classList.toggle("hidden", k.open_alerts === 0);
  $("#nav-blocked").textContent = k.blocked_ips;
  $("#toggle-sim").textContent = d.simulator ? "Pause traffic" : "Resume traffic";

  const [lvl, label] = threatLevel(d.severity);
  $("#threat").className = "threat threat-" + lvl;
  $("#threat-text").textContent = "Threat level: " + label;

  if (currentView !== "dashboard") return; // charts are only visible on the dashboard
  const c = charts;
  c.timeline.data.labels = d.timeline.map((p) => new Date(p.t * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }));
  c.timeline.data.datasets[0].data = d.timeline.map((p) => p.events);
  c.timeline.data.datasets[1].data = d.timeline.map((p) => p.alerts);
  c.timeline.update("none");

  c.severity.data.datasets[0].data = ["critical", "high", "medium", "low"].map((s) => d.severity[s] || 0);
  c.severity.update("none");

  c.ips.data.labels = d.top_ips.map((r) => r.ip);
  c.ips.data.datasets[0].data = d.top_ips.map((r) => r.n);
  c.ips.update("none");

  c.rules.data.labels = d.rules.map((r) => r.rule);
  c.rules.data.datasets[0].data = d.rules.map((r) => r.n);
  c.rules.update("none");
}

function alertActions(a) {
  return `<div class="actions">
    ${a.status === "open" ? `<button class="btn btn-sm" data-act="acknowledged" data-id="${a.id}">Acknowledge</button>` : ""}
    ${a.status !== "resolved" ? `<button class="btn btn-sm" data-act="resolved" data-id="${a.id}">Resolve</button>` : ""}
    ${a.blocked
      ? `<button class="btn btn-sm" data-unblock="${esc(a.src_ip)}">Unblock</button>`
      : `<button class="btn btn-sm btn-danger" data-block="${esc(a.src_ip)}">Block IP</button>`}
  </div>`;
}

function alertRow(a, full) {
  return `<tr>
    ${timeCell(a.ts)}
    <td><span class="badge ${esc(a.severity)}">${esc(a.severity)}</span></td>
    <td class="mono">${esc(a.rule)}</td>
    <td class="mono">${esc(a.src_ip)}</td>
    ${full ? `<td class="desc">${esc(a.description)}</td>` : ""}
    <td class="mono">${esc(a.mitre)}</td>
    <td><span class="status status-${esc(a.status)}">${esc(a.status)}</span></td>
    <td>${alertActions(a)}</td>
  </tr>`;
}

async function refreshRecent() {
  const rows = await api("/api/alerts?limit=6&status=open");
  $("#recent-body").innerHTML = rows.length
    ? rows.map((a) => alertRow(a, false)).join("")
    : `<tr><td colspan="7" class="empty">No open alerts - all clear</td></tr>`;
}

async function refreshAlerts() {
  const params = new URLSearchParams({ limit: 100 });
  if ($("#f-status").value) params.set("status", $("#f-status").value);
  if ($("#f-severity").value) params.set("severity", $("#f-severity").value);
  const rows = await api("/api/alerts?" + params);
  $("#alerts-body").innerHTML = rows.length
    ? rows.map((a) => alertRow(a, true)).join("")
    : `<tr><td colspan="8" class="empty">No alerts match the filters</td></tr>`;
}

async function refreshLogs() {
  const q = $("#f-search").value.trim();
  const rows = await api("/api/logs?limit=100" + (q ? "&q=" + encodeURIComponent(q) : ""));
  $("#logs-body").innerHTML = rows.length
    ? rows.map((l) => `
      <tr class="log-${esc(l.event_type)}">
        ${timeCell(l.ts)}
        <td>${esc(l.source)}</td>
        <td><span class="etype ${esc(l.event_type)}">${esc(l.event_type)}</span></td>
        <td class="mono">${esc(l.src_ip)}</td>
        <td>${esc(l.username || "")}</td>
        <td class="mono">${esc(l.port || "")}</td>
        <td>${esc(l.message)}</td>
      </tr>`).join("")
    : `<tr><td colspan="7" class="empty">No logs found</td></tr>`;
}

async function refreshBlocked() {
  const rows = await api("/api/blocked");
  $("#blocked-body").innerHTML = rows.length
    ? rows.map((b) => `
      <tr>
        <td class="mono">${esc(b.ip)}</td>
        ${timeCell(b.ts)}
        <td>${esc(b.reason)}</td>
        <td><div class="actions"><button class="btn btn-sm" data-unblock="${esc(b.ip)}">Unblock</button></div></td>
      </tr>`).join("")
    : `<tr><td colspan="4" class="empty">No blocked IP addresses</td></tr>`;
}

async function tick() {
  try {
    const jobs = [refreshOverview()];
    if (currentView === "dashboard") jobs.push(refreshRecent());
    if (currentView === "alerts") jobs.push(refreshAlerts());
    if (currentView === "logs") jobs.push(refreshLogs());
    if (currentView === "blocked") jobs.push(refreshBlocked());
    await Promise.all(jobs);
    $("#live-pill").classList.remove("off");
    $("#live-pill").lastChild.textContent = " Live";
  } catch (e) {
    console.error(e);
    $("#live-pill").classList.add("off");
    $("#live-pill").lastChild.textContent = " Offline";
  }
  $("#clock").textContent = new Date().toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

// ------------------------------------------------------------------ events
document.addEventListener("click", async (e) => {
  const nav = e.target.closest("[data-view]");
  if (nav) { e.preventDefault(); setView(nav.dataset.view); return; }

  const t = e.target.closest("button");
  if (!t) { if (!e.target.closest("#sim-menu")) $("#sim-menu").removeAttribute("open"); return; }
  if (t.id === "menu-btn") { $("#sidebar").classList.toggle("open"); return; }
  try {
    if (t.dataset.sim) { $("#sim-menu").removeAttribute("open"); await post("/api/simulate/" + t.dataset.sim); }
    else if (t.id === "toggle-sim") await post("/api/simulate/toggle");
    else if (t.dataset.act) await post(`/api/alerts/${t.dataset.id}/status`, { status: t.dataset.act });
    else if (t.dataset.block) await post("/api/block", { ip: t.dataset.block, reason: "Blocked by analyst" });
    else if (t.dataset.unblock) await post("/api/block", { ip: t.dataset.unblock, unblock: true });
    else return;
    tick();
  } catch (err) { alert("Action failed: " + err.message); }
});

$("#block-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const ip = $("#f-blockip").value.trim();
  if (!ip) return;
  try { await post("/api/block", { ip, reason: "Blocked manually by analyst" }); $("#f-blockip").value = ""; tick(); }
  catch (err) { alert("Action failed: " + err.message); }
});
["#f-status", "#f-severity"].forEach((s) => $(s).addEventListener("change", refreshAlerts));
$("#f-search").addEventListener("input", refreshLogs);
window.addEventListener("hashchange", () => setView(location.hash.slice(1)));

setView(location.hash.slice(1) || "dashboard");
setInterval(tick, POLL_MS);
