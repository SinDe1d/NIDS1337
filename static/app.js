const $ = (id) => document.getElementById(id);
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
}[c]));
const formatTime = (value) => value ? new Date(Number(value) * 1000).toLocaleString() : "—";
let currentAlert = null;

async function getJson(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(await response.text());
  return response.json();
}

async function load() {
  const type = $("typeFilter").value;
  const search = $("search").value.trim();
  const [summary, alerts, flows] = await Promise.all([
    getJson("/api/summary"),
    getJson(`/api/alerts?limit=100${type ? `&type=${encodeURIComponent(type)}` : ""}`),
    getJson(`/api/flows?limit=100${search ? `&search=${encodeURIComponent(search)}` : ""}`),
  ]);
  $("flows").textContent = summary.flows;
  $("alerts").textContent = summary.alerts;
  $("high").textContent = summary.high_confidence_alerts;
  $("active").textContent = summary.active_flows;
  $("alertRows").innerHTML = alerts.length ? alerts.map((alert) => `
    <tr>
      <td><span class="badge">${esc(alert.attack_type)}</span></td>
      <td class="confidence">${(Number(alert.confidence) * 100).toFixed(1)}%</td>
      <td>${esc(alert.source)}</td><td>${esc(alert.destination)}</td>
      <td>${esc(formatTime(alert.created_at))}</td>
      <td><button class="link" data-alert="${alert.id}">Inspect</button></td>
    </tr>`).join("") : '<tr><td colspan="6" class="empty">No alerts match this filter.</td></tr>';
  $("flowRows").innerHTML = flows.length ? flows.map((flow) => `
    <tr><td>${esc(flow.src_ip)}:${esc(flow.src_port)}</td>
      <td>${esc(flow.dst_ip)}:${esc(flow.dst_port)}</td>
      <td>${flow.protocol === 6 ? "TCP" : flow.protocol === 17 ? "UDP" : flow.protocol}</td>
      <td>${flow.total_packets}</td><td>${flow.total_bytes.toLocaleString()}</td>
      <td>${Number(flow.duration).toFixed(3)}s</td></tr>`).join("") :
    '<tr><td colspan="6" class="empty">No flow data matches this filter.</td></tr>';
  document.querySelectorAll("[data-alert]").forEach((button) => {
    button.addEventListener("click", () => openAlert(button.dataset.alert));
  });
}

async function openAlert(id) {
  currentAlert = await getJson(`/api/alerts/${id}`);
  $("detailTitle").textContent = currentAlert.attack_type;
  const flow = currentAlert.flow;
  $("detailBody").innerHTML = `
    <p>${esc(currentAlert.reason || "No explanation recorded.")}</p>
    <div class="detail-grid">
      <div><small>Confidence</small><strong>${(currentAlert.confidence * 100).toFixed(1)}%</strong></div>
      <div><small>Observed</small><strong>${esc(formatTime(currentAlert.created_at))}</strong></div>
      <div><small>Source</small><strong>${esc(currentAlert.source)}</strong></div>
      <div><small>Destination</small><strong>${esc(currentAlert.destination)}</strong></div>
      ${flow ? `<div><small>Packets / bytes</small><strong>${flow.total_packets} / ${flow.total_bytes}</strong></div>
      <div><small>Duration</small><strong>${Number(flow.duration).toFixed(3)}s</strong></div>` : ""}
    </div>`;
  $("drawer").classList.remove("hidden");
}

async function feedback(value) {
  if (!currentAlert) return;
  await fetch(`/api/alerts/${currentAlert.id}/feedback`, {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({value}),
  });
  $("drawer").classList.add("hidden");
  await load();
}

$("refresh").addEventListener("click", load);
$("typeFilter").addEventListener("change", load);
$("search").addEventListener("input", () => { clearTimeout(window.searchTimer); window.searchTimer = setTimeout(load, 250); });
$("closeDrawer").addEventListener("click", () => $("drawer").classList.add("hidden"));
document.querySelectorAll("[data-feedback]").forEach((button) => button.addEventListener("click", () => feedback(button.dataset.feedback)));
load().catch((error) => console.error(error));
