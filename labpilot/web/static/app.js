const $ = (s) => document.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const gib = (b) => (b / 1024 ** 3).toFixed(1) + " GiB";
const pct = (a, b) => (b ? Math.min(100, (a / b) * 100) : 0);
const level = (p) => (p >= 90 ? "critical" : p >= 75 ? "warning" : "ok");

async function api(path, opts = {}) {
  const r = await fetch("/api" + path, { headers: { "Content-Type": "application/json" }, ...opts });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText);
  return r.json();
}

function bar(value, max, cls) {
  const p = pct(value, max);
  return `<div class="bar"><div class="bg-${cls || level(p)}" style="width:${p}%"></div></div>`;
}

function spark(points, color) {
  if (points.length < 2) return '<div class="muted">collecting history…</div>';
  const w = 240, h = 40;
  const xs = points.map((_, i) => (i / (points.length - 1)) * w);
  const d = points.map((v, i) => `${xs[i].toFixed(1)},${(h - (v / 100) * h).toFixed(1)}`).join(" ");
  return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"><polyline fill="none" stroke="${color}" stroke-width="1.5" points="${d}"/></svg>`;
}

// ---------- tabs ----------
document.querySelectorAll("#tabs button").forEach((b) =>
  b.addEventListener("click", () => {
    document.querySelectorAll("#tabs button, .tab").forEach((e) => e.classList.remove("active"));
    b.classList.add("active");
    $("#" + b.dataset.tab).classList.add("active");
    render(b.dataset.tab);
  })
);

const renderers = {};
function render(tab) {
  const el = $("#" + tab);
  if (renderers[tab] && !el.innerHTML.trim()) el.innerHTML = '<div class="muted">Loading…</div>';
  (renderers[tab] || (async () => {}))().catch((e) => ($("#" + tab).innerHTML = `<div class="finding critical">${esc(e.message)}</div>`));
}
const current = () => document.querySelector("#tabs button.active").dataset.tab;

// ---------- overview ----------
renderers.overview = async () => {
  const [o, m] = await Promise.all([api("/overview"), api("/metrics?hours=24")]);
  $("#updated").textContent = o.updated ? "Updated " + new Date(o.updated * 1000).toLocaleTimeString() : "Waiting for first refresh…";
  const hist = (node, f) => m.filter((r) => r.node === node).map(f);

  const integrations = o.integrations.map((i) =>
    `<span class="pill ${i.ok ? "ok" : i.configured ? "critical" : ""}" title="${esc(i.error || "")}">${esc(i.name)}: ${i.ok ? "ok" : i.configured ? "error" : "not configured"}</span>`).join(" ");

  const nodes = o.nodes.map((n) => {
    if (!n.mem_total) return `<div class="card"><h3>${esc(n.node)} <span class="pill critical">${esc(n.status)}</span></h3></div>`;
    const ramPct = pct(n.mem_used, n.mem_total);
    return `<div class="card">
      <h3>${esc(n.node)} <span class="pill ${level(ramPct)}">RAM ${ramPct.toFixed(0)}%</span></h3>
      <div class="row"><span>CPU</span><span>${(n.cpu * 100).toFixed(0)}% of ${n.maxcpu} cores</span></div>
      ${bar(n.cpu * 100, 100)}
      <div class="row"><span>RAM</span><span>${gib(n.mem_used)} / ${gib(n.mem_total)}</span></div>
      ${bar(n.mem_used, n.mem_total)}
      ${n.swap_total ? `<div class="row"><span>Swap</span><span>${gib(n.swap_used)} / ${gib(n.swap_total)}</span></div>${bar(n.swap_used, n.swap_total)}` : ""}
      <div class="row"><span>RAM % (24h)</span></div>${spark(hist(n.node, (r) => pct(r.mem_used, r.mem_total)), "#5b9dff")}
      <div class="row"><span>CPU % (24h)</span></div>${spark(hist(n.node, (r) => r.cpu * 100), "#3fb97a")}
    </div>`;
  }).join("");

  const gw = (o.pfsense.gateways || []).map((g) => `<div class="row"><span>${esc(g.name)}</span><span>${esc(g.status)} ${esc(g.delay || "")} ${esc(g.loss || "")}</span></div>`).join("");
  const crit = o.findings.filter((f) => f.severity !== "info");

  updateBadge(o.alerts);
  $("#overview").innerHTML = `
    ${alertsHtml(o.alerts, o.ignored_alerts)}
    <div style="margin-bottom:12px">${integrations}</div>
    <div class="grid">
      <div class="card"><h3>Guests</h3><div class="stat">${o.guest_counts.running}/${o.guest_counts.total}</div><div class="muted">running · ${o.guest_counts.vms} VMs · ${o.guest_counts.containers} containers</div></div>
      <div class="card"><h3>Cluster</h3><div class="stat ${o.quorate ? "ok" : "critical"}">${o.quorate ? "Quorate" : o.quorate === null ? "–" : "No quorum"}</div><div class="muted">${o.nodes.length} nodes</div></div>
      <div class="card"><h3>IP findings</h3><div class="stat ${crit.length ? "warning" : "ok"}">${crit.length}</div><div class="muted">conflicts and warnings</div></div>
      <div class="card"><h3>WAN gateways</h3>${gw || '<div class="muted">pfSense not connected</div>'}</div>
    </div>
    <h2>Nodes</h2><div class="grid">${nodes}</div>
    <h2>Findings</h2>${findingsHtml(crit.length ? crit : o.findings.slice(0, 10))}`;
  document.querySelectorAll("#overview .ignore").forEach((b) => (b.onclick = () => alertAction("/alerts/ignore", b.dataset.key, b.dataset.msg)));
  document.querySelectorAll("#overview .unignore").forEach((b) => (b.onclick = () => alertAction("/alerts/unignore", b.dataset.key)));
};

const ago = (ts) => {
  const m = Math.round((Date.now() / 1000 - ts) / 60);
  return m < 1 ? "just now" : m < 60 ? `${m} min` : m < 1440 ? `${Math.round(m / 60)} h` : `${Math.round(m / 1440)} d`;
};

function alertsHtml(alerts, ignored = []) {
  const list = !alerts.length
    ? '<div class="finding ok-box"><b class="ok">All clear</b> <span>No active alerts.</span></div>'
    : `<h2 style="margin-top:0">Alerts (${alerts.length})</h2>${alerts.map((a) =>
      `<div class="finding ${a.severity} alert-row"><div><b class="${a.severity}">${esc(a.severity)}</b> <span>${esc(a.message)}</span> <span class="muted">· ${ago(a.since)}</span></div>
       <button class="small ignore" data-key="${esc(a.key)}" data-msg="${esc(a.message)}" title="Hide this alert until you restore it">Ignore</button></div>`).join("")}`;
  const hidden = ignored.length ? `<details class="ignored"><summary class="muted">${ignored.length} ignored alert${ignored.length === 1 ? "" : "s"}</summary>
    ${ignored.map((i) => `<div class="finding alert-row"><div><span>${esc(i.message || i.key)}</span> <span class="muted">· ${i.active ? "still happening" : "not happening now"} · ignored ${ago(i.created) === "just now" ? "just now" : ago(i.created) + " ago"}</span></div>
      <button class="small unignore" data-key="${esc(i.key)}">Restore</button></div>`).join("")}</details>` : "";
  return list + hidden;
}

async function alertAction(path, key, message = "") {
  try {
    const r = await api(path, { method: "POST", body: JSON.stringify({ key, message }) });
    updateBadge(r.alerts);
    render("overview");
  } catch (e) { toast(e.message, "critical"); }
}

function updateBadge(alerts) {
  const b = $("#alert-badge");
  const crit = alerts.filter((a) => a.severity === "critical").length;
  b.hidden = !alerts.length;
  b.className = "alert-badge " + (crit ? "critical" : "warning");
  b.textContent = `⚠ ${alerts.length} alert${alerts.length === 1 ? "" : "s"}`;
}

$("#alert-badge").onclick = () => document.querySelector('#tabs button[data-tab="overview"]').click();

function findingsHtml(list) {
  if (!list.length) return '<div class="muted">No findings.</div>';
  return list.map((f) => `<div class="finding ${f.severity}"><b class="${f.severity}">${esc(f.type)}</b> <span>${esc(f.message)}</span></div>`).join("");
}

// ---------- guests ----------
renderers.guests = async () => {
  const guests = await api("/guests");
  const rows = guests.map((g) => {
    const ips = [...new Set([...(g.nics || []).map((n) => n.ip).filter(Boolean), ...(g.live_ips || []).map((a) => a.ip)])];
    const vlans = [...new Set((g.nics || []).map((n) => n.vlan).filter(Boolean))];
    return `<tr data-q="${esc(JSON.stringify([g.vmid, g.name, g.node, ips, g.tags]).toLowerCase())}">
      <td class="mono">${g.vmid}</td><td>${esc(g.name)}</td><td>${g.type === "qemu" ? "VM" : "CT"}</td><td>${esc(g.node)}</td>
      <td class="${g.status === "running" ? "ok" : "muted"}">${esc(g.status)}</td>
      <td>${g.maxcpu}</td><td>${gib(g.maxmem)}${g.ballooning && g.balloon_min < g.maxmem ? ` <span class="muted">(min ${gib(g.balloon_min)})</span>` : ""}</td>
      <td>${g.status === "running" ? gib(g.mem) : ""}</td>
      <td class="mono">${esc(ips.join(", "))}</td><td>${esc(vlans.join(", "))}</td>
      <td>${g.type === "qemu" ? (g.agent_enabled ? '<span class="ok">yes</span>' : '<span class="warning">no</span>') : ""}</td>
      <td class="nowrap">${powerButtons(g)}</td></tr>`;
  }).join("");
  $("#guests").innerHTML = `<input class="filter" placeholder="Filter guests…" oninput="filterRows(this, '#guests')">
    <table><tr><th>ID</th><th>Name</th><th>Type</th><th>Node</th><th>Status</th><th>vCPU</th><th>Memory</th><th>Using</th><th>IPs</th><th>VLAN</th><th>Agent</th><th></th></tr>${rows}</table>`;
};

function powerButtons(g) {
  const acts = g.status === "running" ? ["shutdown", "reboot", "stop"] : ["start"];
  return acts.map((a) => `<button class="small ${a === "stop" ? "danger" : ""}" title="${a === "stop" ? "Hard stop (like pulling the plug)" : a === "shutdown" ? "Graceful shutdown" : ""}"
    onclick="doAction('guest_power', {guest: '${g.vmid}', action: '${a}'}, '${a[0].toUpperCase() + a.slice(1)} ${g.type === "qemu" ? "VM" : "CT"} ${g.vmid} ${esc(String(g.name ?? "").replace(/['\\]/g, ""))}?')">${a}</button>`).join(" ");
}

window.doAction = async (tool, params, question) => {
  if (!confirm(question)) return;
  document.querySelectorAll("main button").forEach((b) => (b.disabled = true));
  try {
    const a = await api("/do", { method: "POST", body: JSON.stringify({ tool, params }) });
    toast(`${a.summary}: ${a.status}${a.result ? " (" + a.result + ")" : ""}`, a.status === "done" ? "ok" : "critical");
  } catch (e) {
    toast("Failed: " + e.message, "critical");
  }
  render(current());
};

window.filterRows = (input, scope) => {
  const q = input.value.toLowerCase();
  document.querySelectorAll(scope + " tr[data-q]").forEach((tr) => (tr.style.display = tr.dataset.q.includes(q) ? "" : "none"));
};

// ---------- IPAM ----------
renderers.ipam = async () => {
  const d = await api("/ipam");
  const subnets = d.subnets.map((s) => `<div class="card">
    <h3>${esc(s.name)} <span class="muted mono">${esc(s.cidr)}</span></h3>
    <div class="row"><span>${s.used} seen</span><span>${s.size} usable</span></div>${bar(s.used, s.size)}
    ${s.gateway ? `<div class="row"><span>Gateway</span><span class="mono">${esc(s.gateway)}</span></div>` : ""}
    ${s.pool ? `<div class="row"><span>DHCP pool</span><span class="mono">${esc(s.pool)}</span></div>` : ""}
    <div class="row"><span>Next free static</span><span class="mono">${esc(s.next_free.slice(0, 3).join(", ") || "none")}</span></div>
  </div>`).join("");
  const rows = d.addresses.map((a) => `<tr data-q="${esc(JSON.stringify(a).toLowerCase())}">
    <td class="mono">${esc(a.ip)}</td><td>${esc(a.subnet_name || "unknown")}</td><td>${esc(a.names.join(", "))}</td>
    <td class="mono">${esc(a.macs.join(", "))}</td><td>${a.sources.map((s) => `<span class="pill">${esc(s)}</span>`).join(" ")}</td>
    <td>${a.sources.includes("inventory") ? "" : `<button class="small add-inv" data-ip="${esc(a.ip)}" data-mac="${esc(a.macs[0] || "")}" data-name="${esc(a.names[0] || "")}" title="Add to inventory">+ Inventory</button>`}</td></tr>`).join("");
  $("#ipam").innerHTML = `<h2>Subnets and VLANs</h2><div class="grid">${subnets || '<div class="muted">No subnets yet. Connect Windows DHCP or pfSense, or set EXTRA_SUBNETS.</div>'}</div>
    <h2>Findings</h2>${findingsHtml(d.findings)}
    <h2>All addresses (${d.addresses.length})</h2>
    <input class="filter" placeholder="Filter by IP, name, MAC…" oninput="filterRows(this, '#ipam')">
    <table><tr><th>IP</th><th>Subnet</th><th>Names</th><th>MACs</th><th>Seen by</th><th></th></tr>${rows}</table>`;
  document.querySelectorAll("#ipam .add-inv").forEach((b) => (b.onclick = () => {
    pendingDevice = { name: b.dataset.name, ip: b.dataset.ip, mac: b.dataset.mac };
    document.querySelector('#tabs button[data-tab="inventory"]').click();
  }));
};

// ---------- inventory ----------
let pendingDevice = null;  // prefill from the IP addresses tab
let KINDS = [];

renderers.inventory = async () => {
  const { devices, kinds } = await api("/devices");
  KINDS = kinds;
  const statusCell = (d) => !d.check_port ? '<span class="muted">not checked</span>'
    : !d.status ? '<span class="muted">waiting…</span>'
    : d.status.up ? `<span class="ok">up</span> <span class="muted">${ago(d.status.since)}</span>`
    : `<span class="critical">down</span> <span class="muted">${ago(d.status.since)}</span>`;
  const rows = devices.map((d) => `<tr data-q="${esc(JSON.stringify(d).toLowerCase())}">
    <td><b>${esc(d.name)}</b>${d.notes ? `<div class="muted">${esc(d.notes)}</div>` : ""}</td><td>${esc(d.kind)}</td>
    <td class="mono">${esc(d.ip)}</td><td class="mono">${esc(d.mac)}</td><td>${esc(d.role)}</td><td>${esc(d.location)}</td>
    <td>${d.check_port ? `<span class="mono">:${d.check_port}</span> ` : ""}${statusCell(d)}</td>
    <td class="nowrap"><button class="small edit-dev" data-id="${d.id}">Edit</button> <button class="small danger del-dev" data-id="${d.id}">Delete</button></td></tr>`).join("");
  $("#inventory").innerHTML = `
    <div class="card" id="discover-card"></div>
    <div class="card" id="dev-form-card">
      <h3 id="dev-form-title">Add a device</h3>
      <form id="dev-form" class="dev-form">
        <input type="hidden" name="id">
        <label>Name *<input name="name" required maxlength="64" placeholder="e.g. synology-nas"></label>
        <label>Type<select name="kind">${kinds.map((k) => `<option>${esc(k)}</option>`).join("")}</select></label>
        <label>IP address<input name="ip" placeholder="10.0.0.50"></label>
        <label>MAC<input name="mac" placeholder="aa:bb:cc:dd:ee:ff"></label>
        <label>Role<input name="role" maxlength="120" placeholder="e.g. backups, Plex media"></label>
        <label>Location<input name="location" maxlength="120" placeholder="e.g. rack, office"></label>
        <label>Port check<input name="check_port" type="number" min="1" max="65535" placeholder="22, 443, 5000…"></label>
        <label class="wide">Notes<textarea name="notes" rows="2" maxlength="2000" placeholder="Login URL, model, what's running on it…"></textarea></label>
        <div class="wide actions-row"><button type="submit" class="approve">Save</button> <button type="button" id="dev-cancel">Clear</button>
          <span class="muted">Port check: Lab Helper tries a TCP connection every refresh and alerts if it fails.</span></div>
      </form>
    </div>
    <h2>Devices (${devices.length})</h2>
    <input class="filter" placeholder="Filter devices…" oninput="filterRows(this, '#inventory')">
    ${devices.length ? `<table><tr><th>Name</th><th>Type</th><th>IP</th><th>MAC</th><th>Role</th><th>Location</th><th>Health</th><th></th></tr>${rows}</table>`
      : '<div class="muted">No devices yet. Add your NAS, switches, access points and other gear so the assistant knows about them. You can also add them from the IP addresses tab.</div>'}`;

  const form = $("#dev-form");
  const fill = (d) => {
    form.reset();
    for (const [k, v] of Object.entries(d || {})) if (form.elements[k] && v != null) form.elements[k].value = v;
    $("#dev-form-title").textContent = d && d.id ? `Edit ${d.name}` : "Add a device";
  };
  if (pendingDevice) { fill(pendingDevice); pendingDevice = null; form.elements.name.focus(); }
  $("#dev-cancel").onclick = () => fill(null);
  form.onsubmit = async (e) => {
    e.preventDefault();
    const body = Object.fromEntries(new FormData(form));
    const id = body.id; delete body.id;
    try {
      await api(id ? `/devices/${id}` : "/devices", { method: id ? "PUT" : "POST", body: JSON.stringify(body) });
      toast(`Saved ${body.name}`, "ok");
      render("inventory");
    } catch (err) { toast(err.message, "critical"); }
  };
  renderDiscovery();
  const byId = Object.fromEntries(devices.map((d) => [d.id, d]));
  document.querySelectorAll("#inventory .edit-dev").forEach((b) => (b.onclick = () => { fill(byId[b.dataset.id]); window.scrollTo(0, 0); }));
  document.querySelectorAll("#inventory .del-dev").forEach((b) => (b.onclick = async () => {
    const d = byId[b.dataset.id];
    if (!confirm(`Delete ${d.name} from the inventory?`)) return;
    try { await api(`/devices/${d.id}`, { method: "DELETE" }); toast(`Deleted ${d.name}`, "ok"); render("inventory"); }
    catch (err) { toast(err.message, "critical"); }
  }));
};

// ---------- discovery ----------
let discoveryTimer = null;

async function renderDiscovery() {
  const card = $("#discover-card");
  if (!card) return;
  const d = await api("/discovery");
  const pctDone = d.total ? Math.round((d.done / d.total) * 100) : 0;
  const fresh = d.results.filter((r) => !r.in_inventory);
  const rows = d.results.map((r, i) => `<tr class="${r.in_inventory ? "muted" : ""}">
    <td>${r.in_inventory ? "" : `<input type="checkbox" class="disc-pick" data-i="${i}" checked>`}</td>
    <td class="mono">${esc(r.ip)}</td>
    <td><input class="disc-name" data-i="${i}" value="${esc(r.in_inventory || r.suggested_name)}" ${r.in_inventory ? "disabled" : ""}></td>
    <td>${r.in_inventory ? `<span class="muted">in inventory</span>` : `<select class="disc-kind" data-i="${i}">${KINDS.map((k) => `<option ${k === r.kind ? "selected" : ""}>${esc(k)}</option>`).join("")}</select>`}</td>
    <td>${esc(r.role || "")}</td>
    <td class="mono">${esc(r.mac || "")}</td>
    <td>${r.services.map((x) => `<span class="pill">${esc(x)}</span>`).join(" ")}</td>
    <td>${r.sources.map((x) => `<span class="pill">${esc(x)}</span>`).join(" ")}</td></tr>`).join("");
  card.innerHTML = `<h3>Discover devices</h3>
    <div class="muted" style="margin-bottom:8px">Scans your subnets for devices answering on common ports (SSH, web, Proxmox, SMB, NAS, printers…) and merges what pfSense, DHCP and Proxmox already see. Nothing is changed on the devices.</div>
    <div class="actions-row">
      <input id="disc-subnets" class="filter" style="width:360px;margin:0" placeholder="Subnets, e.g. 10.0.0.0/24, 192.168.1.0/24"
        value="${esc((d.subnets.length ? d.subnets : d.suggested_subnets).join(", "))}">
      <button id="disc-go" class="approve" ${d.running ? "disabled" : ""}>${d.running ? "Scanning…" : "Scan"}</button>
      ${d.running ? `<span class="muted">${pctDone}%</span>` : d.finished ? `<span class="muted">Last scan ${ago(d.finished)}${ago(d.finished) === "just now" ? "" : " ago"}: ${d.results.length} found, ${fresh.length} new</span>` : ""}
    </div>
    ${d.running ? `<div class="bar"><div class="bg-info" style="width:${pctDone}%"></div></div>` : ""}
    ${d.error ? `<div class="finding critical"><span>${esc(d.error)}</span></div>` : ""}
    ${!d.running && d.results.length ? `<div class="actions-row" style="margin:10px 0 6px">
        <button id="disc-add" class="approve">Add selected to inventory</button>
        <button id="disc-all" class="small">Select all</button> <button id="disc-none" class="small">Select none</button>
        <span class="muted">Edit names and types first if you like.</span></div>
      <div style="overflow-x:auto"><table><tr><th></th><th>IP</th><th>Name</th><th>Type</th><th>Guess</th><th>MAC</th><th>Services</th><th>Seen by</th></tr>${rows}</table></div>` : ""}`;

  $("#disc-go").onclick = async () => {
    const subnets = $("#disc-subnets").value.split(/[\s,]+/).filter(Boolean);
    try { await api("/discovery", { method: "POST", body: JSON.stringify({ subnets }) }); renderDiscovery(); }
    catch (e) { toast(e.message, "critical"); }
  };
  clearTimeout(discoveryTimer);
  if (d.running) discoveryTimer = setTimeout(() => current() === "inventory" && renderDiscovery(), 1500);
  if (!d.running && d.results.length) {
    const pick = (on) => document.querySelectorAll(".disc-pick").forEach((c) => (c.checked = on));
    $("#disc-all").onclick = () => pick(true);
    $("#disc-none").onclick = () => pick(false);
    $("#disc-add").onclick = async () => {
      const chosen = [...document.querySelectorAll(".disc-pick:checked")].map((c) => {
        const i = c.dataset.i, r = d.results[i];
        return { name: $(`.disc-name[data-i="${i}"]`).value, kind: $(`.disc-kind[data-i="${i}"]`).value, ip: r.ip,
                 mac: r.mac, role: r.role, check_port: r.check_port,
                 notes: r.services.length ? "Discovered: " + r.services.join(", ") : "Discovered" };
      });
      if (!chosen.length) return toast("Nothing selected");
      try {
        const res = await api("/devices/bulk", { method: "POST", body: JSON.stringify({ devices: chosen }) });
        toast(`Added ${res.added.length}` + (res.skipped.length ? `, skipped ${res.skipped.length} already listed` : "") +
          (res.errors.length ? `, ${res.errors.length} errors: ${res.errors.join("; ")}` : ""), res.errors.length ? "critical" : "ok");
        render("inventory");
      } catch (e) { toast(e.message, "critical"); }
    };
  }
}

// ---------- network diagram ----------
const ICONS = { firewall: "🧱", router: "🌐", switch: "🔀", "access point": "📡", hypervisor: "🏗️", server: "🖥️",
  nas: "🗄️", vm: "💠", container: "📦", iot: "💡", workstation: "💻", printer: "🖨️", other: "🔹", unknown: "❔" };

function hostChip(h) {
  const dot = h.status === "up" ? "ok" : h.status === "down" ? "critical" : "muted";
  const guests = h.guests && h.guests.length ? `<div class="guests">${h.guests.map((g) =>
    `<span class="gchip ${g.status === "running" ? "" : "stopped"}" title="${esc(g.type === "qemu" ? "VM" : "CT")} ${g.vmid} · ${esc(g.status)}">${g.type === "qemu" ? "💠" : "📦"} ${esc(g.label)}</span>`).join("")}</div>` : "";
  return `<div class="host ${h.kind}">
    <div class="host-top"><span class="icon">${ICONS[h.kind] || "🔹"}</span><b>${esc(h.label)}</b>${h.status ? `<span class="dot bg-${dot}" title="${esc(h.status)}"></span>` : ""}</div>
    <div class="muted mono">${esc(h.ip || "no IP")}</div>${h.role ? `<div class="muted">${esc(h.role)}</div>` : ""}${guests}</div>`;
}

function toMermaid(t) {
  const id = (s) => "n_" + String(s).replace(/[^A-Za-z0-9]/g, "_");
  const q = (s) => String(s ?? "").replace(/"/g, "'");
  const out = ["flowchart TD", `  internet(("Internet"))`, `  fw["${q(t.firewall.name)} (firewall)"]`, "  internet --> fw"];
  for (const n of t.networks) {
    out.push(`  subgraph ${id(n.cidr)}["${q(n.name)} ${n.cidr}"]`);
    for (const h of n.hosts) out.push(`    ${id(h.ip)}["${q(h.label)}<br/>${h.ip}"]`);
    out.push("  end", `  fw --> ${id(n.cidr)}`);
  }
  return out.join("\n");
}

renderers.network = async () => {
  const t = await api("/topology");
  const wan = t.wan.length ? t.wan.map((g) => `<div class="muted">${esc(g.name)} · ${esc(g.status || "?")}</div>`).join("") : '<div class="muted">WAN</div>';
  const nets = t.networks.map((n) => `<div class="net">
      <div class="net-head"><b>${esc(n.name)}</b> <span class="mono muted">${esc(n.cidr)}</span>
        ${n.gateway ? `<div class="muted">gateway ${esc(n.gateway)}</div>` : ""}<div class="muted">${n.hosts.length} host${n.hosts.length === 1 ? "" : "s"}</div></div>
      <div class="hosts">${n.hosts.map(hostChip).join("") || '<div class="muted">Nothing seen yet</div>'}</div></div>`).join("");
  $("#network").innerHTML = `
    <div class="actions-row" style="margin-bottom:12px">
      <button id="net-mermaid" class="small">Copy as Mermaid</button>
      <span class="muted">Built from pfSense, Proxmox, DHCP and your inventory. Add devices on the Inventory tab (or run Discover) to fill it in.</span>
    </div>
    <div class="topo">
      <div class="tier"><div class="node-box internet">☁️ <b>Internet</b>${wan}</div></div>
      <div class="vline"></div>
      <div class="tier"><div class="node-box fw">🧱 <b>${esc(t.firewall.name)}</b><div class="muted">${t.firewall.connected ? "firewall / router" : "pfSense not connected"}</div></div></div>
      <div class="vline"></div>
      ${t.networks.length ? `<div class="nets">${nets}</div>` : '<div class="muted" style="text-align:center">No subnets known yet. Connect pfSense or set EXTRA_SUBNETS in .env.</div>'}
      ${t.other.length ? `<h2>Not in a known subnet</h2><div class="hosts loose">${t.other.map(hostChip).join("")}</div>` : ""}
    </div>`;
  $("#net-mermaid").onclick = () => {
    const text = toMermaid(t);
    const ta = Object.assign(document.createElement("textarea"), { value: text });
    document.body.appendChild(ta); ta.select(); document.execCommand("copy"); ta.remove();
    toast("Mermaid diagram copied. Paste it into Obsidian, GitHub or mermaid.live", "ok");
  };
};

// ---------- firewall ----------
renderers.firewall = async () => {
  const pf = await api("/raw/pfsense");
  if (!pf.system) { $("#firewall").innerHTML = '<div class="muted">pfSense not connected.</div>'; return; }
  const ifaces = (pf.interfaces || []).map((i) => `<tr><td>${esc(i.descr || i.name)}</td><td>${esc(i.status)}</td><td class="mono">${esc(i.ipaddr)}/${esc(i.subnet)}</td><td class="mono">${esc(i.macaddr)}</td></tr>`).join("");
  const aliases = (pf.aliases || []).map((a) => `<tr><td>${esc(a.name)}</td><td>${esc(a.type)}</td><td class="mono">${esc((a.address || []).join(", "))}</td><td>${esc(a.descr)}</td></tr>`).join("");
  const q = (v) => esc(String(v ?? "").replace(/['\\]/g, ""));
  const toggle = (tool, params, enabled, label) => `<button class="small ${enabled ? "danger" : "approve"}"
    onclick="doAction('${tool}', ${esc(JSON.stringify(params))}, '${enabled ? "Disable" : "Enable"} ${q(label)} and apply?')">${enabled ? "Disable" : "Enable"}</button>`;
  const rules = (pf.rules || []).map((r) => `<tr class="${r.disabled ? "muted" : ""}" data-q="${esc(JSON.stringify(r).toLowerCase())}"><td>${esc(r.interface)}</td><td class="${r.type === "pass" ? "ok" : "critical"}">${esc(r.type)}</td><td>${esc(r.protocol || "any")}</td><td class="mono">${esc(r.source)}</td><td class="mono">${esc(r.destination)}${r.destination_port ? ":" + esc(r.destination_port) : ""}</td><td>${esc(r.descr)}${r.disabled ? ' <span class="pill">disabled</span>' : ""}</td>
    <td>${r.tracker ? toggle("set_firewall_rule_enabled", { tracker: String(r.tracker), enabled: !!r.disabled }, !r.disabled, "rule " + (r.descr || r.tracker)) : ""}</td></tr>`).join("");
  const tunnels = (pf.tunnels || []).map((t) => `<tr class="${t.disabled ? "muted" : ""}"><td class="mono">${esc(t.ikeid)}</td><td>${esc(t.descr)}</td><td class="mono">${esc(t.remote_gateway)}</td>
    <td class="${t.disabled ? "muted" : /establish|install/i.test(t.state) ? "ok" : "warning"}">${t.disabled ? "disabled" : esc(t.state)}</td>
    <td>${toggle("set_ipsec_tunnel_enabled", { ikeid: String(t.ikeid), enabled: !!t.disabled }, !t.disabled, "IPsec tunnel " + (t.descr || t.ikeid))}</td></tr>`).join("");
  $("#firewall").innerHTML = `<h2>Interfaces</h2><table><tr><th>Name</th><th>Status</th><th>Address</th><th>MAC</th></tr>${ifaces}</table>
    <h2>IPsec tunnels</h2>${tunnels ? `<table><tr><th>ID</th><th>Description</th><th>Remote gateway</th><th>State</th><th></th></tr>${tunnels}</table>` : '<div class="muted">No IPsec tunnels.</div>'}
    <h2>Aliases</h2><table><tr><th>Name</th><th>Type</th><th>Entries</th><th>Description</th></tr>${aliases}</table>
    <h2>Rules</h2><input class="filter" placeholder="Filter rules…" oninput="filterRows(this, '#firewall')">
    <table><tr><th>Interface</th><th>Action</th><th>Proto</th><th>Source</th><th>Destination</th><th>Description</th><th></th></tr>${rules}</table>`;
};

// ---------- change queue ----------
renderers.actions = async () => {
  const list = await api("/actions");
  $("#actions").innerHTML = `<table><tr><th>#</th><th>When</th><th>Change</th><th>Status</th><th>Result</th><th></th></tr>${list.map((a) => `
    <tr><td>${a.id}</td><td>${new Date(a.created * 1000).toLocaleString()}</td><td>${esc(a.summary)}</td>
    <td class="${a.status === "done" ? "ok" : a.status === "failed" ? "critical" : a.status === "pending" ? "warning" : "muted"}">${esc(a.status)}</td>
    <td class="mono">${esc(a.result || "")}</td>
    <td>${a.status === "pending" ? `<button class="small approve" onclick="decide(${a.id}, 'approve')">Approve</button> <button class="small reject" onclick="decide(${a.id}, 'reject')">Reject</button>` : ""}</td></tr>`).join("")}</table>`;
};

window.decide = async (id, what) => {
  try {
    const a = await api(`/actions/${id}/${what}`, { method: "POST" });
    const text = `Change #${id} ${a.status}${a.result ? ": " + a.result : ""}`;
    addMsg("bot", text);
    toast(text, a.status === "done" ? "ok" : a.status === "failed" ? "critical" : "");
  } catch (e) {
    addMsg("bot", `Change #${id}: ${e.message}`);
    toast(`Change #${id}: ${e.message}`, "critical");
  }
  document.querySelectorAll(`[data-action="${id}"] button`).forEach((b) => (b.disabled = true));
  render(current());
};

function toast(text, cls = "") {
  const t = document.createElement("div");
  t.className = "toast " + cls;
  t.textContent = text;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 6000);
}

// ---------- assistant ----------
const TASKS = {
  "Proxmox": [
    "Give me a health check of the cluster",
    "Which node has the most free memory?",
    "Walk me through creating a new VM",
    "Walk me through creating an LXC container from a template",
    "Take a snapshot of a VM before I change it",
    "Help me set up scheduled backups",
    "Walk me through updating both Proxmox nodes safely",
    "Migrate a VM to the other node",
    "Which VMs are missing the QEMU guest agent, and how do I install it?",
  ],
  "pfSense": [
    "Show my firewall rules and point out anything risky",
    "What's the status of my IPsec tunnels?",
    "Walk me through adding a port forward",
    "Walk me through creating a new VLAN end to end (pfSense + Proxmox)",
    "Help me block a device on my network",
    "Are my WAN gateways healthy?",
    "How do I back up my pfSense config?",
    "Walk me through a DHCP static mapping in pfSense",
  ],
  "Home lab": [
    "What's in my inventory, and what on my network isn't documented yet?",
    "Help me set up Docker and Compose in a new LXC container",
    "Set up Tailscale so I can reach my lab remotely",
    "Plan a backup strategy for my whole lab (3-2-1)",
    "Put my services behind a reverse proxy with HTTPS",
    "Harden SSH on my Linux servers",
    "Set up Uptime Kuma to monitor my services",
    "How should I split my network into VLANs?",
  ],
  "Troubleshoot": [
    "Are there any alerts right now? Help me fix them",
    "Are there any IP conflicts?",
    "Find me a free IP on each VLAN",
    "A VM has no network. Help me troubleshoot step by step",
    "A node is using a lot of RAM. What's using it?",
  ],
};

$("#tasks").innerHTML = Object.entries(TASKS).map(([group, items]) =>
  `<h3>${esc(group)}</h3>${items.map((t) => `<button class="task">${esc(t)}</button>`).join("")}`).join("");
document.querySelectorAll("#tasks .task").forEach((b) => b.addEventListener("click", () => send(b.textContent)));

// Small, safe markdown: escape first, then add code blocks (with Copy), inline code, bold and headings.
function md(text) {
  const blocks = [];
  let h = esc(text).replace(/```[a-zA-Z0-9_-]*\n?([\s\S]*?)```/g, (_, code) => {
    blocks.push(code.replace(/\n$/, ""));
    return `\u0000${blocks.length - 1}\u0000`;
  });
  h = h.replace(/`([^`\n]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*\n]+)\*\*/g, "<b>$1</b>")
    .replace(/^#{1,4} (.+)$/gm, "<b>$1</b>");
  return h.replace(/\u0000(\d+)\u0000\n?/g, (_, i) =>
    `<div class="code"><button class="small copy" onclick="copyCode(this)">Copy</button><pre>${blocks[i]}</pre></div>`);
}

window.copyCode = (btn) => {
  const text = btn.nextElementSibling.textContent;
  const done = () => { btn.textContent = "Copied"; setTimeout(() => (btn.textContent = "Copy"), 1500); };
  if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done);
  else {  // plain http on the LAN: clipboard API is unavailable, fall back to a hidden textarea
    const ta = Object.assign(document.createElement("textarea"), { value: text });
    document.body.appendChild(ta); ta.select(); document.execCommand("copy"); ta.remove(); done();
  }
};

// ---------- chat ----------
let sessionId = null;

function addMsg(who, text, extra = "") {
  const div = document.createElement("div");
  div.className = "msg " + who;
  div.innerHTML = (who === "bot" ? md(text) : esc(text)) + extra;
  $("#chat-log").appendChild(div);
  $("#chat-log").scrollTop = 1e9;
  return div;
}

async function send(text) {
  if (!text.trim()) return;
  if (current() !== "assistant") document.querySelector('#tabs button[data-tab="assistant"]').click();
  addMsg("user", text);
  $("#chat-input").value = "";
  const thinking = addMsg("bot", "Thinking…");
  try {
    const r = await api("/chat", { method: "POST", body: JSON.stringify({ message: text, session_id: sessionId }) });
    sessionId = r.session_id;
    thinking.remove();
    const tools = r.tools.length ? `<div class="tools">used: ${esc([...new Set(r.tools)].join(", "))}</div>` : "";
    addMsg("bot", r.reply || "(no reply)", tools);
    for (const p of r.proposed) {
      const div = document.createElement("div");
      div.className = "proposal";
      div.dataset.action = p.id;
      div.innerHTML = `<b>Change #${p.id} needs approval</b><div>${esc(p.summary)}</div>
        <div class="actions-row"><button class="small approve" onclick="decide(${p.id}, 'approve')">Approve</button>
        <button class="small reject" onclick="decide(${p.id}, 'reject')">Reject</button></div>`;
      $("#chat-log").appendChild(div);
    }
    $("#chat-log").scrollTop = 1e9;
  } catch (e) {
    thinking.textContent = "Error: " + e.message;
  }
}

$("#chat-form").addEventListener("submit", (e) => { e.preventDefault(); send($("#chat-input").value); });
$("#chat-input").addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(e.target.value); } });
$("#chat-reset").onclick = async () => {
  if (sessionId) await api(`/chat/${sessionId}/reset`, { method: "POST" }).catch(() => {});
  sessionId = null;
  $("#chat-log").innerHTML = "";
  addMsg("bot", "New chat started.");
};

$("#refresh").onclick = async () => {
  $("#refresh").disabled = true;
  try { await api("/refresh", { method: "POST" }); render(current()); } finally { $("#refresh").disabled = false; }
};

render("overview");
setInterval(() => {
  render(current());
  if (current() !== "overview") api("/alerts").then(updateBadge).catch(() => {});
}, 60000);
