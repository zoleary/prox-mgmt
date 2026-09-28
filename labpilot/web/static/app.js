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
  (renderers[tab] || (async () => {}))().catch((e) => ($("#" + tab).innerHTML = `<div class="finding critical">${esc(e.message)}</div>`));
}
const current = () => document.querySelector("#tabs button.active").dataset.tab;

// ---------- overview ----------
renderers.overview = async () => {
  const [o, m] = await Promise.all([api("/overview"), api("/metrics?hours=24")]);
  $("#updated").textContent = o.updated ? "Updated " + new Date(o.updated * 1000).toLocaleTimeString() : "Waiting for first refresh…";
  const memByNode = Object.fromEntries(o.memory.nodes.map((n) => [n.node, n]));
  const hist = (node, f) => m.filter((r) => r.node === node).map(f);

  const integrations = o.integrations.map((i) =>
    `<span class="pill ${i.ok ? "ok" : i.configured ? "critical" : ""}" title="${esc(i.error || "")}">${esc(i.name)}: ${i.ok ? "ok" : i.configured ? "error" : "not configured"}</span>`).join(" ");

  const nodes = o.nodes.map((n) => {
    const mm = memByNode[n.node] || {};
    if (!n.mem_total) return `<div class="card"><h3>${esc(n.node)} <span class="pill critical">${esc(n.status)}</span></h3></div>`;
    return `<div class="card">
      <h3>${esc(n.node)} <span class="pill ${mm.status}">overcommit ${mm.overcommit_ratio}×</span></h3>
      <div class="row"><span>CPU</span><span>${(n.cpu * 100).toFixed(0)}% of ${n.maxcpu} cores</span></div>
      ${bar(n.cpu * 100, 100)}
      <div class="row"><span>Host RAM</span><span>${gib(n.mem_used)} / ${gib(n.mem_total)}</span></div>
      ${bar(n.mem_used, n.mem_total)}
      <div class="row"><span>Assigned to running guests</span><span>${gib(mm.assigned_running)}</span></div>
      ${bar(mm.assigned_running, n.mem_total * 1.5, mm.status)}
      <div class="row"><span>RAM % (24h)</span></div>${spark(hist(n.node, (r) => pct(r.mem_used, r.mem_total)), "#5b9dff")}
      <div class="row"><span>CPU % (24h)</span></div>${spark(hist(n.node, (r) => r.cpu * 100), "#3fb97a")}
    </div>`;
  }).join("");

  const gw = (o.pfsense.gateways || []).map((g) => `<div class="row"><span>${esc(g.name)}</span><span>${esc(g.status)} ${esc(g.delay || "")} ${esc(g.loss || "")}</span></div>`).join("");
  const crit = o.findings.filter((f) => f.severity !== "info");

  $("#overview").innerHTML = `
    <div style="margin-bottom:12px">${integrations}</div>
    <div class="grid">
      <div class="card"><h3>Guests</h3><div class="stat">${o.guest_counts.running}/${o.guest_counts.total}</div><div class="muted">running · ${o.guest_counts.vms} VMs · ${o.guest_counts.containers} containers</div></div>
      <div class="card"><h3>Cluster</h3><div class="stat ${o.quorate ? "ok" : "critical"}">${o.quorate ? "Quorate" : o.quorate === null ? "–" : "No quorum"}</div><div class="muted">${o.nodes.length} nodes</div></div>
      <div class="card"><h3>IP findings</h3><div class="stat ${crit.length ? "warning" : "ok"}">${crit.length}</div><div class="muted">conflicts and warnings</div></div>
      <div class="card"><h3>WAN gateways</h3>${gw || '<div class="muted">pfSense not connected</div>'}</div>
    </div>
    <h2>Nodes</h2><div class="grid">${nodes}</div>
    ${failoverHtml(o.memory.failover)}
    <h2>Findings</h2>${findingsHtml(crit.length ? crit : o.findings.slice(0, 10))}`;
};

function failoverHtml(f) {
  if (!f || !f.length) return "";
  return `<h2>If a node goes down</h2><div class="grid">${f.map((x) => `
    <div class="card"><h3>${esc(x.if_down)} fails <span class="pill ${x.fits ? "ok" : x.fits_with_ballooning ? "warning" : "critical"}">${x.fits ? "fits" : x.fits_with_ballooning ? "fits with ballooning" : "won't fit"}</span></h3>
    <div class="row"><span>Running guests need</span><span>${gib(x.needed)} (${gib(x.needed_with_ballooning)} min)</span></div>
    <div class="row"><span>${esc(x.survivors.join(", "))} has</span><span>${gib(x.capacity)}</span></div>
    ${bar(x.needed, x.capacity * 1.5, x.fits ? "ok" : x.fits_with_ballooning ? "warning" : "critical")}</div>`).join("")}</div>`;
}

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
    <td class="mono">${esc(a.macs.join(", "))}</td><td>${a.sources.map((s) => `<span class="pill">${esc(s)}</span>`).join(" ")}</td></tr>`).join("");
  $("#ipam").innerHTML = `<h2>Subnets and VLANs</h2><div class="grid">${subnets || '<div class="muted">No subnets yet. Connect Windows DHCP or pfSense, or set EXTRA_SUBNETS.</div>'}</div>
    <h2>Findings</h2>${findingsHtml(d.findings)}
    <h2>All addresses (${d.addresses.length})</h2>
    <input class="filter" placeholder="Filter by IP, name, MAC…" oninput="filterRows(this, '#ipam')">
    <table><tr><th>IP</th><th>Subnet</th><th>Names</th><th>MACs</th><th>Seen by</th></tr>${rows}</table>`;
};

// ---------- memory ----------
renderers.memory = async () => {
  const d = await api("/memory");
  const cards = d.nodes.filter((n) => n.total).map((n) => `<div class="card">
    <h3>${esc(n.node)} <span class="pill ${n.status}">${n.overcommit_ratio}× (${n.status})</span></h3>
    <div class="row"><span>Physical RAM</span><span>${gib(n.total)}</span></div>
    <div class="row"><span>Host used</span><span>${gib(n.host_used)} (${n.host_used_pct}%)</span></div>${bar(n.host_used, n.total)}
    <div class="row"><span>Assigned, running guests</span><span>${gib(n.assigned_running)}</span></div>
    <div class="row"><span>Balloon floor, running</span><span>${gib(n.balloon_floor)}</span></div>
    <div class="row"><span>Actually used by guests</span><span>${gib(n.guest_used)}</span></div>
    <div class="row"><span>Assigned if all started</span><span>${gib(n.assigned_all)} (${n.overcommit_ratio_if_all_started}×)</span></div>
    <div class="row"><span>KSM shared</span><span>${gib(n.ksm_shared)}</span></div>
    <div class="row"><span>Swap used</span><span>${gib(n.swap_used)}</span></div>
    ${n.notes.length ? `<ul class="notes">${n.notes.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}
  </div>`).join("");
  $("#memory").innerHTML = `<p class="muted">Overcommit = RAM assigned to running guests ÷ physical RAM. Warning at ${d.thresholds.warn}×, critical at ${d.thresholds.crit}×.</p>
    <div class="grid">${cards}</div>${failoverHtml(d.failover)}
    <h2>Will it fit?</h2>
    <div class="card"><input id="fit-gb" class="filter" type="number" min="0.5" step="0.5" value="8" style="width:100px"> GiB
      <button id="fit-go">Check</button><div id="fit-out" style="margin-top:8px"></div></div>`;
  $("#fit-go").onclick = async () => {
    const r = await api("/memory/fit?gb=" + encodeURIComponent($("#fit-gb").value));
    $("#fit-out").innerHTML = r.map((x) => `<div class="row"><span>${esc(x.node)}</span><span class="${x.status}">${x.current_ratio}× → ${x.new_ratio}×</span></div>`).join("");
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
  "Troubleshoot": [
    "Are there any IP conflicts?",
    "Find me a free IP on each VLAN",
    "A VM has no network. Help me troubleshoot step by step",
    "A node is using a lot of memory. What's using it?",
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
setInterval(() => render(current()), 60000);
