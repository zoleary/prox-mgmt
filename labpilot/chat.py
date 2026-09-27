"""Chat assistant: Claude with read tools that answer from live lab data, and
write tools that only *propose* changes. Proposed changes land in the approval
queue and run when you click Approve in the UI."""

import json
import logging
import threading
import uuid

import anthropic

from . import actions
from .analysis.ipam import build_inventory
from .analysis.memory import can_fit

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are LabPilot, the assistant for a home lab: a two-node Proxmox VE cluster, \
pfSense as the firewall/router with VLANs, and Windows Server providing DHCP and DNS.

Answer from the tools, not from assumptions. Data is refreshed about once a minute.

Changes: tools that change something (power, memory, snapshots, DHCP reservations, DNS records, \
firewall aliases) do NOT run immediately. They queue a proposal that the user must approve in the \
UI. After proposing, tell the user what you queued and that it's waiting for their approval. Never \
say a change is done unless a later message confirms it.

Before proposing a change, check it makes sense: for a new VM or static IP, use find_free_ips and \
check_memory_fit; before adding DNS, check the IP isn't already used by something else. If a request \
is risky (stopping a node's critical VM, a big overcommit), say so plainly.

Keep answers short. Use GiB for memory. Use tables only when comparing several items."""


def _obj(props: dict, required: list[str]) -> dict:
    return {"type": "object", "properties": props, "required": required, "additionalProperties": False}


GUEST = {"type": "string", "description": "VMID or exact guest name"}

READ_TOOLS = [
    {"name": "get_overview", "description": "Cluster summary: nodes, quorum, guest counts, integration health, top findings.",
     "input_schema": _obj({}, [])},
    {"name": "list_guests", "description": "All VMs and containers with node, status, memory, and IPs.",
     "input_schema": _obj({"node": {"type": "string", "description": "Only this node"}}, [])},
    {"name": "get_guest", "description": "Full detail for one guest, including NICs, VLAN tags and live IPs.",
     "input_schema": _obj({"guest": GUEST}, ["guest"])},
    {"name": "memory_report", "description": "Per-node memory overcommit ratio, ballooning, KSM, and 2-node failover headroom.",
     "input_schema": _obj({}, [])},
    {"name": "check_memory_fit", "description": "Overcommit ratio on each node if a guest with this much RAM were started there.",
     "input_schema": _obj({"memory_gb": {"type": "number"}}, ["memory_gb"])},
    {"name": "ip_inventory", "description": "Every known IP with its sources (Proxmox, DHCP, DNS, pfSense ARP), plus conflict findings.",
     "input_schema": _obj({"subnet": {"type": "string", "description": "Only this CIDR, e.g. 10.0.20.0/24"},
                           "search": {"type": "string", "description": "Filter by IP, name or MAC substring"}}, [])},
    {"name": "find_free_ips", "description": "Subnets/VLANs with suggested free static IPs (outside DHCP pools, not seen anywhere).",
     "input_schema": _obj({"count": {"type": "integer"}}, [])},
    {"name": "dhcp_scopes", "description": "Windows DHCP scopes, reservations, and active leases.",
     "input_schema": _obj({"scope_id": {"type": "string"}}, [])},
    {"name": "dns_records", "description": "A records from the configured Windows DNS zones.",
     "input_schema": _obj({"search": {"type": "string"}}, [])},
    {"name": "pfsense_status", "description": "pfSense system status, interfaces, VLANs, gateways and aliases.",
     "input_schema": _obj({}, [])},
    {"name": "firewall_rules", "description": "pfSense firewall rules, optionally for one interface.",
     "input_schema": _obj({"interface": {"type": "string"}}, [])},
]

WRITE_TOOLS = [
    {"name": "guest_power", "description": "Propose starting, shutting down (graceful), stopping (hard), or rebooting a guest.",
     "input_schema": _obj({"guest": GUEST, "action": {"type": "string", "enum": ["start", "shutdown", "stop", "reboot"]}},
                          ["guest", "action"])},
    {"name": "set_guest_memory", "description": "Propose changing a guest's memory. balloon_min_mb (VMs only) sets the ballooning floor; 0 disables ballooning.",
     "input_schema": _obj({"guest": GUEST, "memory_mb": {"type": "integer"}, "balloon_min_mb": {"type": "integer"}},
                          ["guest", "memory_mb"])},
    {"name": "snapshot_guest", "description": "Propose taking a snapshot of a guest.",
     "input_schema": _obj({"guest": GUEST, "name": {"type": "string"}, "description": {"type": "string"}}, ["guest", "name"])},
    {"name": "add_dhcp_reservation", "description": "Propose a Windows DHCP reservation.",
     "input_schema": _obj({"scope_id": {"type": "string"}, "ip": {"type": "string"}, "mac": {"type": "string"},
                           "name": {"type": "string", "description": "Short host name"}},
                          ["scope_id", "ip", "mac", "name"])},
    {"name": "add_dns_record", "description": "Propose a Windows DNS A record (and PTR by default).",
     "input_schema": _obj({"zone": {"type": "string"}, "name": {"type": "string", "description": "Host label, not FQDN"},
                           "ip": {"type": "string"}, "create_ptr": {"type": "boolean"}}, ["zone", "name", "ip"])},
    {"name": "remove_dns_record", "description": "Propose deleting a Windows DNS A record.",
     "input_schema": _obj({"zone": {"type": "string"}, "name": {"type": "string"}, "ip": {"type": "string"}},
                          ["zone", "name", "ip"])},
    {"name": "add_to_firewall_alias", "description": "Propose adding an IP or CIDR to an existing pfSense alias, then applying.",
     "input_schema": _obj({"alias": {"type": "string"}, "address": {"type": "string"}}, ["alias", "address"])},
]

TOOLS = READ_TOOLS + WRITE_TOOLS
MAX_RESULT_CHARS = 60_000
MAX_STEPS = 12


def _slim_guest(g: dict) -> dict:
    return {"vmid": g["vmid"], "name": g["name"], "type": g["type"], "node": g["node"], "status": g["status"],
            "mem_gib": round(g["maxmem"] / 1024**3, 1), "cpus": g["maxcpu"],
            "ips": sorted({n["ip"] for n in g.get("nics", []) if n.get("ip")} | {a["ip"] for a in g.get("live_ips", [])})}


def run_read_tool(state, name: str, p: dict):
    raw = state.raw
    if name == "get_overview":
        return state.overview()
    if name == "list_guests":
        return [_slim_guest(g) for g in state.guests if not p.get("node") or g["node"] == p["node"]]
    if name == "get_guest":
        return state.find_guest(p["guest"])
    if name == "memory_report":
        return state.memory()
    if name == "check_memory_fit":
        return can_fit(state.memory()["nodes"], int(p["memory_gb"] * 1024**3), state.s.mem_warn_ratio, state.s.mem_crit_ratio)
    if name == "ip_inventory":
        inv = state.ipam()
        rows = inv["addresses"]
        if p.get("subnet"):
            rows = [r for r in rows if r["subnet"] == p["subnet"]]
        if p.get("search"):
            q = p["search"].lower()
            rows = [r for r in rows if q in json.dumps(r).lower()]
        return {"addresses": rows, "findings": inv["findings"]}
    if name == "find_free_ips":
        obs = [o for d in raw.values() for o in d.get("observations", [])]
        return build_inventory(obs, state.subnets(), free_per_subnet=p.get("count") or 5)["subnets"]
    if name == "dhcp_scopes":
        w = raw.get("windows", {})
        sid = p.get("scope_id")
        pick = (lambda rows: [r for r in rows if not sid or r.get("scope_id") == sid])
        return {"scopes": pick(w.get("scopes", [])), "reservations": pick(w.get("reservations", [])),
                "leases": pick(w.get("leases", []))}
    if name == "dns_records":
        recs = raw.get("windows", {}).get("dns_records", [])
        q = (p.get("search") or "").lower()
        return [r for r in recs if q in json.dumps(r).lower()]
    if name == "pfsense_status":
        pf = raw.get("pfsense", {})
        return {k: pf.get(k) for k in ("system", "interfaces", "vlans", "gateways", "aliases")}
    if name == "firewall_rules":
        rules = raw.get("pfsense", {}).get("rules", [])
        return [r for r in rules if not p.get("interface") or r.get("interface") == p["interface"]]
    raise ValueError(f"unknown tool {name}")


class ChatService:
    def __init__(self, settings, state, db):
        self.s, self.state, self.db = settings, state, db
        self.client = anthropic.Anthropic(api_key=settings.anthropic_api_key or None)
        self.sessions: dict[str, list] = {}
        self.locks: dict[str, threading.Lock] = {}

    def _call(self, messages: list):
        kwargs = dict(model=self.s.claude_model, max_tokens=16000, system=SYSTEM_PROMPT, tools=TOOLS,
                      thinking={"type": "adaptive"}, messages=messages)
        if self.s.claude_fallbacks:
            # Server-side refusal fallback: if the model declines, the API retries on a fallback model.
            return self.client.beta.messages.create(betas=["server-side-fallback-2026-07-01"],
                                                    extra_body={"fallbacks": "default"}, **kwargs)
        return self.client.messages.create(**kwargs)

    def _tool_result(self, block) -> tuple[dict, dict | None]:
        proposed = None
        try:
            if block.name in actions.ACTIONS:
                proposed = actions.propose(self.state, self.db, block.name, block.input)
                content = json.dumps({"queued_for_approval": True, "action_id": proposed["id"],
                                      "summary": proposed["summary"]})
            else:
                content = json.dumps(run_read_tool(self.state, block.name, block.input), default=str)
                if len(content) > MAX_RESULT_CHARS:
                    content = content[:MAX_RESULT_CHARS] + "... [truncated; narrow the query]"
            return {"type": "tool_result", "tool_use_id": block.id, "content": content}, proposed
        except Exception as e:
            return {"type": "tool_result", "tool_use_id": block.id, "content": f"Error: {e}", "is_error": True}, None

    def send(self, session_id: str | None, text: str) -> dict:
        session_id = session_id or uuid.uuid4().hex
        lock = self.locks.setdefault(session_id, threading.Lock())
        with lock:
            messages = self.sessions.setdefault(session_id, [])
            start = len(messages)
            messages.append({"role": "user", "content": text})
            proposed, tools_used = [], []
            for _ in range(MAX_STEPS):
                try:
                    resp = self._call(messages)
                except anthropic.APIStatusError as e:
                    del messages[start:]  # drop this turn so history stays valid and the user can retry
                    return {"session_id": session_id, "reply": f"Claude API error {e.status_code}: {e.message}",
                            "proposed": [], "tools": []}
                except anthropic.APIConnectionError:
                    del messages[start:]
                    return {"session_id": session_id, "reply": "Couldn't reach the Claude API.", "proposed": [], "tools": []}
                messages.append({"role": "assistant", "content": resp.content})
                if resp.stop_reason != "tool_use":
                    break
                results = []
                for block in (b for b in resp.content if b.type == "tool_use"):
                    tools_used.append(block.name)
                    result, prop = self._tool_result(block)
                    results.append(result)
                    if prop:
                        proposed.append(prop)
                messages.append({"role": "user", "content": results})
            else:
                resp = None

            if resp is None:
                reply = "I stopped after too many steps. Try a narrower question."
            elif resp.stop_reason == "refusal":
                reply = "The model declined this request."
            else:
                reply = "\n".join(b.text for b in resp.content if b.type == "text").strip()
                if resp.stop_reason == "max_tokens":
                    reply += "\n\n[reply cut off at the length limit]"
            return {"session_id": session_id, "reply": reply, "proposed": proposed, "tools": tools_used}

    def reset(self, session_id: str) -> None:
        self.sessions.pop(session_id, None)
