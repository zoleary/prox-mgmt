"""Changes the assistant can propose. Nothing here runs until a person approves it.

Each action has:
  prepare(state, params) -> (resolved_params, summary)   validates and resolves, no side effects
  execute(state, resolved_params) -> str                 makes the change
"""

import ipaddress
import re

from .integrations.proxmox import POWER_ACTIONS
from .integrations.windows import valid_hostname, valid_ipv4, valid_mac_dashes

SNAP_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{1,39}$")
ALIAS_RE = re.compile(r"^[A-Za-z0-9_]{1,31}$")


def _guest(state, ref):
    g = state.find_guest(ref)
    return {"vmid": g["vmid"], "node": g["node"], "type": g["type"], "name": g["name"]}


def _integration(state, name):
    integ = state.integrations[name]
    if not integ.configured():
        raise ValueError(f"the {name} integration is not configured")
    return integ


# ---------- Proxmox ----------

def prep_power(state, p):
    if p["action"] not in POWER_ACTIONS:
        raise ValueError(f"action must be one of {sorted(POWER_ACTIONS)}")
    g = _guest(state, p["guest"])
    return {**g, "action": p["action"]}, f"{p['action'].title()} {g['type']}/{g['vmid']} {g['name']} on {g['node']}"


def exec_power(state, r):
    return str(_integration(state, "proxmox").power(r["node"], r["type"], r["vmid"], r["action"]))


def prep_memory(state, p):
    g = _guest(state, p["guest"])
    mem = int(p["memory_mb"])
    if not 128 <= mem <= 1024 * 1024:
        raise ValueError("memory_mb must be between 128 and 1048576")
    floor = p.get("balloon_min_mb")
    if floor is not None:
        floor = int(floor)
        if g["type"] != "qemu":
            raise ValueError("balloon_min_mb only applies to VMs, not containers")
        if not 0 <= floor <= mem:
            raise ValueError("balloon_min_mb must be between 0 and memory_mb (0 disables ballooning)")
    summary = f"Set memory of {g['type']}/{g['vmid']} {g['name']} to {mem} MB"
    if floor is not None:
        summary += f" (balloon minimum {floor} MB)"
    if g["type"] == "qemu":
        summary += ". A running VM may need a reboot for a max-memory change to apply"
    return {**g, "memory_mb": mem, "balloon_min_mb": floor}, summary


def exec_memory(state, r):
    _integration(state, "proxmox").set_memory(r["node"], r["type"], r["vmid"], r["memory_mb"], r["balloon_min_mb"])
    return "memory updated"


def prep_snapshot(state, p):
    g = _guest(state, p["guest"])
    if not SNAP_RE.match(p["name"]):
        raise ValueError("snapshot name: start with a letter; letters, digits, '-' and '_' only; max 40")
    return {**g, "name_snap": p["name"], "description": p.get("description", "")[:200]}, \
        f"Snapshot {g['type']}/{g['vmid']} {g['name']} as '{p['name']}'"


def exec_snapshot(state, r):
    return str(_integration(state, "proxmox").snapshot(r["node"], r["type"], r["vmid"], r["name_snap"], r["description"]))


# ---------- Windows DHCP / DNS ----------

def prep_reservation(state, p):
    r = {"scope_id": valid_ipv4(p["scope_id"]), "ip": valid_ipv4(p["ip"]),
         "mac": valid_mac_dashes(p["mac"]), "name": valid_hostname(p["name"])}
    _integration(state, "windows")
    return r, f"DHCP reservation {r['ip']} -> {r['mac']} ({r['name']}) in scope {r['scope_id']}"


def exec_reservation(state, r):
    _integration(state, "windows").add_reservation(r["scope_id"], r["ip"], r["mac"], r["name"])
    return "reservation added"


def prep_dns_add(state, p):
    win = _integration(state, "windows")
    r = {"zone": win.zone_or_error(p["zone"]), "name": valid_hostname(p["name"]), "ip": valid_ipv4(p["ip"]),
         "create_ptr": bool(p.get("create_ptr", True))}
    return r, f"DNS A record {r['name']}.{r['zone']} -> {r['ip']}" + (" (+PTR)" if r["create_ptr"] else "")


def exec_dns_add(state, r):
    _integration(state, "windows").add_a_record(r["zone"], r["name"], r["ip"], r["create_ptr"])
    return "record added"


def prep_dns_remove(state, p):
    win = _integration(state, "windows")
    r = {"zone": win.zone_or_error(p["zone"]), "name": valid_hostname(p["name"]), "ip": valid_ipv4(p["ip"])}
    return r, f"Delete DNS A record {r['name']}.{r['zone']} -> {r['ip']}"


def exec_dns_remove(state, r):
    _integration(state, "windows").remove_a_record(r["zone"], r["name"], r["ip"])
    return "record removed"


# ---------- pfSense ----------

def prep_alias(state, p):
    _integration(state, "pfsense")
    if not ALIAS_RE.match(p["alias"]):
        raise ValueError("invalid alias name")
    addr = p["address"].strip()
    if "/" in addr:
        addr = str(ipaddress.IPv4Network(addr, strict=False))
    else:
        addr = valid_ipv4(addr)
    return {"alias": p["alias"], "address": addr}, f"Add {addr} to pfSense alias {p['alias']} and apply firewall changes"


def exec_alias(state, r):
    return str(_integration(state, "pfsense").add_to_alias(r["alias"], r["address"]))


def _pf_item(state, collection, key, value, what):
    for item in state.raw.get("pfsense", {}).get(collection, []):
        if str(item.get(key)) == str(value).strip():
            return item
    raise ValueError(f"no {what} with {key} {value!r} (refresh if it was just added)")


def _enabled(p):
    if not isinstance(p.get("enabled"), bool):
        raise ValueError("enabled must be true or false")
    return p["enabled"]


def prep_rule_toggle(state, p):
    _integration(state, "pfsense")
    enabled = _enabled(p)
    r = _pf_item(state, "rules", "tracker", p["tracker"], "firewall rule")
    label = r.get("descr") or f"{r.get('type')} {r.get('source')} -> {r.get('destination')}"
    return {"tracker": r["tracker"], "enabled": enabled}, \
        f"{'Enable' if enabled else 'Disable'} pfSense rule on {r.get('interface')}: {label} and apply"


def exec_rule_toggle(state, r):
    return str(_integration(state, "pfsense").set_rule_disabled(r["tracker"], not r["enabled"]))


def prep_tunnel_toggle(state, p):
    _integration(state, "pfsense")
    enabled = _enabled(p)
    t = _pf_item(state, "tunnels", "ikeid", p["ikeid"], "IPsec tunnel")
    return {"ikeid": t["ikeid"], "enabled": enabled}, \
        f"{'Enable' if enabled else 'Disable'} IPsec tunnel {t.get('descr') or t['ikeid']} ({t.get('remote_gateway')}) and apply"


def exec_tunnel_toggle(state, r):
    return str(_integration(state, "pfsense").set_tunnel_disabled(r["ikeid"], not r["enabled"]))


ACTIONS = {
    "guest_power": (prep_power, exec_power),
    "set_guest_memory": (prep_memory, exec_memory),
    "snapshot_guest": (prep_snapshot, exec_snapshot),
    "add_dhcp_reservation": (prep_reservation, exec_reservation),
    "add_dns_record": (prep_dns_add, exec_dns_add),
    "remove_dns_record": (prep_dns_remove, exec_dns_remove),
    "add_to_firewall_alias": (prep_alias, exec_alias),
    "set_firewall_rule_enabled": (prep_rule_toggle, exec_rule_toggle),
    "set_ipsec_tunnel_enabled": (prep_tunnel_toggle, exec_tunnel_toggle),
}

# Actions the dashboard buttons may run directly (the user clicks, then confirms in the browser).
DIRECT = {"guest_power", "set_firewall_rule_enabled", "set_ipsec_tunnel_enabled"}


def propose(state, db, tool: str, params: dict) -> dict:
    prepare, _ = ACTIONS[tool]
    resolved, summary = prepare(state, params)
    action_id = db.add_action(tool, resolved, summary)
    return {"id": action_id, "summary": summary}


def approve(state, db, action_id: int) -> dict:
    action = db.get_action(action_id)
    if action is None:
        raise KeyError(action_id)
    if not db.claim_action(action_id, "running"):
        raise ValueError(f"action {action_id} is already {action['status']}")
    _, execute = ACTIONS[action["tool"]]
    try:
        result = execute(state, action["input"])
        db.finish_action(action_id, "done", result)
    except Exception as e:
        db.finish_action(action_id, "failed", str(e)[:1000])
    return db.get_action(action_id)


def reject(db, action_id: int) -> dict:
    if not db.claim_action(action_id, "rejected"):
        raise ValueError(f"action {action_id} is not pending")
    return db.get_action(action_id)
