"""Health alerts derived from the latest collected state. Pure functions, no I/O."""

import re

TUNNEL_UP = re.compile(r"establish|install|connect", re.I)
GATEWAY_OK = {"online", "none", ""}


def build_alerts(*, nodes, quorum, memory_nodes, errors, tunnels, gateways, devices, device_status,
                 findings) -> list[dict]:
    alerts = []

    def add(severity, key, message):
        alerts.append({"severity": severity, "key": key, "message": message})

    if quorum is False:
        add("critical", "quorum", "Proxmox cluster has lost quorum")
    for n in nodes:
        if n.get("status") != "online":
            add("critical", f"node:{n['node']}", f"Proxmox node {n['node']} is {n.get('status') or 'unknown'}")
    for m in memory_nodes:
        if not m.get("total"):
            continue
        if m.get("host_used_pct", 0) >= 90:
            add("warning", f"mem:{m['node']}", f"{m['node']} host RAM is at {m['host_used_pct']}%")
        if m.get("status") == "critical":
            add("warning", f"overcommit:{m['node']}", f"{m['node']} memory overcommit is {m['overcommit_ratio']}x")
    for name, err in errors.items():
        add("warning", f"integration:{name}", f"Can't reach {name}: {err[:160]}")
    for t in tunnels:
        if not t.get("disabled") and not TUNNEL_UP.search(str(t.get("state") or "")):
            add("warning", f"tunnel:{t.get('ikeid')}", f"IPsec tunnel {t.get('descr') or t.get('ikeid')} is {t.get('state') or 'down'}")
    for g in gateways:
        status = str(g.get("status") or "").lower()
        if status not in GATEWAY_OK:
            sev = "critical" if status == "down" else "warning"
            add(sev, f"gateway:{g.get('name')}", f"Gateway {g.get('name')} is {status} (loss {g.get('loss') or '?'}, delay {g.get('delay') or '?'})")
    for d in devices:
        st = device_status.get(d["id"])
        if st and not st["up"]:
            add("critical", f"device:{d['id']}", f"{d['name']} ({d['ip']}:{d['check_port']}) is not responding")
    for f in findings:
        if f["type"] == "duplicate_ip":
            add("critical", f"dup:{f['ip']}", f["message"])

    order = {"critical": 0, "warning": 1}
    return sorted(alerts, key=lambda a: order[a["severity"]])


def track_since(alerts: list[dict], seen: dict[str, float], now: float) -> dict[str, float]:
    """Stamp each alert with when it first appeared; forget alerts that cleared."""
    current = {}
    for a in alerts:
        current[a["key"]] = seen.get(a["key"], now)
        a["since"] = current[a["key"]]
    return current
