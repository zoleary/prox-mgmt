"""Network diagram data: WAN -> firewall -> subnets -> hosts. Pure function, no I/O."""

from ipaddress import IPv4Address, IPv4Network


def build_topology(*, subnets, addresses, devices, device_status, nodes, guests, pf_system, gateways) -> dict:
    inv_by_ip = {d["ip"]: d for d in devices if d.get("ip")}
    node_by_ip = {n["ip"]: n for n in nodes if n.get("ip")}
    guest_by_ip = {}
    for g in guests:
        for ip in {n["ip"] for n in g.get("nics", []) if n.get("ip")} | {a["ip"] for a in g.get("live_ips", [])}:
            guest_by_ip.setdefault(ip, g)

    def host(ip: str, names: list[str]) -> dict:
        d, n, g = inv_by_ip.get(ip), node_by_ip.get(ip), guest_by_ip.get(ip)
        if d:
            st = device_status.get(d["id"])
            h = {"label": d["name"], "kind": d.get("kind") or "other", "role": d.get("role"),
                 "status": None if not st else ("up" if st["up"] else "down"), "source": "inventory"}
        elif n:
            h = {"label": n["node"], "kind": "hypervisor", "role": "Proxmox node",
                 "status": "up" if n.get("status") == "online" else "down", "source": "proxmox"}
        elif g:
            h = {"label": g["name"], "kind": "vm" if g["type"] == "qemu" else "container",
                 "role": f"{'VM' if g['type'] == 'qemu' else 'CT'} {g['vmid']} on {g['node']}",
                 "status": "up" if g["status"] == "running" else "down", "source": "proxmox"}
        else:
            h = {"label": names[0] if names else "unknown", "kind": "unknown", "role": None, "status": None,
                 "source": "seen"}
        if n or (d and d.get("kind") == "hypervisor" and (node := next((x for x in nodes if x["node"] == d["name"]), None))):
            node_name = (n or node)["node"]
            h["guests"] = [{"label": x["name"], "vmid": x["vmid"], "type": x["type"], "status": x["status"]}
                           for x in guests if x["node"] == node_name]
        h["ip"] = ip
        return h

    networks = [{"name": s["name"], "cidr": s["cidr"], "gateway": s.get("gateway"), "interface": s.get("interface"),
                 "hosts": []} for s in subnets]
    placed = set()
    for a in addresses:
        net = next((x for x in networks if IPv4Address(a["ip"]) in IPv4Network(x["cidr"])), None)
        if net is not None:
            net["hosts"].append(host(a["ip"], a.get("names") or []))
            placed.add(a["ip"])
    other = [host(a["ip"], a.get("names") or []) for a in addresses if a["ip"] not in placed]
    other += [{"label": d["name"], "kind": d.get("kind") or "other", "role": d.get("role"), "status": None,
               "source": "inventory", "ip": None} for d in devices if not d.get("ip")]
    order = {"firewall": 0, "router": 1, "switch": 2, "hypervisor": 3, "nas": 4, "server": 5}
    for net in networks:
        net["hosts"].sort(key=lambda h: (order.get(h["kind"], 9), IPv4Address(h["ip"])))

    return {
        "firewall": {"name": (pf_system or {}).get("hostname") or "pfSense", "connected": bool(pf_system)},
        "wan": [{"name": g.get("name"), "status": g.get("status"), "ip": g.get("srcip") or g.get("monitorip")} for g in gateways],
        "networks": networks,
        "other": other,
    }
