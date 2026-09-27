"""IP inventory: merge every source's sightings, find conflicts, suggest free addresses."""

from collections import defaultdict
from ipaddress import IPv4Address, IPv4Network

LIVE_SOURCES = {"proxmox-live", "dhcp-lease", "pfsense-arp"}


def build_subnets(scopes: list[dict], extra: dict[str, IPv4Network], pf_interfaces: list[dict]) -> list[dict]:
    """Known subnets: DHCP scopes, pfSense interface networks, and EXTRA_SUBNETS."""
    subnets: dict[IPv4Network, dict] = {}
    for s in scopes:
        net = IPv4Network(s["cidr"])
        subnets[net] = {"name": s.get("Name") or s["cidr"], "network": net,
                        "pool": (IPv4Address(s["start"]), IPv4Address(s["end"])), "state": s.get("state")}
    for iface in pf_interfaces:
        ip, bits = iface.get("ipaddr"), iface.get("subnet")
        if ip and bits and ip[0].isdigit():
            net = IPv4Network(f"{ip}/{bits}", strict=False)
            entry = subnets.setdefault(net, {"name": iface.get("descr") or iface.get("name"), "network": net, "pool": None})
            entry["gateway"] = IPv4Address(ip)
            entry["interface"] = iface.get("descr") or iface.get("name")
    for name, net in extra.items():
        subnets.setdefault(net, {"name": name, "network": net, "pool": None})
    return sorted(subnets.values(), key=lambda s: s["network"])


def subnet_for(ip: IPv4Address, subnets: list[dict]) -> dict | None:
    return next((s for s in subnets if ip in s["network"]), None)


def build_inventory(observations: list[dict], subnets: list[dict], guests: list[dict] | None = None,
                    free_per_subnet: int = 5) -> dict:
    by_ip: dict[IPv4Address, list[dict]] = defaultdict(list)
    for o in observations:
        try:
            by_ip[IPv4Address(o["ip"])].append(o)
        except ValueError:
            continue

    addresses, findings = [], []
    for ip in sorted(by_ip):
        obs = by_ip[ip]
        sources = sorted({o["source"] for o in obs})
        macs = sorted({o["mac"] for o in obs if o.get("mac")})
        names = sorted({o["name"] for o in obs if o.get("name")})
        net = subnet_for(ip, subnets)
        addresses.append({"ip": str(ip), "subnet": str(net["network"]) if net else None,
                          "subnet_name": net["name"] if net else None,
                          "sources": sources, "macs": macs, "names": names})

        if len(macs) > 1:
            findings.append({"severity": "critical", "type": "duplicate_ip", "ip": str(ip),
                             "message": f"{ip} is used by {len(macs)} different MACs ({', '.join(macs)}): {', '.join(names) or 'unnamed'}"})
        if sources == ["dns"]:
            findings.append({"severity": "warning", "type": "stale_dns", "ip": str(ip),
                             "message": f"DNS record {', '.join(names)} -> {ip} but nothing is seen using that IP"})
        if "proxmox-config" in sources and "dhcp-reservation" not in sources and net and net.get("pool"):
            lo, hi = net["pool"]
            if lo <= ip <= hi:
                findings.append({"severity": "critical", "type": "static_in_dhcp_pool", "ip": str(ip),
                                 "message": f"{', '.join(names)} has static IP {ip} inside the DHCP pool {lo}-{hi} with no reservation"})
        if {"proxmox-config", "proxmox-live"} & set(sources) and "dns" not in sources:
            findings.append({"severity": "info", "type": "no_dns", "ip": str(ip),
                             "message": f"{', '.join(names) or ip} has no DNS A record"})
        if net is None and set(sources) != {"dns"}:
            findings.append({"severity": "warning", "type": "unknown_subnet", "ip": str(ip),
                             "message": f"{ip} ({', '.join(names) or 'unnamed'}) is not in any known subnet"})

    for g in guests or []:
        if g.get("status") == "running" and not g.get("live_ips") and not any(n.get("ip") for n in g.get("nics", [])):
            hint = " (install qemu-guest-agent to see its IP)" if g["type"] == "qemu" and not g.get("agent_enabled") else ""
            findings.append({"severity": "info", "type": "guest_ip_unknown", "ip": None,
                             "message": f"{g['type']}/{g['vmid']} {g['name']} is running but its IP is unknown{hint}"})

    used = set(by_ip)
    subnet_rows = []
    for s in subnets:
        net = s["network"]
        in_net = [ip for ip in used if ip in net]
        subnet_rows.append({
            "name": s["name"], "cidr": str(net), "interface": s.get("interface"),
            "gateway": str(s["gateway"]) if s.get("gateway") else None,
            "pool": f"{s['pool'][0]}-{s['pool'][1]}" if s.get("pool") else None,
            "used": len(in_net), "size": max(net.num_addresses - 2, 0),
            "next_free": next_free(s, used, free_per_subnet),
        })

    order = {"critical": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: order[f["severity"]])
    return {"addresses": addresses, "subnets": subnet_rows, "findings": findings}


def next_free(subnet: dict, used: set[IPv4Address], count: int = 5) -> list[str]:
    """Free static addresses: not seen anywhere, not the gateway, and outside the DHCP pool."""
    out = []
    pool = subnet.get("pool")
    for ip in subnet["network"].hosts():
        if ip in used or ip == subnet.get("gateway"):
            continue
        if pool and pool[0] <= ip <= pool[1]:
            continue
        if int(ip) & 0xFF in (0, 1, 255):  # keep .1 and edges free for gateways by convention
            continue
        out.append(str(ip))
        if len(out) >= count:
            break
    return out
