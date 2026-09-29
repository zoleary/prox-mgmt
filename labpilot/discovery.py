"""Network discovery: find devices on the lab's subnets and suggest inventory entries.

Combines what the integrations already saw (pfSense ARP, DHCP, Proxmox) with a TCP
connect scan of common ports. Only private subnets are scanned, and at most MAX_HOSTS
addresses per run.
"""

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from ipaddress import IPv4Address, IPv4Network

from .inventory import tcp_check

# port -> service label
PORTS = {22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS", 445: "SMB", 631: "IPP printing", 1883: "MQTT",
         3389: "RDP", 5000: "Synology DSM", 5001: "Synology DSM (HTTPS)", 8006: "Proxmox VE",
         8007: "Proxmox Backup Server", 8080: "HTTP alt", 8123: "Home Assistant", 8443: "UniFi / HTTPS alt",
         9100: "Printer (JetDirect)", 32400: "Plex"}
MAX_HOSTS = 4096
TIMEOUT = 0.5


def parse_subnets(cidrs: list[str]) -> list[IPv4Network]:
    nets, total = [], 0
    for c in cidrs:
        c = str(c).strip()
        if not c:
            continue
        try:
            net = IPv4Network(c, strict=False)
        except ValueError:
            raise ValueError(f"{c!r} is not a valid subnet, e.g. 10.0.0.0/24")
        if not net.is_private:
            raise ValueError(f"{net} is not a private network; only lab subnets can be scanned")
        total += max(net.num_addresses - 2, 1)
        nets.append(net)
    if not nets:
        raise ValueError("give at least one subnet to scan, e.g. 10.0.0.0/24")
    if total > MAX_HOSTS:
        raise ValueError(f"that's {total} addresses; scan at most {MAX_HOSTS} at a time (e.g. a few /24s)")
    return nets


def guess(ports: list[int], names: list[str], ip: str) -> tuple[str, str | None]:
    """(kind, role) from open ports and any names we know."""
    p, text = set(ports), " ".join(names).lower()
    if 8006 in p or "pve" in text or "proxmox" in text:
        return "hypervisor", "Proxmox VE"
    if 8007 in p:
        return "server", "Proxmox Backup Server"
    if {5000, 5001} & p or "synology" in text or "nas" in text:
        return "nas", "NAS"
    if {9100, 631} & p or "printer" in text:
        return "printer", None
    if "pfsense" in text or (53 in p and {80, 443} & p and ip.endswith(".1")):
        return "firewall", "Router / firewall"
    if 8443 in p and 8080 in p:
        return "server", "UniFi controller"
    if 8123 in p:
        return "server", "Home Assistant"
    if 32400 in p:
        return "server", "Plex"
    if 3389 in p:
        return "workstation", "Windows (RDP)"
    if 1883 in p:
        return "iot", "MQTT broker"
    if 22 in p:
        return "server", None
    if {80, 443} & p:
        return "other", "Web interface"
    return "other", None


def reverse_dns(ip: str) -> str | None:
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name if name and name != ip else None
    except OSError:
        return None


class Discovery:
    """One scan at a time, run in a background thread; the UI polls status()."""

    def __init__(self):
        self.lock = threading.Lock()
        self._state = {"running": False, "done": 0, "total": 0, "started": None, "finished": None,
                       "subnets": [], "results": [], "error": None}

    def status(self) -> dict:
        with self.lock:
            return dict(self._state)

    def start(self, cidrs: list[str], known: list[dict], devices: list[dict]) -> dict:
        nets = parse_subnets(cidrs)
        with self.lock:
            if self._state["running"]:
                raise ValueError("a discovery scan is already running")
            hosts = [str(ip) for n in nets for ip in (n.hosts() if n.num_addresses > 2 else [n.network_address])]
            self._state.update(running=True, done=0, total=len(hosts) * len(PORTS), started=time.time(),
                               finished=None, subnets=[str(n) for n in nets], results=[], error=None)
        threading.Thread(target=self._run, args=(hosts, nets, known, devices), daemon=True).start()
        return self.status()

    def _tick(self):
        with self.lock:
            self._state["done"] += 1

    def _probe(self, ip: str, port: int) -> tuple[str, int, bool]:
        up, _ = tcp_check(ip, port, TIMEOUT)
        self._tick()
        return ip, port, up

    def _run(self, hosts, nets, known, devices):
        try:
            with ThreadPoolExecutor(max_workers=128) as pool:
                probes = list(pool.map(lambda t: self._probe(*t), [(h, p) for h in hosts for p in PORTS]))
            open_ports: dict[str, list[int]] = {}
            for ip, port, up in probes:
                if up:
                    open_ports.setdefault(ip, []).append(port)
            results = merge(open_ports, known, devices, nets)
            with ThreadPoolExecutor(max_workers=32) as pool:
                futures = {r["ip"]: pool.submit(reverse_dns, r["ip"]) for r in results if not r["names"]}
                for r in results:
                    f = futures.get(r["ip"])
                    try:
                        dns = f.result(timeout=3) if f else None
                    except FutureTimeout:
                        dns = None
                    if dns:
                        r["names"].append(dns)
                    finish(r)
            with self.lock:
                self._state.update(results=results)
        except Exception as e:  # report instead of dying silently
            with self.lock:
                self._state["error"] = str(e)[:300]
        finally:
            with self.lock:
                self._state.update(running=False, finished=time.time(), done=self._state["total"])


def merge(open_ports: dict[str, list[int]], known: list[dict], devices: list[dict], nets: list[IPv4Network]) -> list[dict]:
    """Combine scan hits with addresses the integrations already saw (in the scanned subnets)."""
    inv = {d["ip"]: d for d in devices if d.get("ip")}
    rows: dict[str, dict] = {}
    for a in known:
        ip = IPv4Address(a["ip"])
        if any(ip in n for n in nets):
            rows[a["ip"]] = {"ip": a["ip"], "names": list(a.get("names") or []), "macs": list(a.get("macs") or []),
                             "sources": [s for s in a.get("sources", []) if s != "inventory"], "ports": []}
    for ip, ports in open_ports.items():
        row = rows.setdefault(ip, {"ip": ip, "names": [], "macs": [], "sources": [], "ports": []})
        row["ports"] = sorted(ports)
        row["sources"].append("scan")
    for r in rows.values():
        r["in_inventory"] = inv.get(r["ip"], {}).get("name")
    return sorted(rows.values(), key=lambda r: IPv4Address(r["ip"]))


def finish(r: dict) -> None:
    """Fill the suggested inventory fields for one discovered address."""
    kind, role = guess(r["ports"], r["names"], r["ip"])
    name = (r["names"][0].split(".")[0] if r["names"] else f"host-{r['ip'].replace('.', '-')}")[:64]
    check = next((p for p in (8006, 8007, 5001, 5000, 443, 22, 80, 8123, 32400, 9100, 445, 3389) if p in r["ports"]), None)
    r.update(kind=kind, role=role, suggested_name=name, check_port=check,
             services=[PORTS[p] for p in r["ports"]], mac=(r["macs"] or [None])[0])
