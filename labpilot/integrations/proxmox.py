"""Proxmox VE cluster: nodes, guests, memory and guest IP addresses."""

import logging
import re

from proxmoxer import ProxmoxAPI

from .base import Integration, Observation, normalize_mac

log = logging.getLogger(__name__)

POWER_ACTIONS = {"start", "shutdown", "stop", "reboot"}
MB = 1024 * 1024


def parse_kv(value: str) -> dict[str, str]:
    """Parse Proxmox 'a=1,b=2' option strings. A bare first item (e.g. a MAC) is kept under ''."""
    out: dict[str, str] = {}
    for part in (value or "").split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
        elif part.strip():
            out[""] = part.strip()
    return out


def qemu_nics(config: dict) -> list[dict]:
    """NICs from a QEMU config, with static IPs taken from the matching cloud-init ipconfigN."""
    nics = []
    for key, value in config.items():
        m = re.fullmatch(r"net(\d+)", key)
        if not m:
            continue
        opts = parse_kv(value)
        mac = next((v for k, v in opts.items() if k in {"virtio", "e1000", "e1000e", "vmxnet3", "rtl8139"}), None)
        ipcfg = parse_kv(config.get(f"ipconfig{m.group(1)}", ""))
        ip = ipcfg.get("ip", "")
        nics.append(
            {
                "id": key,
                "mac": normalize_mac(mac),
                "bridge": opts.get("bridge"),
                "vlan": opts.get("tag"),
                "ip": ip.split("/")[0] if ip and ip != "dhcp" else None,
                "dhcp": ip == "dhcp",
            }
        )
    return nics


def lxc_nics(config: dict) -> list[dict]:
    nics = []
    for key, value in config.items():
        if not re.fullmatch(r"net\d+", key):
            continue
        opts = parse_kv(value)
        ip = opts.get("ip", "")
        nics.append(
            {
                "id": key,
                "mac": normalize_mac(opts.get("hwaddr")),
                "bridge": opts.get("bridge"),
                "vlan": opts.get("tag"),
                "ip": ip.split("/")[0] if ip and ip not in {"dhcp", "manual"} else None,
                "dhcp": ip == "dhcp",
            }
        )
    return nics


class Proxmox(Integration):
    name = "proxmox"

    def __init__(self, settings):
        self.s = settings
        self._api = None

    def configured(self) -> bool:
        return bool(self.s.pve_host and self.s.pve_token_id and self.s.pve_token_secret)

    @property
    def api(self) -> ProxmoxAPI:
        if self._api is None:
            user, token_name = self.s.pve_token_id.split("!", 1)
            self._api = ProxmoxAPI(
                self.s.pve_host,
                port=self.s.pve_port,
                user=user,
                token_name=token_name,
                token_value=self.s.pve_token_secret,
                verify_ssl=self.s.pve_verify_ssl,
                timeout=15,
            )
        return self._api

    # ---------- reads ----------

    def _guest_api(self, node: str, kind: str, vmid: int):
        node_api = self.api.nodes(node)
        return node_api.qemu(vmid) if kind == "qemu" else node_api.lxc(vmid)

    def _agent_ips(self, node: str, vmid: int) -> list[dict]:
        try:
            res = self.api.nodes(node).qemu(vmid).agent("network-get-interfaces").get()
        except Exception:
            return []  # agent not installed / not running
        out = []
        for iface in res.get("result", []):
            if iface.get("name") == "lo":
                continue
            for addr in iface.get("ip-addresses", []):
                if addr.get("ip-address-type") == "ipv4" and not addr["ip-address"].startswith("127."):
                    out.append({"ip": addr["ip-address"], "mac": normalize_mac(iface.get("hardware-address"))})
        return out

    def _lxc_ips(self, node: str, vmid: int) -> list[dict]:
        try:
            res = self.api.nodes(node).lxc(vmid).interfaces.get()
        except Exception:
            return []
        out = []
        for iface in res or []:
            inet = iface.get("inet")
            if iface.get("name") != "lo" and inet and not inet.startswith("127."):
                out.append({"ip": inet.split("/")[0], "mac": normalize_mac(iface.get("hwaddr"))})
        return out

    def collect(self) -> dict:
        cluster_status = self.api.cluster.status.get()
        node_ips = {c.get("name"): c.get("ip") for c in cluster_status if c.get("type") == "node"}
        nodes = []
        for n in self.api.nodes.get():
            entry = {"node": n["node"], "status": n.get("status"), "maxcpu": n.get("maxcpu"), "ip": node_ips.get(n["node"])}
            if n.get("status") == "online":
                st = self.api.nodes(n["node"]).status.get()
                entry.update(
                    cpu=st.get("cpu", 0),
                    mem_total=st["memory"]["total"],
                    mem_used=st["memory"]["used"],
                    swap_total=st.get("swap", {}).get("total", 0),
                    swap_used=st.get("swap", {}).get("used", 0),
                    ksm_shared=st.get("ksm", {}).get("shared", 0),
                    loadavg=st.get("loadavg"),
                    pveversion=st.get("pveversion"),
                    uptime=st.get("uptime"),
                )
            nodes.append(entry)

        guests = []
        observations = [Observation(n["ip"], "proxmox-node", None, n["node"], "Proxmox node") for n in nodes if n.get("ip")]
        for r in self.api.cluster.resources.get(type="vm"):
            if r.get("template"):
                continue
            kind, node, vmid = r["type"], r["node"], r["vmid"]
            g = {
                "vmid": vmid,
                "name": r.get("name"),
                "type": kind,
                "node": node,
                "status": r.get("status"),
                "maxmem": r.get("maxmem", 0),
                "mem": r.get("mem", 0),
                "cpu": r.get("cpu", 0),
                "maxcpu": r.get("maxcpu", 0),
                "uptime": r.get("uptime", 0),
                "tags": r.get("tags", ""),
                "ha": r.get("hastate"),
            }
            try:
                cfg = self._guest_api(node, kind, vmid).config.get()
            except Exception as e:
                log.warning("config for %s failed: %s", vmid, e)
                cfg = {}
            if kind == "qemu":
                g["nics"] = qemu_nics(cfg)
                # balloon=0 disables ballooning; unset means min == max
                balloon = cfg.get("balloon")
                g["balloon_min"] = (int(balloon) * MB if balloon not in (None, "0", 0) else g["maxmem"])
                g["ballooning"] = balloon not in ("0", 0)
                g["agent_enabled"] = str(cfg.get("agent", "0")).startswith(("1", "enabled=1"))
                live = self._agent_ips(node, vmid) if g["status"] == "running" and g["agent_enabled"] else []
            else:
                g["nics"] = lxc_nics(cfg)
                g["balloon_min"] = g["maxmem"]
                g["ballooning"] = False
                g["agent_enabled"] = None
                live = self._lxc_ips(node, vmid) if g["status"] == "running" else []
            g["live_ips"] = live

            for nic in g["nics"]:
                if nic["ip"]:
                    observations.append(Observation(nic["ip"], "proxmox-config", nic["mac"], g["name"], f"{kind}/{vmid} {nic['id']} vlan={nic['vlan']}"))
            for a in live:
                observations.append(Observation(a["ip"], "proxmox-live", a["mac"], g["name"], f"{kind}/{vmid}"))
            guests.append(g)

        return {
            "cluster": [c for c in cluster_status if c.get("type") == "cluster"],
            "quorum": next((c.get("quorate") for c in cluster_status if c.get("type") == "cluster"), None),
            "nodes": nodes,
            "guests": sorted(guests, key=lambda x: x["vmid"]),
            "observations": [o.to_dict() for o in observations],
        }

    # ---------- writes (only called after the user approves) ----------

    def power(self, node: str, kind: str, vmid: int, action: str) -> str:
        if action not in POWER_ACTIONS:
            raise ValueError(f"unsupported action {action}")
        return self._guest_api(node, kind, vmid).status(action).post()

    def set_memory(self, node: str, kind: str, vmid: int, memory_mb: int, balloon_min_mb: int | None) -> None:
        params = {"memory": memory_mb}
        if kind == "qemu" and balloon_min_mb is not None:
            params["balloon"] = balloon_min_mb
        self._guest_api(node, kind, vmid).config.put(**params)

    def snapshot(self, node: str, kind: str, vmid: int, name: str, description: str = "") -> str:
        return self._guest_api(node, kind, vmid).snapshot.post(snapname=name, description=description)
