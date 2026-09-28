"""Collects data from every integration and derives the dashboard state."""

import logging
import time
from concurrent.futures import ThreadPoolExecutor

from . import inventory
from .analysis.alerts import build_alerts, track_since
from .analysis.ipam import build_inventory, build_subnets
from .analysis.memory import memory_report

log = logging.getLogger(__name__)


class LabState:
    def __init__(self, settings, integrations: dict, db=None):
        self.s = settings
        self.integrations = integrations
        self.db = db
        self.devices: list[dict] = []
        self.device_status: dict[int, dict] = {}
        self.alerts: list[dict] = []
        self._alert_seen: dict[str, float] = {}
        self.raw: dict[str, dict] = {}
        self.errors: dict[str, str] = {}
        self.updated: float | None = None

    def refresh(self) -> None:
        active = {n: i for n, i in self.integrations.items() if i.configured()}
        with ThreadPoolExecutor(max_workers=len(active) or 1) as pool:
            futures = {n: pool.submit(i.collect) for n, i in active.items()}
        raw, errors = {}, {}
        for name, fut in futures.items():
            try:
                raw[name] = fut.result()
            except Exception as e:  # one broken integration must not break the dashboard
                log.warning("%s collect failed: %s", name, e)
                errors[name] = str(e)[:500]
                raw[name] = self.raw.get(name, {})  # keep last good data
        self.raw, self.errors, self.updated = raw, errors, time.time()
        self.load_devices()
        self.device_status = inventory.check_devices(self.devices, self.device_status)
        self.update_alerts()

    def load_devices(self) -> None:
        if self.db is not None:
            self.devices = self.db.list_devices()

    def update_alerts(self) -> None:
        pf = self.raw.get("pfsense", {})
        alerts = build_alerts(
            nodes=self.nodes, quorum=self.raw.get("proxmox", {}).get("quorum"),
            memory_nodes=self.memory()["nodes"], errors=self.errors,
            tunnels=pf.get("tunnels", []), gateways=pf.get("gateways", []),
            devices=self.devices, device_status=self.device_status, findings=self.ipam()["findings"])
        self._alert_seen = track_since(alerts, self._alert_seen, time.time())
        self.alerts = alerts

    # ---------- derived views ----------

    @property
    def guests(self) -> list[dict]:
        return self.raw.get("proxmox", {}).get("guests", [])

    @property
    def nodes(self) -> list[dict]:
        return self.raw.get("proxmox", {}).get("nodes", [])

    def integration_status(self) -> list[dict]:
        return [{"name": n, "configured": i.configured(), "ok": i.configured() and n not in self.errors,
                 "error": self.errors.get(n)} for n, i in self.integrations.items()]

    def subnets(self) -> list[dict]:
        return build_subnets(self.raw.get("windows", {}).get("scopes", []), self.s.subnets,
                             self.raw.get("pfsense", {}).get("interfaces", []))

    def ipam(self) -> dict:
        obs = [o for data in self.raw.values() for o in data.get("observations", [])]
        obs += inventory.observations(self.devices)
        return build_inventory(obs, self.subnets(), self.guests)

    def memory(self) -> dict:
        return memory_report(self.nodes, self.guests, self.s.mem_warn_ratio, self.s.mem_crit_ratio)

    def find_guest(self, ref) -> dict:
        ref = str(ref).strip()
        for g in self.guests:
            if str(g["vmid"]) == ref or (g.get("name") or "").lower() == ref.lower():
                return g
        raise ValueError(f"no guest with id or name {ref!r}")

    def devices_with_status(self) -> list[dict]:
        return [{**d, "status": self.device_status.get(d["id"])} for d in self.devices]

    def overview(self) -> dict:
        guests = self.guests
        ipam = self.ipam()
        pf = self.raw.get("pfsense", {})
        return {
            "updated": self.updated,
            "alerts": self.alerts,
            "integrations": self.integration_status(),
            "quorate": self.raw.get("proxmox", {}).get("quorum"),
            "nodes": self.nodes,
            "memory": self.memory(),
            "guest_counts": {
                "total": len(guests),
                "running": sum(g["status"] == "running" for g in guests),
                "vms": sum(g["type"] == "qemu" for g in guests),
                "containers": sum(g["type"] == "lxc" for g in guests),
            },
            "findings": ipam["findings"],
            "subnets": ipam["subnets"],
            "pfsense": {"system": pf.get("system"), "gateways": pf.get("gateways", [])},
        }
