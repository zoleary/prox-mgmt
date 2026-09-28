import socket

import pytest

from labpilot import actions, inventory
from labpilot.analysis.alerts import build_alerts, track_since
from labpilot.db import DB


def test_clean_device_normalizes_and_validates():
    d = inventory.clean_device({"name": " nas ", "kind": "NAS", "ip": "10.0.0.50", "mac": "AA-BB-CC-DD-EE-FF",
                                "check_port": "5000", "notes": "Synology"})
    assert d["name"] == "nas" and d["kind"] == "nas" and d["mac"] == "aa:bb:cc:dd:ee:ff" and d["check_port"] == 5000
    for bad in [{"name": ""}, {"name": "x", "kind": "toaster"}, {"name": "x", "ip": "10.0.0.300"},
                {"name": "x", "mac": "nope"}, {"name": "x", "ip": "10.0.0.5", "check_port": 70000},
                {"name": "x", "check_port": 22}]:
        with pytest.raises(ValueError):
            inventory.clean_device(bad)


def test_device_crud(tmp_path):
    db = DB(str(tmp_path))
    i = db.save_device(inventory.clean_device({"name": "switch", "kind": "switch", "ip": "10.0.0.2"}))
    db.save_device(inventory.clean_device({"name": "switch", "kind": "switch", "ip": "10.0.0.3"}), i)
    assert [d["ip"] for d in db.list_devices()] == ["10.0.0.3"]
    with pytest.raises(KeyError):
        db.save_device(inventory.clean_device({"name": "ghost"}), 999)
    assert db.delete_device(i) and db.list_devices() == []


def test_inventory_ips_feed_the_ip_list():
    obs = inventory.observations([{"name": "nas", "ip": "10.0.0.50", "mac": None, "kind": "nas", "role": None},
                                  {"name": "no-ip", "ip": None}])
    assert obs == [{"ip": "10.0.0.50", "source": "inventory", "mac": None, "name": "nas", "detail": "nas"}]


def test_port_check_up_and_down():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    devs = [{"id": 1, "ip": "127.0.0.1", "check_port": port}, {"id": 2, "ip": "127.0.0.1", "check_port": 1}]
    st = inventory.check_devices(devs, {})
    srv.close()
    assert st[1]["up"] and not st[2]["up"]
    again = inventory.check_devices(devs[1:], st)
    assert again[2]["since"] == st[2]["since"]  # still down: keeps the original time


def test_alerts():
    alerts = build_alerts(
        nodes=[{"node": "pve1", "status": "online"}, {"node": "pve2", "status": "offline"}], quorum=False,
        memory_nodes=[{"node": "pve1", "total": 1, "host_used_pct": 95, "status": "ok", "overcommit_ratio": 1}],
        errors={"pfsense": "timed out"},
        tunnels=[{"ikeid": 1, "descr": "Office", "disabled": False, "state": "down"},
                 {"ikeid": 2, "descr": "Up", "disabled": False, "state": "ESTABLISHED"},
                 {"ikeid": 3, "descr": "Off", "disabled": True, "state": "down"}],
        gateways=[{"name": "WAN", "status": "online"}, {"name": "WAN2", "status": "down"}],
        devices=[{"id": 7, "name": "nas", "ip": "10.0.0.50", "check_port": 5000}],
        device_status={7: {"up": False}},
        findings=[{"type": "duplicate_ip", "ip": "10.0.0.9", "message": "dup"}, {"type": "no_dns", "ip": "x", "message": "m"}])
    keys = {a["key"] for a in alerts}
    assert keys == {"quorum", "node:pve2", "mem:pve1", "integration:pfsense", "tunnel:1", "gateway:WAN2", "device:7", "dup:10.0.0.9"}
    assert alerts[0]["severity"] == "critical"
    seen = track_since(alerts, {"quorum": 100.0}, 200.0)
    assert seen["quorum"] == 100.0 and seen["node:pve2"] == 200.0


def test_assistant_save_device_needs_approval(tmp_path):
    class S:
        db = DB(str(tmp_path))
        devices = []

        def load_devices(self):
            self.devices = self.db.list_devices()

    state, db = S(), DB(str(tmp_path / "q"))
    p = actions.propose(state, db, "save_device", {"name": "nas", "kind": "nas", "ip": "10.0.0.50"})
    assert state.db.list_devices() == [] and "Add inventory device nas" in p["summary"]
    assert actions.approve(state, db, p["id"])["status"] == "done"
    assert state.devices[0]["ip"] == "10.0.0.50"
    p2 = actions.propose(state, db, "save_device", {"name": "NAS", "kind": "nas", "ip": "10.0.0.51"})
    assert p2["summary"].startswith("Update")
