import pytest

from labpilot import actions
from labpilot.config import Settings
from labpilot.db import DB
from labpilot.integrations.proxmox import lxc_nics, qemu_nics
from labpilot.integrations.windows import WindowsDhcpDns, ps_str, valid_hostname


class FakeProxmox:
    name = "proxmox"

    def __init__(self):
        self.calls = []

    def configured(self):
        return True

    def power(self, *a):
        self.calls.append(("power", a))
        return "UPID:ok"


class FakeState:
    def __init__(self):
        self.s = Settings(dns_zones="lab.home", windows_host="dc", windows_user="u", windows_password="p")
        self.integrations = {"proxmox": FakeProxmox(), "windows": WindowsDhcpDns(self.s)}
        self.guests = [{"vmid": 101, "name": "web", "node": "pve1", "type": "qemu"}]

    def find_guest(self, ref):
        for g in self.guests:
            if str(g["vmid"]) == str(ref) or g["name"] == ref:
                return g
        raise ValueError("no guest")


@pytest.fixture
def env(tmp_path):
    return FakeState(), DB(str(tmp_path))


def test_propose_does_not_execute_until_approved(env):
    state, db = env
    p = actions.propose(state, db, "guest_power", {"guest": "web", "action": "reboot"})
    assert state.integrations["proxmox"].calls == []
    assert db.get_action(p["id"])["status"] == "pending"
    done = actions.approve(state, db, p["id"])
    assert done["status"] == "done"
    assert state.integrations["proxmox"].calls == [("power", ("pve1", "qemu", 101, "reboot"))]
    with pytest.raises(ValueError):
        actions.approve(state, db, p["id"])  # can't run twice


def test_reject(env):
    state, db = env
    p = actions.propose(state, db, "guest_power", {"guest": "101", "action": "stop"})
    assert actions.reject(db, p["id"])["status"] == "rejected"
    with pytest.raises(ValueError):
        actions.approve(state, db, p["id"])


@pytest.mark.parametrize("tool,params", [
    ("guest_power", {"guest": "web", "action": "destroy"}),
    ("set_guest_memory", {"guest": "web", "memory_mb": 4096, "balloon_min_mb": 8192}),
    ("add_dns_record", {"zone": "evil.com", "name": "x", "ip": "10.0.0.1"}),
    ("add_dns_record", {"zone": "lab.home", "name": "x'; Remove-Item C:\\ -Recurse; '", "ip": "10.0.0.1"}),
    ("add_dhcp_reservation", {"scope_id": "10.0.0.0", "ip": "10.0.0.300", "mac": "aa:bb:cc:dd:ee:ff", "name": "x"}),
    ("add_dhcp_reservation", {"scope_id": "10.0.0.0", "ip": "10.0.0.3", "mac": "not-a-mac", "name": "x"}),
])
def test_invalid_proposals_rejected(env, tool, params):
    state, db = env
    with pytest.raises(ValueError):
        actions.propose(state, db, tool, params)
    assert db.list_actions() == []


def test_powershell_quoting():
    assert ps_str("it's") == "'it''s'"
    with pytest.raises(ValueError):
        valid_hostname("a b")


def test_parse_proxmox_nics():
    q = qemu_nics({"net0": "virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,tag=20",
                   "ipconfig0": "ip=10.0.20.15/24,gw=10.0.20.1", "memory": "4096"})
    assert q == [{"id": "net0", "mac": "bc:24:11:aa:bb:cc", "bridge": "vmbr0", "vlan": "20",
                  "ip": "10.0.20.15", "dhcp": False}]
    l = lxc_nics({"net0": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,ip=dhcp,tag=30"})
    assert l[0]["dhcp"] and l[0]["ip"] is None and l[0]["vlan"] == "30"


class FakePfSense:
    name = "pfsense"

    def __init__(self):
        self.calls = []

    def configured(self):
        return True

    def set_rule_disabled(self, tracker, disabled):
        self.calls.append(("rule", tracker, disabled))
        return {"changed": True}

    def set_tunnel_disabled(self, ikeid, disabled):
        self.calls.append(("tunnel", ikeid, disabled))
        return {"changed": True}


@pytest.fixture
def pf_env(env):
    state, db = env
    state.integrations["pfsense"] = FakePfSense()
    state.raw = {"pfsense": {
        "rules": [{"tracker": 1700000001, "interface": "lan", "type": "pass", "descr": "LAN to any", "disabled": False}],
        "tunnels": [{"ikeid": 1, "descr": "Office", "remote_gateway": "203.0.113.5", "disabled": True, "state": "down"}],
    }}
    return state, db


def test_disable_firewall_rule(pf_env):
    state, db = pf_env
    p = actions.propose(state, db, "set_firewall_rule_enabled", {"tracker": "1700000001", "enabled": False})
    assert "Disable" in p["summary"] and "LAN to any" in p["summary"]
    assert actions.approve(state, db, p["id"])["status"] == "done"
    assert state.integrations["pfsense"].calls == [("rule", 1700000001, True)]


def test_enable_ipsec_tunnel(pf_env):
    state, db = pf_env
    p = actions.propose(state, db, "set_ipsec_tunnel_enabled", {"ikeid": "1", "enabled": True})
    assert "Office" in p["summary"]
    actions.approve(state, db, p["id"])
    assert state.integrations["pfsense"].calls == [("tunnel", 1, False)]


@pytest.mark.parametrize("tool,params", [
    ("set_firewall_rule_enabled", {"tracker": "999", "enabled": False}),
    ("set_firewall_rule_enabled", {"tracker": "1700000001", "enabled": "no"}),
    ("set_ipsec_tunnel_enabled", {"ikeid": "7", "enabled": True}),
])
def test_invalid_pfsense_toggles(pf_env, tool, params):
    state, db = pf_env
    with pytest.raises(ValueError):
        actions.propose(state, db, tool, params)


def test_ipsec_tunnel_state():
    from labpilot.integrations.pfsense import ipsec_tunnels
    t = ipsec_tunnels([{"ikeid": 2, "descr": "DC", "remote_gateway": "198.51.100.1", "disabled": False},
                       {"ikeid": 3, "descr": "Old", "remote_gateway": "198.51.100.2", "disabled": True}],
                      [{"con_id": "con2", "state": "ESTABLISHED"}])
    assert [x["state"] for x in t] == ["ESTABLISHED", "down"]
    assert t[1]["disabled"] is True
