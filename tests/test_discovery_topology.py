import socket
import time

import pytest

from labpilot import discovery
from labpilot.analysis.topology import build_topology


def test_parse_subnets_limits():
    assert [str(n) for n in discovery.parse_subnets(["10.0.0.5/24", " "])] == ["10.0.0.0/24"]
    for bad in [["8.8.8.0/24"], ["10.0.0.0/16"], ["nope"], []]:
        with pytest.raises(ValueError):
            discovery.parse_subnets(bad)


@pytest.mark.parametrize("ports,names,ip,kind", [
    ([22, 8006], [], "10.0.0.5", "hypervisor"),
    ([80, 443, 5000], [], "10.0.0.9", "nas"),
    ([9100], [], "10.0.0.20", "printer"),
    ([53, 80, 443], [], "10.0.0.1", "firewall"),
    ([3389], [], "10.0.0.30", "workstation"),
    ([22], [], "10.0.0.40", "server"),
    ([], ["pve2.lab.home"], "10.0.0.6", "hypervisor"),
    ([], [], "10.0.0.50", "other"),
])
def test_guess(ports, names, ip, kind):
    assert discovery.guess(ports, names, ip)[0] == kind


def test_merge_combines_known_and_scan_and_flags_inventory():
    nets = discovery.parse_subnets(["10.0.0.0/24"])
    known = [{"ip": "10.0.0.7", "names": ["printer"], "macs": ["aa:bb:cc:dd:ee:ff"], "sources": ["pfsense-arp"]},
             {"ip": "192.168.9.9", "names": [], "macs": [], "sources": ["dhcp-lease"]}]  # outside scanned range
    rows = discovery.merge({"10.0.0.7": [9100], "10.0.0.8": [22]}, known, [{"ip": "10.0.0.8", "name": "box"}], nets)
    assert [r["ip"] for r in rows] == ["10.0.0.7", "10.0.0.8"]
    assert rows[0]["sources"] == ["pfsense-arp", "scan"] and rows[1]["in_inventory"] == "box"
    discovery.finish(rows[0])
    assert rows[0]["kind"] == "printer" and rows[0]["suggested_name"] == "printer" and rows[0]["check_port"] == 9100
    assert rows[0]["mac"] == "aa:bb:cc:dd:ee:ff"


def test_scan_finds_a_listening_port():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("127.0.0.3", 8006))
    except OSError:
        pytest.skip("port 8006 unavailable")
    srv.listen(64)
    d = discovery.Discovery()
    d.start(["127.0.0.0/29"], [], [])
    for _ in range(200):
        if not d.status()["running"]:
            break
        time.sleep(0.05)
    srv.close()
    st = d.status()
    assert st["error"] is None
    hit = next(r for r in st["results"] if r["ip"] == "127.0.0.3")
    assert 8006 in hit["ports"] and hit["kind"] == "hypervisor"


def test_topology_groups_hosts_by_subnet():
    t = build_topology(
        subnets=[{"name": "LAN", "cidr": "10.0.0.0/24", "gateway": "10.0.0.1"}],
        addresses=[{"ip": "10.0.0.1", "names": ["pfsense"]}, {"ip": "10.0.0.5", "names": []},
                   {"ip": "10.0.0.50", "names": ["web"]}, {"ip": "10.0.0.99", "names": []},
                   {"ip": "172.16.0.9", "names": ["odd"]}],
        devices=[{"id": 1, "name": "pfsense", "kind": "firewall", "ip": "10.0.0.1"},
                 {"id": 2, "name": "ups", "kind": "other", "ip": None}],
        device_status={1: {"up": True}},
        nodes=[{"node": "pve1", "ip": "10.0.0.5", "status": "online"}],
        guests=[{"vmid": 100, "name": "web", "type": "qemu", "node": "pve1", "status": "running",
                 "nics": [{"ip": "10.0.0.50"}], "live_ips": []}],
        pf_system={"hostname": "fw"}, gateways=[{"name": "WAN", "status": "online"}])
    lan = t["networks"][0]["hosts"]
    assert [h["label"] for h in lan] == ["pfsense", "pve1", "web", "unknown"]
    assert lan[0]["status"] == "up" and lan[1]["guests"][0]["label"] == "web"
    assert lan[2]["kind"] == "vm" and lan[3]["kind"] == "unknown"
    assert {h["label"] for h in t["other"]} == {"odd", "ups"}
    assert t["firewall"]["name"] == "fw"
