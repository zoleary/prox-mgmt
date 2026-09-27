from ipaddress import IPv4Network

from labpilot.analysis.ipam import build_inventory, build_subnets


def obs(ip, source, mac=None, name=None):
    return {"ip": ip, "source": source, "mac": mac, "name": name, "detail": ""}


SCOPES = [{"scope_id": "10.0.20.0", "mask": "255.255.255.0", "start": "10.0.20.100", "end": "10.0.20.200",
           "Name": "Servers", "state": "Active", "cidr": "10.0.20.0/24"}]
PF = [{"descr": "SERVERS", "ipaddr": "10.0.20.1", "subnet": "24"}, {"descr": "WAN", "ipaddr": "dhcp", "subnet": ""}]


def subnets():
    return build_subnets(SCOPES, {"Mgmt": IPv4Network("10.0.1.0/24")}, PF)


def types(inv):
    return {f["type"] for f in inv["findings"]}


def test_subnets_merge_dhcp_pfsense_and_extra():
    s = subnets()
    assert [str(x["network"]) for x in s] == ["10.0.1.0/24", "10.0.20.0/24"]
    servers = s[1]
    assert str(servers["gateway"]) == "10.0.20.1" and servers["pool"] is not None


def test_duplicate_ip_detected():
    inv = build_inventory([obs("10.0.20.10", "proxmox-config", "aa:aa:aa:aa:aa:aa", "web"),
                           obs("10.0.20.10", "pfsense-arp", "bb:bb:bb:bb:bb:bb")], subnets())
    assert "duplicate_ip" in types(inv)


def test_static_ip_in_dhcp_pool_without_reservation():
    inv = build_inventory([obs("10.0.20.150", "proxmox-config", "aa:aa:aa:aa:aa:aa", "db")], subnets())
    assert "static_in_dhcp_pool" in types(inv)
    inv = build_inventory([obs("10.0.20.150", "proxmox-config", "aa:aa:aa:aa:aa:aa", "db"),
                           obs("10.0.20.150", "dhcp-reservation", "aa:aa:aa:aa:aa:aa", "db")], subnets())
    assert "static_in_dhcp_pool" not in types(inv)


def test_stale_dns_and_unknown_subnet():
    inv = build_inventory([obs("10.0.20.20", "dns", name="old.lab.home"),
                           obs("192.168.99.5", "pfsense-arp", "cc:cc:cc:cc:cc:cc")], subnets())
    assert {"stale_dns", "unknown_subnet"} <= types(inv)


def test_next_free_skips_used_gateway_and_pool():
    inv = build_inventory([obs("10.0.20.2", "proxmox-config", "aa:aa:aa:aa:aa:aa", "a")], subnets())
    servers = next(s for s in inv["subnets"] if s["cidr"] == "10.0.20.0/24")
    assert servers["next_free"][:3] == ["10.0.20.3", "10.0.20.4", "10.0.20.5"]
    assert all(not (100 <= int(ip.rsplit(".", 1)[1]) <= 200) for ip in servers["next_free"])
