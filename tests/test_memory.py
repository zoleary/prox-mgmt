from labpilot.analysis.memory import GIB, can_fit, memory_report

NODES = [
    {"node": "pve1", "mem_total": 64 * GIB, "mem_used": 40 * GIB, "swap_total": 8 * GIB, "swap_used": 0},
    {"node": "pve2", "mem_total": 32 * GIB, "mem_used": 20 * GIB, "swap_total": 8 * GIB, "swap_used": 0},
]


def guest(vmid, node, maxmem_gib, status="running", balloon_min_gib=None, kind="qemu"):
    return {"vmid": vmid, "name": f"g{vmid}", "type": kind, "node": node, "status": status,
            "maxmem": maxmem_gib * GIB, "mem": maxmem_gib * GIB // 2,
            "balloon_min": (balloon_min_gib or maxmem_gib) * GIB,
            "ballooning": balloon_min_gib is not None, "agent_enabled": True}


def test_ratio_and_status():
    guests = [guest(100, "pve1", 48), guest(101, "pve1", 32), guest(102, "pve1", 16, status="stopped"),
              guest(200, "pve2", 16)]
    r = {n["node"]: n for n in memory_report(NODES, guests)["nodes"]}
    assert r["pve1"]["overcommit_ratio"] == 1.25 and r["pve1"]["status"] == "warning"
    assert r["pve1"]["overcommit_ratio_if_all_started"] == 1.5
    assert r["pve2"]["status"] == "ok"
    assert any("can't reclaim" in n for n in r["pve1"]["notes"])


def test_failover_two_nodes():
    guests = [guest(100, "pve1", 40, balloon_min_gib=16), guest(200, "pve2", 16)]
    f = {x["if_down"]: x for x in memory_report(NODES, guests)["failover"]}
    # pve1 dies: 56 GiB must fit into pve2's 32 GiB -> no, but with balloon floors (32) it does
    assert not f["pve1"]["fits"] and f["pve1"]["fits_with_ballooning"]
    assert f["pve2"]["fits"]


def test_can_fit_sorted_by_headroom():
    guests = [guest(100, "pve1", 60), guest(200, "pve2", 8)]
    rows = memory_report(NODES, guests)["nodes"]
    fit = can_fit(rows, 8 * GIB)
    assert fit[0]["node"] == "pve2" and fit[0]["new_ratio"] == 0.5
