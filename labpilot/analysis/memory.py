"""Memory overcommit per node, failover headroom for the cluster, and "will it fit?" checks."""

GIB = 1024**3


def _status(ratio: float, warn: float, crit: float) -> str:
    return "critical" if ratio >= crit else "warning" if ratio >= warn else "ok"


def memory_report(nodes: list[dict], guests: list[dict], warn: float = 1.2, crit: float = 1.5) -> dict:
    rows = []
    for n in nodes:
        if not n.get("mem_total"):
            rows.append({"node": n["node"], "status": "offline"})
            continue
        mine = [g for g in guests if g["node"] == n["node"]]
        running = [g for g in mine if g["status"] == "running"]
        total = n["mem_total"]
        assigned_running = sum(g["maxmem"] for g in running)
        assigned_all = sum(g["maxmem"] for g in mine)
        balloon_floor = sum(g.get("balloon_min", g["maxmem"]) for g in running)
        guest_used = sum(g.get("mem", 0) for g in running)
        ratio = assigned_running / total
        rows.append({
            "node": n["node"],
            "total": total,
            "host_used": n["mem_used"],
            "host_used_pct": round(n["mem_used"] / total * 100, 1),
            "assigned_running": assigned_running,
            "assigned_all": assigned_all,
            "balloon_floor": balloon_floor,
            "guest_used": guest_used,
            "ksm_shared": n.get("ksm_shared", 0),
            "swap_used": n.get("swap_used", 0),
            "overcommit_ratio": round(ratio, 2),
            "overcommit_ratio_if_all_started": round(assigned_all / total, 2),
            "status": _status(ratio, warn, crit),
            "notes": _notes(n, running, ratio, total),
        })
    return {"nodes": rows, "failover": failover(rows), "thresholds": {"warn": warn, "crit": crit}}


def _notes(node: dict, running: list[dict], ratio: float, total: int) -> list[str]:
    notes = []
    if ratio > 1 and not any(g.get("ballooning") and g.get("balloon_min", 0) < g["maxmem"] for g in running):
        notes.append("Overcommitted but no VM has a balloon minimum below its maximum, so the host can't reclaim RAM.")
    if node.get("swap_used", 0) > 0.25 * max(node.get("swap_total", 0), 1) and node.get("swap_total"):
        notes.append("Host is using a lot of swap.")
    if node["mem_used"] / total > 0.9:
        notes.append("Host RAM above 90%. If it runs ZFS, part of this is ARC cache (see zfs_arc_max).")
    no_agent = [g["name"] for g in running if g["type"] == "qemu" and not g.get("agent_enabled")]
    if no_agent:
        notes.append(f"No guest agent on {len(no_agent)} VM(s), so their real usage and IPs are guesses.")
    return notes


def failover(rows: list[dict]) -> list[dict]:
    """For each node: if it went down, would its running guests fit on the others?"""
    online = [r for r in rows if r.get("total")]
    out = []
    for down in online:
        others = [r for r in online if r is not down]
        if not others:
            continue
        capacity = sum(r["total"] for r in others)
        need = sum(r["assigned_running"] for r in online)
        floor = sum(r["balloon_floor"] for r in online)
        out.append({
            "if_down": down["node"],
            "survivors": [r["node"] for r in others],
            "needed": need,
            "needed_with_ballooning": floor,
            "capacity": capacity,
            "ratio": round(need / capacity, 2),
            "fits": need <= capacity,
            "fits_with_ballooning": floor <= capacity,
        })
    return out


def can_fit(rows: list[dict], memory_bytes: int, warn: float = 1.2, crit: float = 1.5) -> list[dict]:
    out = []
    for r in rows:
        if not r.get("total"):
            continue
        new_ratio = (r["assigned_running"] + memory_bytes) / r["total"]
        out.append({"node": r["node"], "current_ratio": r["overcommit_ratio"],
                    "new_ratio": round(new_ratio, 2), "status": _status(new_ratio, warn, crit)})
    return sorted(out, key=lambda x: x["new_ratio"])
