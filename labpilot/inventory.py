"""Device inventory: the user's documented lab gear, with optional TCP port checks."""

import socket
import time
from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Address

from .integrations.base import Observation, normalize_mac

KINDS = ["server", "hypervisor", "vm", "container", "nas", "switch", "router", "firewall",
         "access point", "iot", "workstation", "printer", "other"]


def clean_device(d: dict) -> dict:
    """Validate and normalize a device from the UI or the assistant. Raises ValueError."""
    name = str(d.get("name") or "").strip()
    if not 1 <= len(name) <= 64:
        raise ValueError("name is required (max 64 characters)")
    kind = str(d.get("kind") or "other").strip().lower()
    if kind not in KINDS:
        raise ValueError(f"kind must be one of: {', '.join(KINDS)}")
    ip = str(d.get("ip") or "").strip()
    if ip:
        try:
            ip = str(IPv4Address(ip))
        except ValueError:
            raise ValueError(f"{ip!r} is not a valid IPv4 address")
    mac = str(d.get("mac") or "").strip()
    if mac:
        norm = normalize_mac(mac)
        if not norm:
            raise ValueError(f"{mac!r} is not a valid MAC address")
        mac = norm
    port = d.get("check_port")
    if port in (None, "", 0, "0"):
        port = None
    else:
        try:
            port = int(port)
        except (TypeError, ValueError):
            raise ValueError("check_port must be a number")
        if not 1 <= port <= 65535:
            raise ValueError("check_port must be between 1 and 65535")
        if not ip:
            raise ValueError("a port check needs an IP address")
    return {"name": name, "kind": kind, "ip": ip or None, "mac": mac or None,
            "role": str(d.get("role") or "").strip()[:120] or None,
            "location": str(d.get("location") or "").strip()[:120] or None,
            "check_port": port, "notes": str(d.get("notes") or "").strip()[:2000] or None}


def observations(devices: list[dict]) -> list[dict]:
    return [Observation(d["ip"], "inventory", d.get("mac"), d["name"], d.get("role") or d.get("kind") or "").to_dict()
            for d in devices if d.get("ip")]


def tcp_check(ip: str, port: int, timeout: float = 3.0) -> tuple[bool, str | None]:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True, None
    except OSError as e:
        return False, str(e) or type(e).__name__


def check_devices(devices: list[dict], previous: dict[int, dict]) -> dict[int, dict]:
    """TCP-check every device that has a check_port. `since` is when the current up/down state began."""
    targets = [d for d in devices if d.get("ip") and d.get("check_port")]
    if not targets:
        return {}
    with ThreadPoolExecutor(max_workers=min(16, len(targets))) as pool:
        results = list(pool.map(lambda d: tcp_check(d["ip"], d["check_port"]), targets))
    now, out = time.time(), {}
    for d, (up, err) in zip(targets, results):
        prev = previous.get(d["id"])
        since = prev["since"] if prev and prev["up"] == up else now
        out[d["id"]] = {"up": up, "error": err, "since": since, "checked": now}
    return out
