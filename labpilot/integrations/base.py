"""Common types shared by all integrations.

To add an integration: subclass Integration, implement `configured` and
`collect`, and register it in integrations/__init__.py. Anything returned in
`collect()["observations"]` feeds the IP inventory automatically.
"""

import re
from dataclasses import asdict, dataclass


@dataclass
class Observation:
    """One sighting of an IP address by one source."""

    ip: str
    source: str  # "proxmox-config", "proxmox-agent", "dhcp-lease", "dhcp-reservation", "dns", "pfsense-arp"
    mac: str | None = None
    name: str | None = None
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def normalize_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    hexdigits = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(hexdigits) != 12:
        return None
    return ":".join(hexdigits[i : i + 2] for i in range(0, 12, 2)).lower()


class Integration:
    name = "base"

    def configured(self) -> bool:
        raise NotImplementedError

    def collect(self) -> dict:
        """Return a dict of read-only data. Must not change anything."""
        raise NotImplementedError
