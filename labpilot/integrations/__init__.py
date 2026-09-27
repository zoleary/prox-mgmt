from .pfsense import PfSense
from .proxmox import Proxmox
from .windows import WindowsDhcpDns

INTEGRATION_CLASSES = [Proxmox, PfSense, WindowsDhcpDns]


def build_integrations(settings) -> dict:
    return {cls.name: cls(settings) for cls in INTEGRATION_CLASSES}
