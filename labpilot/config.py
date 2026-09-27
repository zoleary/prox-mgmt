"""Settings, read from environment variables (or a .env file)."""

from functools import lru_cache
from ipaddress import IPv4Network

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Web UI
    admin_user: str = "admin"
    admin_password: str = ""
    data_dir: str = "/data"
    poll_seconds: int = 60

    # Proxmox VE (API token, e.g. PVE_TOKEN_ID=labpilot@pve!dashboard)
    pve_host: str = ""
    pve_port: int = 8006
    pve_token_id: str = ""
    pve_token_secret: str = ""
    pve_verify_ssl: bool = False

    # pfSense (pfSense-pkg-RESTAPI v2)
    pfsense_url: str = ""
    pfsense_api_key: str = ""
    pfsense_verify_ssl: bool = False

    # Windows Server DHCP + DNS over WinRM
    windows_host: str = ""
    windows_user: str = ""
    windows_password: str = ""
    windows_transport: str = "ntlm"
    windows_use_https: bool = True
    windows_verify_ssl: bool = False
    dns_zones: str = ""  # comma separated, e.g. "lab.home,home.arpa"

    # Extra subnets not covered by DHCP scopes: "Servers=10.0.10.0/24,Mgmt=10.0.1.0/24"
    extra_subnets: str = ""

    # Memory overcommit thresholds (assigned RAM of running guests / physical RAM)
    mem_warn_ratio: float = 1.2
    mem_crit_ratio: float = 1.5

    # Chat assistant
    anthropic_api_key: str = ""
    claude_model: str = "claude-opus-5"
    claude_fallbacks: bool = True

    @property
    def zones(self) -> list[str]:
        return [z.strip().lower() for z in self.dns_zones.split(",") if z.strip()]

    @property
    def subnets(self) -> dict[str, IPv4Network]:
        out: dict[str, IPv4Network] = {}
        for item in self.extra_subnets.split(","):
            if "=" in item:
                name, cidr = item.split("=", 1)
                out[name.strip()] = IPv4Network(cidr.strip(), strict=False)
        return out


@lru_cache
def get_settings() -> Settings:
    return Settings()
