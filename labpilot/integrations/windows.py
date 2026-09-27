"""Microsoft DHCP Server and DNS Server over WinRM (PowerShell).

Every value that goes into a PowerShell script is validated first and then
embedded as a single-quoted literal, so chat input can't inject commands.
"""

import ipaddress
import json
import re

import winrm

from .base import Integration, Observation, normalize_mac

HOSTNAME_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
ZONE_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


def ps_str(value: str) -> str:
    """Single-quoted PowerShell literal. Callers validate first; this is a second guard."""
    return "'" + str(value).replace("'", "''") + "'"


def valid_ipv4(ip: str) -> str:
    return str(ipaddress.IPv4Address(ip.strip()))


def valid_hostname(name: str) -> str:
    if not HOSTNAME_RE.match(name or ""):
        raise ValueError(f"invalid host name {name!r} (letters, digits and '-', max 63)")
    return name


def valid_mac_dashes(mac: str) -> str:
    norm = normalize_mac(mac)
    if not norm:
        raise ValueError(f"invalid MAC address {mac!r}")
    return norm.replace(":", "-")


def to_json(expr: str) -> str:
    return f"ConvertTo-Json -Depth 4 -Compress -InputObject @({expr})"


class WindowsDhcpDns(Integration):
    name = "windows"

    def __init__(self, settings):
        self.s = settings

    def configured(self) -> bool:
        return bool(self.s.windows_host and self.s.windows_user and self.s.windows_password)

    def _session(self) -> winrm.Session:
        scheme, port = ("https", 5986) if self.s.windows_use_https else ("http", 5985)
        return winrm.Session(
            f"{scheme}://{self.s.windows_host}:{port}/wsman",
            auth=(self.s.windows_user, self.s.windows_password),
            transport=self.s.windows_transport,
            server_cert_validation="validate" if self.s.windows_verify_ssl else "ignore",
        )

    def run(self, script: str):
        r = self._session().run_ps("$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; " + script)
        if r.status_code != 0:
            raise RuntimeError(r.std_err.decode(errors="replace")[:2000])
        out = r.std_out.decode(errors="replace").strip()
        return json.loads(out) if out else None

    def zone_or_error(self, zone: str) -> str:
        zone = zone.lower().strip(".")
        if not ZONE_RE.match(zone) or zone not in self.s.zones:
            raise ValueError(f"zone {zone!r} is not in DNS_ZONES ({', '.join(self.s.zones) or 'none set'})")
        return zone

    def collect(self) -> dict:
        scopes = self.run(to_json(
            "Get-DhcpServerv4Scope | Select-Object "
            "@{n='scope_id';e={$_.ScopeId.IPAddressToString}},"
            "@{n='mask';e={$_.SubnetMask.IPAddressToString}},"
            "@{n='start';e={$_.StartRange.IPAddressToString}},"
            "@{n='end';e={$_.EndRange.IPAddressToString}},"
            "Name,@{n='state';e={[string]$_.State}}"
        )) or []
        leases = self.run(to_json(
            "Get-DhcpServerv4Scope | Get-DhcpServerv4Lease | Select-Object "
            "@{n='ip';e={$_.IPAddress.IPAddressToString}},"
            "@{n='scope_id';e={$_.ScopeId.IPAddressToString}},"
            "@{n='mac';e={$_.ClientId}},HostName,"
            "@{n='state';e={[string]$_.AddressState}},"
            "@{n='expires';e={if($_.LeaseExpiryTime){$_.LeaseExpiryTime.ToString('o')}}}"
        )) or []
        reservations = self.run(to_json(
            "Get-DhcpServerv4Scope | Get-DhcpServerv4Reservation | Select-Object "
            "@{n='ip';e={$_.IPAddress.IPAddressToString}},"
            "@{n='scope_id';e={$_.ScopeId.IPAddressToString}},"
            "@{n='mac';e={$_.ClientId}},Name,Description"
        )) or []
        records = []
        for zone in self.s.zones:
            records += self.run(to_json(
                f"Get-DnsServerResourceRecord -ZoneName {ps_str(zone)} -RRType A | Select-Object "
                "HostName,@{n='ip';e={$_.RecordData.IPv4Address.IPAddressToString}},"
                f"@{{n='zone';e={{{ps_str(zone)}}}}},"
                "@{n='dynamic';e={[bool]$_.Timestamp}}"
            )) or []

        obs = []
        for l in leases:
            obs.append(Observation(l["ip"], "dhcp-lease", normalize_mac(l.get("mac")), l.get("HostName"), l.get("state", "")))
        for r in reservations:
            obs.append(Observation(r["ip"], "dhcp-reservation", normalize_mac(r.get("mac")), r.get("Name")))
        for rec in records:
            if rec.get("ip") and rec.get("HostName") != "@":
                obs.append(Observation(rec["ip"], "dns", None, f"{rec['HostName']}.{rec['zone']}", "dynamic" if rec.get("dynamic") else "static"))

        for s in scopes:
            s["cidr"] = str(ipaddress.IPv4Network(f"{s['scope_id']}/{s['mask']}", strict=False))
        return {
            "scopes": scopes,
            "leases": leases,
            "reservations": reservations,
            "dns_records": records,
            "observations": [o.to_dict() for o in obs],
        }

    # ---------- writes ----------

    def add_reservation(self, scope_id: str, ip: str, mac: str, name: str) -> None:
        self.run(
            f"Add-DhcpServerv4Reservation -ScopeId {ps_str(valid_ipv4(scope_id))} -IPAddress {ps_str(valid_ipv4(ip))} "
            f"-ClientId {ps_str(valid_mac_dashes(mac))} -Name {ps_str(valid_hostname(name))} -Description 'added by labpilot'"
        )

    def add_a_record(self, zone: str, name: str, ip: str, create_ptr: bool = True) -> None:
        ptr = " -CreatePtr" if create_ptr else ""
        self.run(
            f"Add-DnsServerResourceRecordA -ZoneName {ps_str(self.zone_or_error(zone))} "
            f"-Name {ps_str(valid_hostname(name))} -IPv4Address {ps_str(valid_ipv4(ip))}{ptr}"
        )

    def remove_a_record(self, zone: str, name: str, ip: str) -> None:
        self.run(
            f"Remove-DnsServerResourceRecord -ZoneName {ps_str(self.zone_or_error(zone))} -RRType A "
            f"-Name {ps_str(valid_hostname(name))} -RecordData {ps_str(valid_ipv4(ip))} -Force"
        )
