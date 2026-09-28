"""pfSense firewall via the pfSense-pkg-RESTAPI package (v2 API).

Install the package on pfSense (System > Package Manager doesn't list it; see
README) and create an API key under System > REST API > Keys.
"""

import httpx

from .base import Integration, Observation, normalize_mac


def ipsec_tunnels(phase1s: list[dict], sas: list[dict]) -> list[dict]:
    """IPsec phase 1 entries with their live state. strongSwan names phase 1 N "conN"."""
    state = {sa.get("con_id"): sa.get("state") for sa in sas}
    return [{"ikeid": p.get("ikeid"), "descr": p.get("descr"), "remote_gateway": p.get("remote_gateway"),
             "disabled": bool(p.get("disabled")), "state": state.get(f"con{p.get('ikeid')}") or "down"}
            for p in phase1s]


class PfSense(Integration):
    name = "pfsense"

    def __init__(self, settings):
        self.s = settings

    def configured(self) -> bool:
        return bool(self.s.pfsense_url and self.s.pfsense_api_key)

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.s.pfsense_url.rstrip("/") + "/api/v2",
            headers={"X-API-Key": self.s.pfsense_api_key},
            verify=self.s.pfsense_verify_ssl,
            timeout=15,
        )

    @staticmethod
    def _data(resp: httpx.Response):
        resp.raise_for_status()
        return resp.json().get("data")

    def _get(self, c: httpx.Client, path: str, **params):
        try:
            return self._data(c.get(path, params=params or None))
        except httpx.HTTPError:
            return None

    def collect(self) -> dict:
        with self._client() as c:
            system = self._data(c.get("/status/system"))  # fail loudly if the API is unreachable
            interfaces = self._get(c, "/status/interfaces") or []
            gateways = self._get(c, "/status/gateways") or []
            arp = self._get(c, "/diagnostics/arp_table") or []
            aliases = self._get(c, "/firewall/aliases") or []
            rules = self._get(c, "/firewall/rules") or []
            vlans = self._get(c, "/interface/vlans") or []
            phase1s = self._get(c, "/vpn/ipsec/phase1s") or []
            sas = self._get(c, "/status/ipsec/sas") or []

        observations = []
        for e in arp:
            ip = e.get("ip_address") or e.get("ip")
            if ip:
                observations.append(
                    Observation(ip, "pfsense-arp", normalize_mac(e.get("mac_address") or e.get("mac")),
                                e.get("hostname") if e.get("hostname") not in (None, "?") else None,
                                e.get("interface", "")).to_dict()
                )
        return {
            "system": system,
            "interfaces": interfaces,
            "gateways": gateways,
            "vlans": vlans,
            "aliases": [{"name": a.get("name"), "type": a.get("type"), "address": a.get("address"), "descr": a.get("descr")} for a in aliases],
            "rules": [
                {k: r.get(k) for k in ("tracker", "interface", "type", "protocol", "source", "destination", "destination_port", "descr", "disabled")}
                for r in rules
            ],
            "tunnels": ipsec_tunnels(phase1s, sas),
            "observations": observations,
        }

    # ---------- writes ----------

    def add_to_alias(self, alias_name: str, address: str) -> dict:
        with self._client() as c:
            aliases = self._data(c.get("/firewall/aliases", params={"name": alias_name})) or []
            alias = next((a for a in aliases if a.get("name") == alias_name), None)
            if alias is None:
                raise ValueError(f"alias {alias_name!r} not found")
            addresses = list(alias.get("address") or [])
            if address in addresses:
                return {"changed": False}
            details = list(alias.get("detail") or [""] * len(addresses))
            self._data(c.patch("/firewall/alias", json={
                "id": alias["id"],
                "address": addresses + [address],
                "detail": details + ["added by labpilot"],
            }))
            self._data(c.post("/firewall/apply"))
        return {"changed": True}

    def _toggle(self, list_path: str, item_path: str, apply_path: str, key: str, value, disabled: bool) -> dict:
        """Look the item up fresh (the API's ids are array positions and shift), then flip `disabled` and apply."""
        with self._client() as c:
            items = self._data(c.get(list_path)) or []
            item = next((i for i in items if str(i.get(key)) == str(value)), None)
            if item is None:
                raise ValueError(f"no item with {key}={value} on pfSense")
            if bool(item.get("disabled")) == disabled:
                return {"changed": False}
            self._data(c.patch(item_path, json={"id": item["id"], "disabled": disabled}))
            self._data(c.post(apply_path))
        return {"changed": True}

    def set_rule_disabled(self, tracker, disabled: bool) -> dict:
        return self._toggle("/firewall/rules", "/firewall/rule", "/firewall/apply", "tracker", tracker, disabled)

    def set_tunnel_disabled(self, ikeid, disabled: bool) -> dict:
        return self._toggle("/vpn/ipsec/phase1s", "/vpn/ipsec/phase1", "/vpn/ipsec/apply", "ikeid", ikeid, disabled)
