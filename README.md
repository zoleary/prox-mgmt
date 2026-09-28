# Lab Helper

A home lab dashboard and assistant. It connects to a Proxmox VE cluster, pfSense, and (optionally) Windows Server DHCP/DNS, keeps an inventory of the rest of your gear, then:

- **Shows the environment**: node CPU/RAM with 24-hour history, guests, quorum, WAN gateways, firewall interfaces, aliases and rules.
- **Tracks IP addresses** across every source (Proxmox config, guest agent, DHCP leases and reservations, DNS, pfSense ARP) and flags duplicate IPs, static IPs inside DHCP pools, stale DNS records, guests without DNS, and addresses outside any known subnet. It suggests free static IPs per VLAN.
- **Plans memory**: overcommit ratio per node, ballooning floors, KSM, swap, "will an 8 GiB VM fit?", and whether one node can carry everything if the other fails.
- **Chat assistant** (Claude) that answers from live data and can propose changes: start/stop/reboot guests, change memory, take snapshots, add DHCP reservations, add or remove DNS records, add addresses to pfSense aliases, and enable or disable pfSense firewall rules and IPsec tunnels.
- **Device inventory**: document your NAS, switches, access points and other gear (IP, MAC, role, location, notes). Inventory IPs join the IP list, and any device can get a TCP port check.
- **Health alerts**: node down, lost quorum, high host RAM, integration errors, gateway problems, IPsec tunnels down, devices failing their port check, and duplicate IPs. Shown on the Overview with a badge in the header.
- **Lab assistant tab**: step-by-step help with Proxmox, pfSense, Docker, networking, backups, remote access and more, using your real lab data. Quick-task buttons for common jobs.
- **Control buttons**: start, shut down, reboot or stop guests on the Guests tab, and enable or disable firewall rules and IPsec tunnels on the Firewall tab.

**Nothing changes until you approve it.** The assistant only queues proposals. Each one appears in the chat and on the Changes tab with Approve / Reject buttons. Dashboard buttons ask you to confirm first. Every change is logged on the Changes tab.

## Quick start

```bash
cp .env.example .env      # fill in the values below
docker compose up -d      # or: docker compose up -d --build
```

Open `http://<host>:8080` and log in with `ADMIN_USER` / `ADMIN_PASSWORD`. Integrations you leave blank are skipped.

## Running it on Proxmox

Docker runs best in a small VM (1–2 vCPU, 1 GiB RAM). To use an LXC container instead, create an unprivileged Debian 12 container with **Options → Features → nesting and keyctl** enabled, then install Docker in it:

```bash
apt update && apt install -y curl && curl -fsSL https://get.docker.com | sh
mkdir -p /opt/labpilot && cd /opt/labpilot
curl -O https://raw.githubusercontent.com/zoleary/prox-mgmt/main/docker-compose.yml
curl -o .env https://raw.githubusercontent.com/zoleary/prox-mgmt/main/.env.example   # then edit .env
docker compose up -d
```

Put the container on your management VLAN so it can reach Proxmox, pfSense and the Windows server.

## Setting up each integration

### Proxmox VE

Create a user and token (on either node; the cluster shares them):

```bash
pveum user add labpilot@pve
pveum user token add labpilot@pve dashboard --privsep 0   # copy the secret into PVE_TOKEN_SECRET
```

Read-only (dashboard and chat questions only):

```bash
pveum acl modify / --users labpilot@pve --roles PVEAuditor
```

To let approved changes run (power, memory, snapshots) and read IPs from the guest agent, add a custom role:

```bash
# Proxmox VE 9:
pveum role add LabPilot --privs "VM.PowerMgmt VM.Config.Memory VM.Snapshot VM.GuestAgent.Audit"
# Proxmox VE 8:
pveum role add LabPilot --privs "VM.PowerMgmt VM.Config.Memory VM.Snapshot VM.Monitor"

pveum acl modify /vms --users labpilot@pve --roles LabPilot
```

Install `qemu-guest-agent` in your VMs and enable **Options → QEMU Guest Agent**. Without it Lab Helper only knows static cloud-init IPs for VMs.

### pfSense

Lab Helper uses the [pfSense REST API package](https://github.com/jaredhendrickson13/pfsense-api) (v2). It isn't in the built-in package manager. Install it from the pfSense shell following that project's install instructions for your pfSense version. Then go to **System → REST API**, enable API key authentication, and create a key under **Keys**. Give it a user with read access, plus: alias edit and firewall apply for alias changes; firewall rule edit and firewall apply to enable/disable rules; IPsec phase 1 edit and IPsec apply to enable/disable tunnels.

### Windows Server DHCP and DNS

Lab Helper runs PowerShell on the server over WinRM.

1. Create a service account, for example `LAB\svc-labpilot`, and add it to **DHCP Administrators** and **DnsAdmins** (use **DHCP Users** only for read-only).
2. Enable WinRM over HTTPS on the DHCP/DNS server:
   ```powershell
   $cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My
   New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force
   New-NetFirewallRule -DisplayName "WinRM HTTPS" -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow
   ```
3. Allow the account to use WinRM (add it to **Remote Management Users**).
4. Set `DNS_ZONES` to the zones Lab Helper may read and change. It refuses to touch any other zone.

### Chat assistant

Create an API key at [console.anthropic.com](https://console.anthropic.com) and set `ANTHROPIC_API_KEY`. The default model is `claude-opus-5`. `CLAUDE_FALLBACKS=true` turns on server-side refusal fallback: if the model declines a request, the API retries it on a fallback model. Set it to `false` if your account or proxy rejects that option.

Things to try:

- "Which node has the most memory headroom?"
- "I need a new 8 GB VM for Home Assistant on VLAN 20. Where should it go and what IP should it get?"
- "Add a DNS record for grafana pointing at 10.0.20.31"
- "Are there any IP conflicts?"

## Security notes

- The UI uses HTTP basic auth. Keep it on your LAN or put it behind a reverse proxy with TLS (Caddy, Nginx Proxy Manager, Traefik).
- Secrets live only in `.env`, which is git-ignored. Don't commit it.
- Every value from the chat is validated before it's queued. DHCP and DNS values are checked as IPs, MACs and host names and passed to PowerShell as quoted literals.
- Grant only the Proxmox, pfSense and Windows permissions for the actions you want.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
ADMIN_PASSWORD=dev DATA_DIR=./data uvicorn labpilot.main:app --reload --port 8080
```

### Adding an integration

1. Create `labpilot/integrations/<name>.py` with a subclass of `Integration` that implements `configured()` and `collect()`.
2. Return any IPs it sees as `Observation`s in `collect()["observations"]`. They show up in the IP inventory and conflict checks automatically.
3. Register it in `labpilot/integrations/__init__.py`.
4. For chat access, add a read tool in `labpilot/chat.py`. For changes, add a `prepare`/`execute` pair in `labpilot/actions.py`.

Integrations worth adding next: Proxmox Backup Server (backup age per guest), UniFi or other switches (port and MAC tables), Uptime Kuma, Home Assistant, and ZFS pool health.

## Publishing the image

`.github/workflows/docker.yml` runs the tests and pushes `ghcr.io/zoleary/prox-mgmt` for amd64 and arm64 on every push to `main` and on `v*` tags. If the package is private, make it public in the package settings or run `docker login ghcr.io` on the host first.
