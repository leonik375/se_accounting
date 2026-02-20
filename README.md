# se-radius — SoftEther VPN to RADIUS Accounting Bridge

Daemon that polls the SoftEther VPN JSON-RPC API and sends RADIUS accounting packets (Start / Interim-Update / Stop) to a FreeRADIUS server. This lets you use standard RADIUS tooling for session tracking, traffic accounting, and billing.

## Features

- Sends RFC 2866 accounting packets: **Start**, **Interim-Update**, **Stop**
- Multi-hub support — list specific hubs or leave empty to auto-scan all hubs
- Tracks per-session byte counters with Gigaword support (>4 GB)
- Skips system sessions (SecureNAT, Local Bridge)
- Graceful shutdown — sends Stop packets for all active sessions on SIGTERM/SIGINT
- SQLite state DB survives daemon restarts
- Dry-run mode for testing without sending RADIUS packets

## Requirements

- Python 3.10+(with installed pyrad and httpx)
- SoftEther VPN Server with JSON-RPC API enabled (HTTPS)
- FreeRADIUS (or any RADIUS server accepting accounting)

## Installation

```bash
# Clone / copy files to /opt/se-radius
sudo mkdir -p /opt/se-radius
sudo cp se_radius_accounting.py /opt/se-radius/
sudo chmod +x /opt/se-radius/se_radius_accounting.py

# Install Python dependencies
sudo pip install pyrad httpx

# Create state directory
sudo mkdir -p /var/lib/se-radius
```

## Configuration

Edit the constants at the top of `se_radius_accounting.py`:

```python
SE_HOST       = "https://localhost:443"   # SoftEther API endpoint
SE_PASSWORD   = "admin_pass"              # SoftEther admin password
SE_HUBS       = ["MAIN"]                   # Hub names, or [] to auto-scan all hubs

RADIUS_HOST   = "127.0.0.1"
RADIUS_PORT   = 1813
RADIUS_SECRET = b"radius_secret"
NAS_IP        = "127.0.0.1"              # NAS-IP-Address sent in RADIUS packets

POLL_INTERVAL = 300                       # seconds between polls
STATE_DB      = "/var/lib/se-radius/state.db"
```

### Hub modes

| `SE_HUBS` value   | Behavior |
|-------------------|---|
| `["MAIN", "DEV"]` | Poll only the listed hubs |
| `[]`              | Auto-discover all hubs via `EnumHub` each poll cycle |

Each hub is identified in RADIUS packets via `Calling-Station-Id` as `SE/<hub>` (e.g. `SE/TLP`).

## Systemd service

```bash
# Install the service file
sudo cp se-radius-acc.service /etc/systemd/system/

# Reload, enable, and start
sudo systemctl daemon-reload
sudo systemctl enable se-radius-acc.service
sudo systemctl start se-radius-acc.service

# Check status and logs
sudo systemctl status se-radius-acc.service
sudo journalctl -u se-radius-acc.service -f
```

## Running manually

```bash
# Normal run
python3 se_radius_accounting.py

# Dry run — logs what would be sent, no actual RADIUS packets
python3 se_radius_accounting.py --dry-run

# Debug HTTP — logs every SoftEther API call as a curl command
python3 se_radius_accounting.py --debug-http

# Both flags can be combined
python3 se_radius_accounting.py --dry-run --debug-http
```

## RADIUS attributes sent

| Attribute | Value |
|---|---|
| `User-Name` | SoftEther username |
| `Acct-Session-Id` | `<session_name>@<created_time>` |
| `Calling-Station-Id` | `SE/<hub>` |
| `NAS-IP-Address` | Configured `NAS_IP` |
| `Framed-IP-Address` | Client VPN IP |
| `Acct-Session-Time` | Duration in seconds (from `CreatedTime_dt`) |
| `Acct-Input-Octets` / `Acct-Input-Gigawords` | Bytes received |
| `Acct-Output-Octets` / `Acct-Output-Gigawords` | Bytes sent |
| `Acct-Terminate-Cause` | `Lost-Carrier` (disconnect) or `Admin-Reset` (daemon shutdown) |

## How it works

1. Each poll cycle, the daemon resolves the hub list (configured or auto-scanned)
2. For each hub, it calls `EnumSession` to get active sessions
3. For each session, it calls `GetSessionStatus` for byte counters
4. New sessions get a **Start** packet; known sessions with traffic changes get an **Interim-Update**
5. Sessions that disappeared since the last poll get a **Stop** packet with `Lost-Carrier`
6. On daemon shutdown (SIGTERM/SIGINT), all tracked sessions get a **Stop** with `Admin-Reset`
7. Session state is persisted in SQLite so restarts don't lose tracking
