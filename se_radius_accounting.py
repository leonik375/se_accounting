#!/home/leonik/projects/se-radius/.venv/bin/python3
"""
SoftEther VPN → FreeRADIUS Accounting Daemon
Polls SoftEther JSON-RPC API and sends RADIUS accounting packets.

Requirements:
    pip install pyrad httpx

Usage:
    python3 se_radius_accounting.py
    or as a service: see se_radius_accounting.service
"""

import argparse
import io
import logging
import os
import signal
import sqlite3
import time
import json

from datetime import datetime, timezone
from typing import Optional

import httpx
from pyrad.client import Client
from pyrad.dictionary import Dictionary

# ─── Configuration ────────────────────────────────────────────────────────────

SE_HOST         = "https://localhost:443"
SE_PASSWORD     = "admin_pass"
SE_HUBS         = []   # list of hub names, or [] to auto-scan all hubs

RADIUS_HOST     = "127.0.0.1"
RADIUS_PORT     = 1813
RADIUS_SECRET   = b"radius_secret"
NAS_IP          = "127.0.0.1"   # IP of this VPN server as seen by RADIUS

POLL_INTERVAL   = 60       # seconds between polls
STATE_DB        = "/var/lib/se-radius/state.db"
DRY_RUN         = False     # overridden by --dry-run flag
DEBUG_HTTP      = False     # overridden by --debug-http flag

STOP_ON_SHUTDOWN = False

LOG_LEVEL       = logging.INFO
LOG_FORMAT      = "%(asctime)s [%(levelname)s] %(message)s"

# Sessions to always ignore regardless of flags
IGNORED_USERS   = {"SecureNAT", "Local Bridge"}

# Minimal RFC 2866 dictionary — used as fallback when RADIUS_DICT is unreadable.
# Without this, every req["Attr-Name"] = ... would raise KeyError silently.
_MINIMAL_DICT = """\
ATTRIBUTE User-Name              1  string
ATTRIBUTE NAS-IP-Address         4  ipaddr
ATTRIBUTE Framed-IP-Address      8  ipaddr
ATTRIBUTE Called-Station-Id     30  string
ATTRIBUTE Calling-Station-Id    31  string
ATTRIBUTE NAS-Identifier        32  string
ATTRIBUTE Acct-Status-Type      40  integer
ATTRIBUTE Acct-Delay-Time       41  integer
ATTRIBUTE Acct-Input-Octets     42  integer
ATTRIBUTE Acct-Output-Octets    43  integer
ATTRIBUTE Acct-Session-Id       44  string
ATTRIBUTE Acct-Session-Time     46  integer
ATTRIBUTE Acct-Terminate-Cause  49  integer
ATTRIBUTE Acct-Input-Gigawords  52  integer
ATTRIBUTE Acct-Output-Gigawords 53  integer
VALUE Acct-Status-Type  Start           1
VALUE Acct-Status-Type  Stop            2
VALUE Acct-Status-Type  Interim-Update  3
VALUE Acct-Terminate-Cause  User-Request  1
VALUE Acct-Terminate-Cause  Lost-Carrier  2
VALUE Acct-Terminate-Cause  Admin-Reset   6
"""

# ─── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT)
log = logging.getLogger("se-radius")

# ─── Globals ──────────────────────────────────────────────────────────────────

running = True

# ─── SoftEther API ────────────────────────────────────────────────────────────

SE_HEADERS = {
    "X-VPNADMIN-HUBNAME": "",           # empty = full server admin
    "X-VPNADMIN-PASSWORD": SE_PASSWORD,
    "Content-Type": "application/json",
}



def _log_as_curl(url: str, headers: dict, payload: dict) -> None:
    """Log the outgoing request as an equivalent curl command."""
    import json as _json
    header_args = " ".join(f"-H '{k}: {v}'" for k, v in headers.items())
    body = _json.dumps(payload, separators=(",", ":"))
    log.debug("[HTTP] curl -k -s -X POST '%s' %s -d '%s'", url, header_args, body)


def _log_response(r: httpx.Response) -> None:
    """Log the HTTP response status and body."""
    try:
        body = r.json()
    except Exception:
        body = r.text
    log.debug("[HTTP] <- %d %s  body=%s", r.status_code, r.reason_phrase, body)


def se_api(method: str, params: Optional[dict] = None) -> Optional[dict]:
    """
    Call SoftEther VPN HTTPS RPC API.

    This version enforces HTTP/1.1, uses the exact headers SoftEther expects,
    disables SSL verification for self-signed certs, and encodes JSON payload
    manually to match SoftEther requirements.
    """
    url = f"{SE_HOST}/api/"

    payload = {
        "jsonrpc": "2.0",
        "id": "1",
        "method": method,
        "params": params or {},
    }

    headers = {
        # SoftEther requires this password header for RPC
        "X-VPNADMIN-PASSWORD": SE_HEADERS.get("X-VPNADMIN-PASSWORD", ""),
        "Content-Type": "application/json",
        "Accept": "*/*",
        "Accept-Encoding": "identity",
        "Connection": "Keep-Alive",
    }

    try:
        if DEBUG_HTTP:
            # Optional: log the request as a curl command
            curl_cmd = (
                f"curl -k -X POST {url} "
                + " ".join(f"-H '{k}: {v}'" for k, v in headers.items())
                + f" -d '{json.dumps(payload)}'"
            )
            log.info("[HTTP] -> %s", curl_cmd)

        # HTTP/1.1 enforced by http2=False, SSL defaults by verify=False
        with httpx.Client(verify=False, http2=False, timeout=10) as client:
            r = client.post(url, headers=headers, content=json.dumps(payload).encode())

        if DEBUG_HTTP:
            _log_response(r)

        data = r.json()
        if "error" in data:
            log.error("SE API error [%s]: %s", method, data["error"])
            return None

        return data.get("result")

    except Exception as e:
        log.error("SE API request failed [%s]: %s", method, e)
        return None


def get_hubs() -> Optional[list[str]]:
    """Return list of hub names from SoftEther, or None on API error."""
    result = se_api("EnumHub")
    if result is None:
        return None
    return [h["HubName_str"] for h in result.get("HubList", [])]


def resolve_hubs() -> Optional[list[str]]:
    """Return the configured hub list, or auto-discover all hubs if empty."""
    if SE_HUBS:
        return list(SE_HUBS)
    hubs = get_hubs()
    if hubs is None:
        log.error("EnumHub failed, cannot auto-discover hubs")
        return None
    log.debug("Auto-discovered hubs: %s", hubs)
    return hubs


def get_active_sessions(hub: str) -> Optional[list]:
    """Return list of real user sessions (filtered), or None on API error."""
    result = se_api("EnumSession", {"HubName_str": hub})
    if result is None:
        return None

    sessions = []
    for s in result.get("SessionList", []):
        # Skip system sessions
        if s.get("SecureNATMode_bool") or s.get("BridgeMode_bool"):
            continue
        if s.get("Username_str") in IGNORED_USERS:
            continue
        sessions.append(s)
    return sessions


def get_session_detail(hub: str, session_name: str) -> Optional[dict]:
    """Get detailed stats for a single session."""
    return se_api("GetSessionStatus", {
        "HubName_str": hub,
        "Name_str": session_name,
    })

# ─── State DB ─────────────────────────────────────────────────────────────────

def _db_key(hub: str, session_name: str) -> str:
    """Build a unique DB key: hub/session_name."""
    return f"{hub}/{session_name}"


def init_db(path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_name    TEXT PRIMARY KEY,
            username        TEXT,
            client_ip       TEXT,
            start_time      TEXT,
            last_recv       INTEGER DEFAULT 0,
            last_send       INTEGER DEFAULT 0,
            acct_started    INTEGER DEFAULT 0,
            hub             TEXT DEFAULT ''
        )
    """)
    conn.commit()
    return conn


def db_get_session(conn: sqlite3.Connection, name: str) -> Optional[dict]:
    cur = conn.execute(
        "SELECT session_name,username,client_ip,start_time,last_recv,last_send,acct_started,hub "
        "FROM sessions WHERE session_name=?", (name,)
    )
    row = cur.fetchone()
    if not row:
        return None
    return dict(zip([d[0] for d in cur.description], row))



def db_delete_session(conn: sqlite3.Connection, name: str):
    conn.execute("DELETE FROM sessions WHERE session_name = ?", (name,))
    conn.commit()


def db_all_session_names(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT session_name FROM sessions").fetchall()
    return {r[0] for r in rows}

# ─── RADIUS ───────────────────────────────────────────────────────────────────

def make_radius_client() -> Client:
    d = Dictionary()
    d.ReadDictionary(io.StringIO(_MINIMAL_DICT))

    client = Client(
        server=RADIUS_HOST,
        acctport=RADIUS_PORT,
        secret=RADIUS_SECRET,
        dict=d,
    )
    client.timeout = 5
    client.retries = 2
    return client


def send_accounting(radius: Client, status_type: str, session: dict,
                     recv_bytes: int, send_bytes: int, session_time: int,
                     terminate_cause: Optional[str] = None):
    """Send a RADIUS Accounting-Request packet."""
    hub = session.get("hub", "")
    st_id = f"SE/{hub}" if hub else "softether-vpn"
    try:
        req = radius.CreateAcctPacket()
        req.AddAttribute("Acct-Status-Type", status_type)
        req.AddAttribute("Acct-Session-Id", f"{session['session_name']}@{session['start_time']}")
        req.AddAttribute("User-Name", session["username"])
        req.AddAttribute("NAS-IP-Address", NAS_IP)
        req.AddAttribute("Called-Station-Id", st_id)
        if session.get("client_product"):
            req.AddAttribute("Calling-Station-Id", session["client_product"])
        req.AddAttribute("Framed-IP-Address", session["client_ip"])
        req.AddAttribute("Acct-Input-Octets", send_bytes & 0xFFFFFFFF)
        req.AddAttribute("Acct-Output-Octets", recv_bytes & 0xFFFFFFFF)
        if recv_bytes >> 32:
            req.AddAttribute("Acct-Input-Gigawords", send_bytes >> 32)
        if send_bytes >> 32:
            req.AddAttribute("Acct-Output-Gigawords", recv_bytes >> 32)
        req.AddAttribute("Acct-Session-Time", session_time)
        if terminate_cause:
            req.AddAttribute("Acct-Terminate-Cause", terminate_cause)

        if DRY_RUN:
            log.info(
                "[DRY-RUN] RADIUS %-15s | %-15s | hub=%-10s | session=%s | in=%d out=%d time=%ds",
                status_type, session["username"], hub, session["session_name"],
                recv_bytes, send_bytes, session_time,
            )
            return
        reply = radius.SendPacket(req)
        log.debug("RADIUS reply code: %s", reply.code)
        log.info(
            "RADIUS %-15s | %-15s | hub=%-10s | session=%s | in=%d out=%d time=%ds",
            status_type, session["username"], hub, session["session_name"],
            recv_bytes, send_bytes, session_time,
        )
    except Exception as e:
        log.error("RADIUS send failed (%s for %s): %s", status_type, session["username"], e)

# ─── Helpers ──────────────────────────────────────────────────────────────────

def parse_dt(value) -> datetime:
    """Parse SoftEther datetime: ISO8601 string or Unix-ms integer."""
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value / 1000, tz=timezone.utc)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def session_duration(start_time) -> int:
    """Return session duration in seconds from start_time."""
    start = parse_dt(start_time)
    now = datetime.now(timezone.utc)
    return max(0, int((now - start).total_seconds()))

# ─── Main Loop ────────────────────────────────────────────────────────────────

def poll(conn: sqlite3.Connection, radius: Client):
    log.debug("Polling SoftEther sessions...")

    hubs = resolve_hubs()
    if hubs is None:
        log.error("Could not resolve hubs, skipping poll cycle")
        return

    # Collect all active DB keys across all hubs
    all_active_keys: set[str] = set()

    for hub in hubs:
        active_sessions = get_active_sessions(hub)
        if active_sessions is None:
            # API error — do NOT treat this hub's sessions as gone
            log.error("EnumSession failed for hub %s, skipping", hub)
            continue

        active_keys = {_db_key(hub, s["Name_str"]) for s in active_sessions}
        all_active_keys.update(active_keys)

        # ── Handle active sessions ────────────────────────────────────────
        for s in active_sessions:
            name       = s["Name_str"]
            username   = s["Username_str"]
            client_ip  = s["Ip_ip"]
            start_time = s["CreatedTime_dt"]
            key        = _db_key(hub, name)

            # Get detailed byte counters
            detail = get_session_detail(hub, name)
            if not detail:
                log.warning("Could not get detail for session %s on hub %s, skipping", name, hub)
                continue

            recv_bytes     = detail.get("TotalRecvSize_u64", 0)
            send_bytes     = detail.get("TotalSendSize_u64", 0)
            client_product = detail.get("ClientProductName_str", "")
            duration       = session_duration(start_time)

            state = db_get_session(conn, key)

            session_info = {
                "session_name": name,
                "username": username,
                "client_ip": client_ip,
                "start_time": start_time,
                "hub": hub,
                "client_product": client_product,
            }

            if not state:
                # New session — send Start
                send_accounting(radius, "Start", session_info, 0, 0, 0)
                conn.execute(
                    "INSERT INTO sessions (session_name,username,client_ip,start_time,last_recv,last_send,acct_started,hub) "
                    "VALUES (?,?,?,?,?,?,1,?)",
                    (key, username, client_ip, start_time, recv_bytes, send_bytes, hub),
                )
            else:
                # Skip Interim-Update when no traffic since last poll
                if recv_bytes == state["last_recv"] and send_bytes == state["last_send"]:
                    log.debug("No traffic change for %s on hub %s, skipping Interim-Update", name, hub)
                    continue
                send_accounting(radius, "Interim-Update", session_info,
                                recv_bytes, send_bytes, duration)
                conn.execute(
                    "UPDATE sessions SET last_recv=?,last_send=? WHERE session_name=?",
                    (recv_bytes, send_bytes, key),
                )

    # ── Handle disconnected sessions (send Stop) ─────────────────────────
    known_keys = db_all_session_names(conn)
    for gone_key in known_keys - all_active_keys:
        state = db_get_session(conn, gone_key)
        if state and state["acct_started"]:
            # Reconstruct session_info from DB for the Stop packet
            # The DB key is hub/session_name — extract the original session name
            hub = state.get("hub", "")
            original_name = gone_key.split("/", 1)[1] if "/" in gone_key else gone_key
            stop_info = {
                "session_name": original_name,
                "username": state["username"],
                "client_ip": state["client_ip"],
                "start_time": state["start_time"],
                "hub": hub,
            }
            duration = session_duration(state["start_time"])
            send_accounting(
                radius, "Stop", stop_info,
                state["last_recv"], state["last_send"], duration,
                terminate_cause="Lost-Carrier",
            )
        conn.execute("DELETE FROM sessions WHERE session_name=?", (gone_key,))
        log.info("Session ended: %s", gone_key)

    # Single commit for the entire poll cycle instead of one per session
    conn.commit()


def handle_signal(sig, frame):
    global running
    log.info("Signal %s received, shutting down...", sig)
    running = False


def main():
    global running, DRY_RUN, DEBUG_HTTP

    parser = argparse.ArgumentParser(description="SoftEther → RADIUS Accounting Daemon")
    parser.add_argument("--dry-run", action="store_true",
                        help="Poll SoftEther and log what would be sent, but send no RADIUS packets")
    parser.add_argument("--debug-http", action="store_true",
                        help="Print every SoftEther API request as a curl command and log the response")
    args = parser.parse_args()
    DRY_RUN    = args.dry_run
    DEBUG_HTTP = args.debug_http

    flags = [f for f, v in [("DRY-RUN", DRY_RUN), ("DEBUG-HTTP", DEBUG_HTTP)] if v]
    log.info("SoftEther → RADIUS Accounting Daemon starting%s",
             f" [{', '.join(flags)}]" if flags else "")
    hub_label = ", ".join(SE_HUBS) if SE_HUBS else "(auto-scan)"
    log.info("SE Hubs: %s | RADIUS: %s:%d | Poll: %ds",
             hub_label, RADIUS_HOST, RADIUS_PORT, POLL_INTERVAL)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    conn   = init_db(STATE_DB)
    radius = make_radius_client()

    while running:
        cycle_start = time.monotonic()
        try:
            poll(conn, radius)
        except Exception as e:
            log.error("Poll cycle failed: %s", e, exc_info=True)

        # Sleep for the remainder of the interval, waking every second to
        # check the running flag so signals are handled promptly.
        elapsed  = time.monotonic() - cycle_start
        deadline = time.monotonic() + max(0.0, POLL_INTERVAL - elapsed)
        while running:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(1.0, remaining))

    # On shutdown — send Stop for all known sessions
    if STOP_ON_SHUTDOWN:
        log.info("Sending final Stop packets for all active sessions...")
        for key in db_all_session_names(conn):
            try:
                state = db_get_session(conn, key)
                if state and state["acct_started"]:
                    hub = state.get("hub", "")
                    original_name = key.split("/", 1)[1] if "/" in key else key
                    stop_info = {
                        "session_name": original_name,
                        "username": state["username"],
                        "client_ip": state["client_ip"],
                        "start_time": state["start_time"],
                        "hub": hub,
                    }
                    duration = session_duration(state["start_time"])
                    send_accounting(
                        radius, "Stop", stop_info,
                        state["last_recv"], state["last_send"], duration,
                        terminate_cause="Admin-Reset",
                    )
            except Exception as e:
                log.error("Error sending Stop for %s: %s", key, e)
            finally:
                db_delete_session(conn, key)

    conn.close()
    log.info("Daemon stopped.")


if __name__ == "__main__":
    main()
