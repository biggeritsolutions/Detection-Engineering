#!/usr/bin/env python3
"""
honeypot.py - Raspberry Pi / Linux Honeypot
  - Fake SSH server  (port 22)  -- captures credentials, always rejects
  - Fake HTTP server (port 80)  -- serves a fake Apache default page
  - Trap port listeners          -- detects port scans via canary ports
  - Alerting: JSON log file + Slack/generic webhook
"""

import asyncio
import json
import socket
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import paramiko
import requests

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CONFIG_FILE = Path(__file__).parent / "config.json"
DEFAULT_CONFIG = {
    "ssh_port": 22,
    "http_port": 80,
    "trap_ports": [21, 23, 25, 53, 110, 143, 443, 445, 3306, 3389, 5900, 8080, 8443],
    "scan_threshold_ports": 3,
    "scan_threshold_seconds": 30,
    "log_file": "honeypot.json",
    "webhook_url": "",
    "webhook_events": ["port_scan", "ssh_attempt"],
    "ssh_banner": "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1",
    "http_server_header": "Apache/2.4.54 (Debian)",
    "host_key_file": "host_key.pem",
    "max_ssh_session_seconds": 30,
}


def load_config():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return {**DEFAULT_CONFIG, **json.load(f)}
    return DEFAULT_CONFIG.copy()


CONFIG = load_config()

# ---------------------------------------------------------------------------
# Logging / Alerting
# ---------------------------------------------------------------------------

_log_path = Path(__file__).parent / CONFIG["log_file"]
_log_fh = open(_log_path, "a", buffering=1)


def emit_event(event_type, data, webhook=True):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": event_type,
        **data,
    }
    line = json.dumps(event)
    print(line, flush=True)
    _log_fh.write(line + "\n")
    if webhook and CONFIG.get("webhook_url") and event_type in CONFIG["webhook_events"]:
        _send_webhook(event_type, event)


def _send_webhook(event_type, event):
    emoji = {
        "port_scan":     ":warning:",
        "ssh_attempt":   ":closed_lock_with_key:",
        "http_request":  ":globe_with_meridians:",
        "trap_port_hit": ":fishing_pole_and_fish:",
    }.get(event_type, ":bell:")
    text = (
        f"{emoji} *Honeypot -- {event_type.replace('_', ' ').title()}*\n"
        f"```{json.dumps(event, indent=2)}```"
    )
    try:
        requests.post(CONFIG["webhook_url"], json={"text": text}, timeout=5)
    except Exception as exc:
        print(f"[webhook] send failed: {exc}", flush=True)


# ---------------------------------------------------------------------------
# Port Scan Detector
# ---------------------------------------------------------------------------

class ScanDetector:
    def __init__(self):
        self._hits = defaultdict(list)   # ip -> [(monotonic_ts, port)]
        self._alerted = {}               # ip -> last alert monotonic time
        self._lock = threading.Lock()

    def record_hit(self, ip, port):
        now = time.monotonic()
        window = CONFIG["scan_threshold_seconds"]
        threshold = CONFIG["scan_threshold_ports"]
        with self._lock:
            self._hits[ip] = [
                (ts, p) for ts, p in self._hits[ip] if now - ts < window
            ]
            self._hits[ip].append((now, port))
            ports_seen = {p for _, p in self._hits[ip]}
            if len(ports_seen) >= threshold:
                last_alert = self._alerted.get(ip, 0)
                if now - last_alert >= window:
                    self._alerted[ip] = now
                    emit_event("port_scan", {
                        "src_ip": ip,
                        "ports_probed": sorted(ports_seen),
                        "distinct_ports": len(ports_seen),
                        "window_seconds": window,
                    })


_scan_detector = ScanDetector()


# ---------------------------------------------------------------------------
# Fake SSH Server
# ---------------------------------------------------------------------------

class _HoneypotSSHInterface(paramiko.ServerInterface):
    def __init__(self, src_ip, src_port):
        self.src_ip = src_ip
        self.src_port = src_port

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, term, width, height, pw, ph, modes):
        return True

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_auth_password(self, username, password):
        emit_event("ssh_attempt", {
            "src_ip": self.src_ip, "src_port": self.src_port,
            "auth_type": "password", "username": username, "password": password,
        })
        time.sleep(1.5)  # Slows brute-force tools
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        emit_event("ssh_attempt", {
            "src_ip": self.src_ip, "src_port": self.src_port,
            "auth_type": "publickey", "username": username,
            "key_type": key.get_name(),
            "key_fingerprint": key.get_fingerprint().hex(),
        })
        return paramiko.AUTH_FAILED


def _get_or_create_host_key():
    key_path = Path(__file__).parent / CONFIG["host_key_file"]
    if key_path.exists():
        return paramiko.RSAKey(filename=str(key_path))
    print(f"[ssh] Generating RSA host key -> {key_path}", flush=True)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(key_path))
    return key


def _handle_ssh_client(conn, addr, host_key):
    src_ip, src_port = addr[0], addr[1]
    transport = None
    try:
        transport = paramiko.Transport(conn)
        transport.add_server_key(host_key)
        transport.local_version = CONFIG["ssh_banner"]
        iface = _HoneypotSSHInterface(src_ip, src_port)
        transport.start_server(server=iface)
        deadline = time.monotonic() + CONFIG["max_ssh_session_seconds"]
        while time.monotonic() < deadline:
            if not transport.is_active():
                break
            time.sleep(1)
    except (paramiko.SSHException, EOFError, ConnectionResetError, OSError):
        pass
    except Exception as exc:
        print(f"[ssh] Unexpected error from {src_ip}: {exc}", flush=True)
    finally:
        if transport:
            transport.close()
        try:
            conn.close()
        except OSError:
            pass


def run_ssh_server():
    host_key = _get_or_create_host_key()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", CONFIG["ssh_port"]))
    sock.listen(64)
    print(f"[ssh] Listening on port {CONFIG['ssh_port']}", flush=True)
    while True:
        try:
            conn, addr = sock.accept()
        except OSError:
            break
        threading.Thread(
            target=_handle_ssh_client, args=(conn, addr, host_key), daemon=True
        ).start()


# ---------------------------------------------------------------------------
# Fake HTTP Server
# ---------------------------------------------------------------------------

_APACHE_HTML = """\
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Apache2 Debian Default Page: It works</title>
 </head>
 <body>
  <h1>It works!</h1>
  <p>This is the default welcome page used to test the correct operation of
  the Apache2 server after installation on Debian systems. If you can read
  this page, it means that the Apache2 web server installed at this site is
  working properly. You should <b>replace this file</b> (located at
  <tt>/var/www/html/index.html</tt>) before continuing to operate your
  HTTP server.</p>
  <hr>
  <address>Apache/2.4.54 (Debian) Server at {host} Port 80</address>
 </body>
</html>
"""


class _FakeHTTPHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.54"
    sys_version = "(Debian)"

    def _serve(self):
        body = _APACHE_HTML.format(host=self.headers.get("Host", "localhost")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        self._log_http()
        self._serve()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode(errors="replace") if length else ""
        self._log_http(post_body=body)
        self._serve()

    def do_HEAD(self):
        self._log_http()
        self._serve()

    def _log_http(self, post_body=""):
        data = {
            "src_ip": self.client_address[0], "src_port": self.client_address[1],
            "method": self.command, "path": self.path,
            "user_agent": self.headers.get("User-Agent", ""),
            "host": self.headers.get("Host", ""),
        }
        if post_body:
            data["post_body"] = post_body
        emit_event("http_request", data, webhook=False)

    def log_message(self, fmt, *args):
        pass


def run_http_server():
    class _ThreadedHTTP(HTTPServer):
        def __init__(self, *a, **kw):
            self.daemon_threads = True
            super().__init__(*a, **kw)
        def handle_error(self, request, client_address):
            pass

    srv = _ThreadedHTTP(("", CONFIG["http_port"]), _FakeHTTPHandler)
    print(f"[http] Listening on port {CONFIG['http_port']}", flush=True)
    srv.serve_forever()


# ---------------------------------------------------------------------------
# Trap Port Listeners (port scan canaries)
# ---------------------------------------------------------------------------

async def _trap_handler(reader, writer, port):
    addr = writer.get_extra_info("peername")
    src_ip   = addr[0] if addr else "unknown"
    src_port = addr[1] if addr else 0
    emit_event("trap_port_hit", {
        "src_ip": src_ip, "src_port": src_port, "dst_port": port,
    }, webhook=False)
    _scan_detector.record_hit(src_ip, port)
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass


async def _run_trap_servers():
    skip = {CONFIG["ssh_port"], CONFIG["http_port"]}
    bound = []
    for port in CONFIG["trap_ports"]:
        if port in skip:
            continue
        try:
            srv = await asyncio.start_server(
                lambda r, w, p=port: _trap_handler(r, w, p),
                host="", port=port,
            )
            bound.append(srv)
            print(f"[trap] Bound port {port}", flush=True)
        except OSError as exc:
            print(f"[trap] Could not bind port {port}: {exc}", flush=True)
    if bound:
        await asyncio.gather(*(s.serve_forever() for s in bound))
    else:
        print("[trap] No trap ports bound -- check permissions.", flush=True)


def _run_asyncio_loop():
    asyncio.run(_run_trap_servers())


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def main():
    print("=" * 60, flush=True)
    print("  Honeypot starting", flush=True)
    print(f"  Log  : {_log_path}", flush=True)
    print(f"  Slack: {'configured' if CONFIG.get('webhook_url') else 'not set'}", flush=True)
    print("=" * 60, flush=True)

    threads = [
        threading.Thread(target=run_ssh_server,    name="ssh",  daemon=True),
        threading.Thread(target=run_http_server,   name="http", daemon=True),
        threading.Thread(target=_run_asyncio_loop, name="trap", daemon=True),
    ]
    for t in threads:
        t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[main] Shutting down.", flush=True)


if __name__ == "__main__":
    main()
