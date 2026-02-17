# Honeypot

A lightweight honeypot for Raspberry Pi (or any Linux host) that passively monitors
your local network and alerts on suspicious activity.

---

## What It Does

| Service | Port | Behaviour |
|---------|------|-----------|
| **Fake SSH** | 22 | Accepts connections, logs every username/password attempt, always rejects auth |
| **Fake HTTP** | 80 | Serves a realistic Apache 2 Debian default page, logs all requests + user-agents |
| **Trap ports** | many | Canary listeners — any IP that probes 3+ distinct ports within 30 s triggers a `port_scan` alert |

All events are written as newline-delimited JSON to a log file.
High-priority events (`ssh_attempt`, `port_scan`) can optionally POST to a Slack/Discord webhook.

---

## Requirements

- Python 3.10+
- `paramiko` — SSH server implementation
- `requests` — webhook delivery

```bash
pip3 install paramiko requests
```

---

## Setup

### 1. Move your real SSH daemon off port 22

The honeypot needs port 22. Edit `/etc/ssh/sshd_config` and change the port:

```bash
sudo nano /etc/ssh/sshd_config
# Change:  Port 22
# To:      Port 2222
sudo systemctl restart sshd
```

Reconnect going forward with `ssh -p 2222 user@host`.

---

### 2. Configure

Edit `config.json` — all fields are optional (defaults shown):

| Key | Default | Description |
|-----|---------|-------------|
| `ssh_port` | `22` | Port for the fake SSH server |
| `http_port` | `80` | Port for the fake HTTP server |
| `trap_ports` | see file | Canary ports used for scan detection |
| `scan_threshold_ports` | `3` | Distinct ports an IP must hit to trigger an alert |
| `scan_threshold_seconds` | `30` | Sliding window for scan detection |
| `log_file` | `honeypot.json` | JSON log path (relative to the script) |
| `webhook_url` | `""` | Slack/Discord webhook URL (blank = disabled) |
| `webhook_events` | `["port_scan","ssh_attempt"]` | Which event types fire the webhook |
| `ssh_banner` | `SSH-2.0-OpenSSH_8.4p1 ...` | Version string advertised to SSH clients |
| `max_ssh_session_seconds` | `30` | How long to hold a fake SSH session open |

---

### 3. Run manually

Ports below 1024 require root (or the `CAP_NET_BIND_SERVICE` capability):

```bash
sudo python3 honeypot.py
```

Expected startup output:

```
============================================================
  Honeypot starting
  Log  : /opt/honeypot/honeypot.json
  Slack: configured
============================================================
[ssh]  Generating RSA host key -> /opt/honeypot/host_key.pem
[ssh]  Listening on port 22
[http] Listening on port 80
[trap] Bound port 21
[trap] Bound port 23
...
```

---

### 4. Run as a systemd service (recommended)

```bash
# Copy files to install location
sudo mkdir -p /opt/honeypot
sudo cp honeypot.py config.json /opt/honeypot/

# Install and enable
sudo cp honeypot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now honeypot

# Check it is running
sudo systemctl status honeypot

# Follow live output
sudo journalctl -u honeypot -f

# Or tail the JSON log directly
tail -f /opt/honeypot/honeypot.json | python3 -m json.tool
```

---

## Log Format

One JSON object per line in `honeypot.json`:

```json
{"timestamp": "2025-01-15T03:12:44+00:00", "type": "ssh_attempt",   "src_ip": "10.0.0.55", "src_port": 51234, "auth_type": "password", "username": "admin", "password": "admin123"}
{"timestamp": "2025-01-15T03:12:50+00:00", "type": "port_scan",     "src_ip": "10.0.0.55", "ports_probed": [21, 23, 443], "distinct_ports": 3, "window_seconds": 30}
{"timestamp": "2025-01-15T03:12:55+00:00", "type": "trap_port_hit", "src_ip": "10.0.0.55", "src_port": 60001, "dst_port": 3389}
{"timestamp": "2025-01-15T03:13:01+00:00", "type": "http_request",  "src_ip": "10.0.0.55", "src_port": 61000, "method": "GET", "path": "/wp-admin", "user_agent": "Nmap Scripting Engine"}
```

### Event Types

| Type | Webhook | Description |
|------|---------|-------------|
| `ssh_attempt` | Yes | SSH login attempt — username and password (or public key fingerprint) recorded |
| `port_scan` | Yes | An IP crossed the trap-port threshold |
| `trap_port_hit` | No | A single canary port was touched (log only) |
| `http_request` | No | Any HTTP request received (log only) |

---

## Slack / Discord Webhook

### Slack

1. Go to **Slack → Apps → Incoming Webhooks → Add to Slack**
2. Pick a channel and copy the webhook URL
3. Paste it into `config.json` as `webhook_url`

### Discord

1. In a channel: **Edit Channel → Integrations → Webhooks → New Webhook**
2. Copy the webhook URL and append `/slack` to it:
   ```
   https://discord.com/api/webhooks/123/abc/slack
   ```
3. Paste that into `config.json` as `webhook_url`

---

## Trap Ports Reference

| Port | Protocol | Why it is suspicious |
|------|----------|----------------------|
| 21 | FTP | Legacy, rarely legitimate |
| 23 | Telnet | Unencrypted; common IoT malware target |
| 25 | SMTP | Mail relay probing |
| 53 | DNS | Open resolver scanning |
| 110 | POP3 | Mail credential harvesting |
| 143 | IMAP | Mail credential harvesting |
| 443 | HTTPS | General scanner (TCP-only, no TLS) |
| 445 | SMB | Ransomware / worm propagation |
| 3306 | MySQL | Database exposure scanning |
| 3389 | RDP | Windows remote desktop attacks |
| 5900 | VNC | Remote desktop scanning |
| 8080 | HTTP-alt | Proxy / web app scanning |
| 8443 | HTTPS-alt | Proxy / web app scanning |

---

## Notes

- **SSH auth is always rejected** — this is not a real login system.
- The RSA host key (`host_key.pem`) is generated on first run and reused on subsequent starts. Keep this file — losing it causes SSH clients to warn about a host-key change.
- Port 443 is a TCP-only trap (no TLS). Scanners see a connection open then close, which is sufficient for detection.
- Lower `scan_threshold_ports` to `2` on quiet networks for higher sensitivity.
