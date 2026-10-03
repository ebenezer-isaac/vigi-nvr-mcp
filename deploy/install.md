# Deploying vigi-nvr-mcp

A hardened, non-root systemd deployment on Linux (Ubuntu/Debian assumed). The
server binds to loopback and is reached over Tailscale or an SSH tunnel; it has
no authentication of its own, so it must **never** be exposed on the LAN.

## 1. Create a dedicated user

```sh
sudo useradd --system --home /var/lib/vigi-nvr-mcp --shell /usr/sbin/nologin viginvrmcp
sudo mkdir -p /var/lib/vigi-nvr-mcp
sudo chown viginvrmcp:viginvrmcp /var/lib/vigi-nvr-mcp
```

## 2. Install into a virtualenv

```sh
sudo mkdir -p /opt/vigi-nvr-mcp
sudo python3 -m venv /opt/vigi-nvr-mcp/.venv
sudo /opt/vigi-nvr-mcp/.venv/bin/pip install vigi-nvr-mcp
# ...or install from a checkout: pip install /path/to/vigi-nvr-mcp
```

`ffmpeg`/`ffprobe` are only needed for the media/export tools:

```sh
sudo apt-get install -y ffmpeg
```

## 3. Create the environment file (mode 0600)

Copy `.env.example` and fill in your NVR host and password. It holds secrets, so
it is owned by the service user and readable only by it.

```sh
sudo install -m 0600 -o viginvrmcp -g viginvrmcp .env.example /etc/vigi-nvr-mcp.env
sudoedit /etc/vigi-nvr-mcp.env     # set VIGI_NVR_HOST, VIGI_NVR_PASSWORD, etc.
```

Leave `VIGI_NVR_ALLOW_WRITES=false` unless you intend to allow writes. The unit
file sets `VIGI_NVR_STATE_DIR`, `VIGI_NVR_BACKUP_DIR` and `VIGI_NVR_EXPORT_DIR`
under the systemd-managed state directory, so you do not need to set them here.

## 4. Verify auth before enabling the service

Do this **before** the service starts making automated logins — a wrong password
burns the lockout budget.

```sh
sudo -u viginvrmcp VIGI_NVR_STATE_DIR=/var/lib/vigi-nvr-mcp/state \
  /opt/vigi-nvr-mcp/.venv/bin/vigi-nvr-mcp --env-file /etc/vigi-nvr-mcp.env --check-auth
# then, once, to confirm the password:
sudo -u viginvrmcp VIGI_NVR_STATE_DIR=/var/lib/vigi-nvr-mcp/state \
  /opt/vigi-nvr-mcp/.venv/bin/vigi-nvr-mcp --env-file /etc/vigi-nvr-mcp.env --check-auth --login
```

Expect `user_group: root` (or similar) on success. If the breaker ever trips,
clear it after fixing the password:

```sh
sudo -u viginvrmcp VIGI_NVR_STATE_DIR=/var/lib/vigi-nvr-mcp/state \
  /opt/vigi-nvr-mcp/.venv/bin/vigi-nvr-mcp breaker --env-file /etc/vigi-nvr-mcp.env --show
```

## 5. Install and enable the unit

```sh
sudo install -m 0644 deploy/vigi-nvr-mcp.service.example \
  /etc/systemd/system/vigi-nvr-mcp.service
# adjust ExecStart / paths in the unit if yours differ, then:
sudo systemctl daemon-reload
sudo systemctl enable --now vigi-nvr-mcp
sudo systemctl status vigi-nvr-mcp
```

The service listens on `http://127.0.0.1:8765/mcp`.

## 6. Reach it over Tailscale or SSH (never the LAN)

- **Tailscale:** install Tailscale on the server and on the client machine; reach
  the server at `http://<tailscale-ip>:8765/mcp`. Keep the systemd bind at
  `127.0.0.1` and let Tailscale's own ACLs gate access; do **not** change
  `VIGI_MCP_HOST` to a LAN or tailnet address unless you fully trust that network.
- **SSH tunnel:** `ssh -N -L 8765:127.0.0.1:8765 user@server`, then point the
  client at `http://127.0.0.1:8765/mcp`.

## 7. Logs

Logs go to stderr, captured by the journal:

```sh
journalctl -u vigi-nvr-mcp -f
```

Raise verbosity with `VIGI_MCP_LOG_LEVEL=DEBUG` in `/etc/vigi-nvr-mcp.env`.
Request bodies are never logged and session tokens are masked.

## 8. Upgrading

```sh
sudo /opt/vigi-nvr-mcp/.venv/bin/pip install --upgrade vigi-nvr-mcp
sudo systemctl restart vigi-nvr-mcp
sudo systemctl status vigi-nvr-mcp
```

Review [CHANGELOG.md](../CHANGELOG.md) before upgrading. Writable state
(breaker, backups, exports) persists under `/var/lib/vigi-nvr-mcp/`.
