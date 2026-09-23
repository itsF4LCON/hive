# hive

A low-interaction honeypot with a live attack map. A small Rust sensor pretends to be an SSH server and a
forgotten nginx box. Bots find it on their own. Every login attempt and web probe goes to a Cloudflare Worker,
and [xivlabs.tech](https://xivlabs.tech/#attacks) shows them on a world map as they happen.

```
 bots ──▶ :22 / :80 ──▶ hive-sensor (Rust, VM) ──1 signed request/min──▶ hive Worker (Rust/WASM) ──▶ D1
                        counts every event,        stats snapshot +                          1 snapshot row
                        hourly buckets on disk     10 newest events                          + newest 500 events
                                                                                ▲
                                                   xivlabs.tech ── GET /stats, /recent (cached 30s)
```

## Safety model

- **Nobody ever gets in.** Every SSH login is rejected, so there's no shell, channel or command execution.
  The HTTP side never reads request bodies and always returns the same static page.
- **Bounded:** at most 256 open connections (10 per IP), 30–60s session limits, capped string lengths,
  and an in-memory queue that drops the oldest events when it's full.
- **Sandboxed:** runs as an unprivileged `hive` user under systemd with a read-only filesystem, no new
  privileges and a syscall filter (`systemd-analyze security` exposure: 1.5). It gets
  `CAP_NET_BIND_SERVICE` only to bind ports 22 and 80.
- **Isolated:** runs on its own VM, not on a home network or a machine that holds anything else.
- **Privacy:** source IPs are masked to their network (`203.0.113.x`) inside the sensor, so full
  addresses never leave the VM. The public API only shows masked IPs and countries.

## Why the sensor does the counting

The Worker runs on Cloudflare's free plan, where D1 allows 100k rows written per day **across the whole
account**. A public port 22 can draw tens of thousands of attempts a day, so storing one row per attempt
would use that up, and break other projects sharing the account.

So the sensor counts every event in memory instead. It keeps hourly buckets for 7 days, saves them to
`stats.json` so restarts don't lose history, and caps distinct keys per bucket so memory stays bounded.
Once a minute it sends a single signed request with the stats snapshot and the 10 newest events. The Worker
upserts one snapshot row, inserts those events and prunes the feed back to 500 rows. That's at most about
21 rows written per minute (~30k a day) however hard the honeypot is hit. `/stats` reads one row and
`/recent` reads only the rows it returns, both behind a 30s edge cache.

## Layout

| Path | What |
|---|---|
| `sensor/` | The Rust honeypot: SSH (`russh`), HTTP (`hyper`), GeoLite2 lookups, signed shipping |
| `sensor/hive-sensor.service` | systemd unit |
| `worker/` | Cloudflare Worker (Rust): `POST /ingest`, `GET /stats`, `GET /recent` |
| `test/worker.sh` | Tests for the Worker's auth, validation, IP masking and CORS |

## API

| Endpoint | |
|---|---|
| `POST /ingest` | Sensor only. Body is `{sent_at, events[≤50], stats?}`, signed with `X-Hive-Signature: hex(HMAC-SHA256(secret, body))`. Requests more than 5 min off the Worker's clock are rejected. The snapshot is size-capped and cleaned before it's stored. |
| `GET /recent?limit=50` | Latest events (max 100) |
| `GET /stats` | The latest snapshot: 24h/7d totals, unique sources, top usernames, passwords, paths, countries and user agents, and map points |

The public endpoints are cached at the edge for 30s and only send CORS headers to origins in `ALLOWED_ORIGINS`.

## Setup

### 1. Worker

```bash
cd worker
wrangler d1 create hive-db             # put the id in wrangler.toml
wrangler d1 execute hive-db --remote --file=schema.sql
openssl rand -hex 32                    # the shared secret, keep it for the sensor too
wrangler secret put HIVE_SECRET
wrangler deploy                         # serves on hive.xivlabs.tech
```

### 2. VM (Oracle Cloud Always Free)

1. Create an **Ampere A1** VM (1 OCPU and 6 GB is plenty) running Ubuntu 24.04. Always Free allows
   4 OCPU and 24 GB in total, shared with any other VMs you already have.
2. In the VM's subnet **security list**, allow TCP 22 and 80 from `0.0.0.0/0`, and 2200 only from
   your own IP.
3. **Move your real SSH to port 2200 before anything else.** Oracle's Ubuntu images also firewall
   with iptables, so open the ports there too:
   ```bash
   for p in 22 80 2200; do sudo iptables -I INPUT 6 -p tcp --dport $p -m state --state NEW -j ACCEPT; done
   sudo netfilter-persistent save
   sudo sed -i 's/^#\?Port .*/Port 2200/' /etc/ssh/sshd_config
   sudo systemctl daemon-reload && sudo systemctl restart ssh.socket   # Ubuntu 24.04 starts sshd via this socket
   ```
   Check that `ssh -p 2200 ubuntu@<vm-ip>` works from a **second terminal** before you close the first.
   Then check that nothing is left on 22:
   ```bash
   sudo ss -tlnp | grep -E ':(22|2200)\b'    # expect sshd on 2200 only
   ```
   If sshd still shows on 22, the image runs `ssh.service` instead of the socket: run
   `sudo systemctl restart ssh` and check again.
4. `sudo apt install unattended-upgrades` so the VM patches itself.

### 3. Sensor

Download `hive-sensor-aarch64-unknown-linux-gnu` from the latest release, or build it on the VM with
`cargo build --release` in `sensor/`. Then:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin hive
sudo install -m 755 hive-sensor-aarch64-unknown-linux-gnu /usr/local/bin/hive-sensor
sudo install -d -m 750 -o root -g hive /etc/hive
sudo tee /etc/hive/env >/dev/null <<'ENV'
HIVE_INGEST_URL=https://hive.xivlabs.tech/ingest
HIVE_SECRET=<the secret from step 1>
HIVE_GEOIP_DB=/etc/hive/GeoLite2-City.mmdb
ENV
sudo chmod 640 /etc/hive/env && sudo chgrp hive /etc/hive/env
```

For locations on the map, create a free [MaxMind](https://www.maxmind.com/en/geolite2/signup) account,
download **GeoLite2-City** (`.mmdb`), and copy it to `/etc/hive/GeoLite2-City.mmdb`. Without it the
sensor still works, just without map points.

```bash
sudo cp hive-sensor.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now hive-sensor
journalctl -u hive-sensor -f
```

From your own machine, `ssh root@<vm-ip>` should show up in the journal right away, and on the map within about 2 minutes (one flush plus the 30s cache).

### Configuration

| Variable | Default | |
|---|---|---|
| `HIVE_INGEST_URL` | required | Worker ingest URL |
| `HIVE_SECRET` | required | Shared HMAC secret |
| `HIVE_SSH_ADDR` | `0.0.0.0:22` | |
| `HIVE_HTTP_ADDR` | `0.0.0.0:80` | |
| `HIVE_STATE_DIR` | `/var/lib/hive` | Holds the SSH host key and `stats.json` |
| `HIVE_GEOIP_DB` | unset | Path to GeoLite2-City `.mmdb` |

## Development

```bash
# Worker
cd worker && cp .dev.vars.example .dev.vars   # set HIVE_SECRET
wrangler d1 execute hive-db --local --file=schema.sql && wrangler dev
HIVE_SECRET=... ../test/worker.sh

# Sensor, on unprivileged ports
cd sensor && cargo test
HIVE_INGEST_URL=http://localhost:8787/ingest HIVE_SECRET=... \
HIVE_SSH_ADDR=127.0.0.1:2222 HIVE_HTTP_ADDR=127.0.0.1:8080 HIVE_STATE_DIR=/tmp/hive cargo run
```

This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com.
