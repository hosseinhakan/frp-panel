# FRP Tunnel Suite

Production-grade tunnel & FRP management: bash CLI (`frp-manager`), Go web
panel (`frp-panel`), GRE reverse-tunnel manager, kernel turbo tuning, live
monitoring, backup and watchdog — all operating on the **same** config paths
(`/root/frp/server|client/*.toml`, `/root/frp/gre/*.env`) and the same
systemd units, so CLI and Web UI never drift.

> Architecture & roadmap: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
> · release history: [CHANGELOG.md](CHANGELOG.md)
>
> **راهنمای فارسی (Persian guide): [docs/FA.md](docs/FA.md)** — تانل چیست، چطور
> راه بیندازیم، و عیب‌یابی.

## Quickstart

Install the web panel on a fresh Ubuntu 22.04/24.04 or Debian 12 VPS
(root):

```sh
curl -fsSL https://raw.githubusercontent.com/hosseinhakan/frp-panel/main/scripts/install.sh | bash
```

The installer detects the architecture, downloads the release tarball,
installs `/usr/local/bin/frp-panel` (the whole dashboard is embedded in the
single binary — no CDN, no Node), writes the systemd unit from inside the
binary (`frp-panel install-unit`) and enables `frp-panel.service`.
Flags: `--port 9000 --bind ADDR --version v1.2.7 --base URL`. The panel binds
`0.0.0.0` (all interfaces) by default and the installer opens the port in UFW
when it is available; pass `--bind 127.0.0.1` for loopback-only access.

First start prints a **one-time admin password** to the console:

```sh
journalctl -u frp-panel --no-pager | grep -i password | head -n1
```

Open `http://<public-ip>:9000` (or `http://<tunnel-ip>:9000` when bound to a GRE
address), sign in, set a real password, and you are on the dashboard.

The bash CLI installs alongside from the same repo:

```sh
sudo bash frp-setup.sh   # self-installs as /usr/local/bin/frp-manager
```

## The Iran ↔ Foreign topology (reverse FRP over GRE)

Two VPSes, one GRE tunnel, and FRP control traffic that never touches the
public internet. **Iran is the entry/bridge; Foreign is the exit/backend.**

```
 User ──► Iran Public IP:port ──► frps (Iran, 10.100.111.2) ──► GRE (gt11) ──► frpc (Foreign, 10.100.111.1) ──► Foreign 127.0.0.1:port
```

| Node | Role | GRE `gt11` | FRP process | Public listener |
|---|---|---|---|---|
| **Iran** | entry / bridge | `10.100.111.2/30` | `frps` bound to `10.100.111.2:7025` | forwarded service ports only |
| **Foreign** | exit / backend | `10.100.111.1/30` | `frpc` dials `10.100.111.2:7025` | none — it dials out over GRE |

`frps` listens only on the tunnel IP, so the FRP control port is invisible to
the public internet. Users reach the Foreign services on the **Iran public
IP**, at the same forwarded port.

### One-step setup (recommended)

1. **Iran (entry)** — Dashboard → *FRP over GRE Reverse — Quick Setup* →
   **Iran Node**. The form is pre-filled with the next free interface,
   `/30` subnet and control port (`gt11` / `10.100.111.0/30` / `7025` on a
   fresh host). The wizard creates:
   - a GRE tunnel with the selected `/30` (`…2/30 ↔ …1/30`), MTU `1320`,
     `txqueuelen 1000`, `NOTRACK` for proto 47 and TCPMSS clamping (local SYN
     MSS pinned to `1220` so PMTUD black holes cannot stall the control
     channel), plus a persisted zero-drop `sysctl.d` profile (BBR + fq, 16 MB
     buffers, deep backlogs, `rp_filter=0`, `tcp_mtu_probing`, `nf_conntrack`);
     every field is editable from the GRE row after creation;
   - a 32-char token (or your own custom token) and an `frps` instance bound to
     the tunnel IP by default — `::` and `0.0.0.0` are selectable in the form —
     while `proxyBindAddr` keeps the forwarded user ports public; then enables
     both units;
   - the dual-layer auto-heal watchdog (`frp-watchdog`, 15s interval, 3 strikes,
     60s cooldown) — untick the wizard toggle to opt out.

   If the requested interface, subnet or port is already busy, the wizard
   allocates the next free one (`gt12`, `10.100.112.0/30`, `7026`) and reports
   the switch in the result banner, so one Iran server can drive several
   Foreign nodes.

   Copy the generated **mirror payload** (or the equivalent CLI command), or
   skip the wizard on the Foreign host entirely and use the **Foreign Setup**
   block in the result (also available on every frps row). It only needs root
   SSH on the Foreign server and accepts a port list with ranges
   (`8989,8443,6000-6005`) plus an optional GRE `/30` (blank = auto-allocate
   the next free `gtNN` / `10.100.NN.0/30`).
2. **Foreign (exit)** — either paste the generated one-click Bash block, or run
   the same wizard on the Foreign node, choose **Foreign Node**, paste the
   payload, and enter a comma-separated local port list
   (`8989,8443,6000-6005`) plus the TCP / TCP+UDP selector. Either path creates
   the mirrored GRE tunnel (`…1/30 ↔ …2/30`; a busy local `gtNN` is renamed
   without touching the mirrored `/30`) and an `frpc` instance. Generated
   configs use the proven `mikeesierrah` profile: `tls.enable = false`,
   per-proxy `useEncryption = false`, compression off, compact
   `parseNumberRangePair` port templates, `dial 10s / keepalive 30s / pool 15`
   and `heartbeat 15s / timeout 45s`. It then pings the Iran tunnel IP and
   reports the frpc unit state, and allocates the loopback metrics `webServer`
   port the watchdog uses for proxy health.
3. Point users/DNS at **`Iran Public IP:<forwarded port>`** (for example
   `1.2.3.4:443`).

### Telegram alerts (optional)

`frp-watchdog` can notify a Telegram chat on every heal event (layer, unit,
reason, consecutive failures, result). Configure it in **Watchdog → Telegram
alerts** (token, chat ID, optional API base) and press **Send test alert**, or
from the CLI:

```sh
frp-manager watchdog telegram --token '123456:ABC…' --chat -1001234567890
frp-manager watchdog test-telegram
# Iran servers where Telegram is blocked: point at a Worker reverse proxy
frp-manager watchdog telegram --api-base https://tg.example.workers.dev
```

The bot token is masked in API responses and redacted in secret-free backups.
Delivery runs in a background `curl --max-time 5` and can never stall the heal
loop.

The same flow exists in the CLI: `frp-manager` → **14) FRP over GRE Reverse
(Quick Setup)**, or non-interactively:

```sh
# Iran entry node (prints the mirror payload/command)
frp-manager reverse iran --iran-public 1.2.3.4 --foreign-public 5.6.7.8

# Foreign exit node (paste the payload, add the ports it exposes)
frp-manager reverse foreign --payload /root/mirror.env \
  --ports 8443,2053,443 --proto both
```

Manual configuration (separate GRE + server + client screens) still works and
writes exactly the same files; the wizard just does all three at once.

Single-node usage works the same way — skip GRE and bind frps to `::`
(dual-stack).

### Config profile and maintenance

Generated configs follow the proven `mikeesierrah/frp-script` profile with
stability-tuned timers: frps `heartbeatTimeout=45`, `tcpKeepalive=30`,
`maxPoolCount=65535`, `tcpMux=false`, and `proxyBindAddr=0.0.0.0` whenever
`bindAddr` is a GRE IP; frpc `tls.enable=false`, per-proxy
encryption/compression off, `dial 10/30`, `poolCount=15`, `heartbeat 15/45`,
and compact `parseNumberRangePair` port templates. The Edit modal exposes every
one of these fields (plus the QUIC block) and keeps both template and plain
`[[proxies]]` configs editable.

The **Turbo** tab adds three one-click maintenance actions (also
`frp-manager turbo …`):

| Action | API | CLI |
|---|---|---|
| FRP auto-GC cron (`0 */3 * * * pkill -10 -x frpc; pkill -10 -x frps`) | `POST /api/system/turbo {"action":"gc-cron"}` | `frp-manager turbo gc-cron` |
| Volatile logs (`Storage=volatile`, 50M/5M, rsyslog off) | `{"action":"volatile-logs"}` | `frp-manager turbo volatile-logs` |
| Clear all system logs (journal + `/var/log` + wtmp/btmp) | `{"action":"clear-logs"}` | `frp-manager turbo clear-logs` |

## Layout

| Path | Contents |
|---|---|
| `frp-setup.sh` | the CLI (self-installs as `/usr/local/bin/frp-manager`) |
| `panel/` | Go backend + embedded web UI (`frp-panel`, port 9000) |
| `panel/web/` | Alpine.js + HTMX dashboard (100% vendored, go:embed) |
| `panel/internal/assets/` | canonical systemd units + helper scripts |
| `scripts/install.sh` | the one-line curl installer |
| `scripts/build-release.sh` | cross-compile + package release tarballs |
| `scripts/vendor-web.sh` | pinned fetcher for the vendored JS libs |
| `scripts/check-sync.sh` | CI guard: bash heredocs == embedded assets |

## Status

- [x] P0 — scaffolding (Go module, embedded assets, health API, build scripts)
- [x] P1 — `frpconf` config engine (TOML model, range parser, token gen, golden tests)
- [x] P2 — CLI upgrade (auto token, bindAddr choice, dual TCP+UDP, GRE manager, turbo, panel install, backup, watchdog)
- [x] P3 — panel core (`panel.toml` bootstrap, bcrypt+JWT cookie auth with rate-limited login, servers/clients CRUD with `frps/frpc verify` gate + `.bak` backups, systemctl wrapper, `reset-password` command)
- [x] P4 — GRE API (CLI-byte-identical `.env` model, mirror-config, `/30` subnet allocator, link test, embedded-asset install)
- [x] P5 — turbo API (`GET/POST /api/system/turbo`: BBR/fq state via `frp-turbo status`, apply/revert, ZRAM on/off with CLI-byte-identical `zram.env`)
- [x] P6 — live monitoring (latency prober + SSE, journal SSE over `journalctl -f` with unit whitelist, FRP webServer stats scraper with 24 h history)
- [x] P7 — backup/restore (ZIP export with secrets redaction, zip-slip-guarded import with `.bak` + credential regeneration) + watchdog API (CLI-byte-identical `watchdog.env`, enable/disable, heal-event tail)
- [x] P8 — full dashboard UI (login + forced password change, dashboard with live SSE latency chart and service cards, servers/clients wizards with token generator + GRE-IP bindAddr selector, GRE manager with link test + mirror modal, turbo/logs/stats/backup/watchdog views — Alpine.js + HTMX, 100% vendored and embedded)
- [x] P9 — release pipeline (one-line installer, `frp-panel install-unit` single-source unit, GitHub Actions CI + release workflow, CHANGELOG, this quickstart)
- [x] P10 — FRP over GRE Reverse quick-setup wizard (`POST /api/wizard/gre-frp`, Dashboard modal, `frp-manager reverse iran|foreign`) and the corrected Iran-entry/Foreign-exit topology across docs and UI

## Quick checks (dev)

```sh
cd panel && go test -count=1 ./...
go vet ./...
scripts/check-sync.sh          # heredocs in frp-setup.sh == canonical assets
bash -n frp-setup.sh            # syntax gate
scripts/vendor-web.sh          # re-fetch vendored JS (pinned sha256)
scripts/build-release.sh 1.0.0 # cross-compile both arches + tarballs
```

Dev-time notes: the panel builds anywhere Go does (dev hosts without
systemd run it fine — service views simply report `unknown`). The frontend
has no build step: edit `panel/web/**` and rebuild the binary.

## Panel auth

First run of `frp-panel serve` generates `/etc/frp-panel/panel.toml` and
prints a one-time admin password to the console (stored only as bcrypt).
`frp-panel reset-password` regenerates it; the first login forces a change.
Sessions are JWT cookies (`HttpOnly`, `SameSite=Strict`), sliding 12 h,
login attempts rate-limited per IP with exponential lockout. The CSP is
same-origin only with vendored assets; Alpine.js expression evaluation
requires `script-src 'unsafe-eval'` — the single accepted relaxation,
documented in `panel/internal/api/router.go`.

## API surface

| Purpose | Endpoint |
|---|---|
| session | `POST /api/auth/login` · `POST /api/auth/logout` · `GET /api/auth/me` · `POST /api/auth/password` |
| frps instances | `GET/POST /api/servers` · `GET/PUT/DELETE /api/servers/{name}` · `POST /api/servers/{name}/token/regenerate` · `GET/PUT /api/servers/{name}/raw` |
| frpc instances | `GET/POST /api/clients` · `GET/PUT/DELETE /api/clients/{name}` · `POST/PUT/DELETE /api/clients/{name}/proxies` · `GET/PUT /api/clients/{name}/raw` |
| services | `GET /api/services` · `POST /api/services/{unit}/action` |
| GRE tunnels | `GET/POST /api/gre` · `GET/DELETE /api/gre/{name}` · `GET /api/gre/{name}/mirror` · `POST /api/gre/{name}/test` |
| reverse wizard | `GET /api/wizard/gre-frp/defaults` (next free iface/subnet/port) · `POST /api/wizard/gre-frp` (`role=iran` creates entry frps + GRE and returns the mirror payload, auto-allocating on conflict; `role=foreign` creates the mirrored GRE + frpc and runs the link test) |
| turbo | `GET/POST /api/system/turbo` |
| monitoring | `GET /api/monitor/latency(/stream)` (SSE) · `GET /api/logs/units` · `GET /api/logs/stream?unit=…` (SSE) · `GET /api/stats` |
| backup | `GET /api/backup/export[?secrets=1]` · `POST /api/backup/import` |
| watchdog | `GET/POST /api/watchdog` · `POST /api/watchdog/test-telegram` |
| misc | `GET /api/health` · `GET /api/version` |
