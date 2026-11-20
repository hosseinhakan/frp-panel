# FRP Tunnel Suite

Production-grade tunnel & FRP management: bash CLI (`frp-manager`), Go web
panel (`frp-panel`), GRE reverse-tunnel manager, kernel turbo tuning, live
monitoring, backup and watchdog — all operating on the **same** config paths
(`/root/frp/server|client/*.toml`, `/root/frp/gre/*.env`) and the same
systemd units, so CLI and Web UI never drift.

> Architecture & roadmap: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
> · release history: [CHANGELOG.md](CHANGELOG.md)

## Quickstart

Install the web panel on a fresh Ubuntu 22.04/24.04 or Debian 12 VPS
(root):

```sh
curl -fsSL https://raw.githubusercontent.com/garshasprahimi/frp-panel/main/scripts/install.sh | bash
```

The installer detects the architecture, downloads the release tarball,
installs `/usr/local/bin/frp-panel` (the whole dashboard is embedded in the
single binary — no CDN, no Node), writes the systemd unit from inside the
binary (`frp-panel install-unit`) and enables `frp-panel.service`.
Flags: `--port 9000 --bind ADDR --version v1.0.0 --base URL`.

First start prints a **one-time admin password** to the console:

```sh
journalctl -u frp-panel --no-pager | grep -i password | head -n1
```

Open `http://127.0.0.1:9000` (or `http://<tunnel-ip>:9000`), sign in, set a
real password, and you are on the dashboard.

The bash CLI installs alongside from the same repo:

```sh
sudo bash frp-setup.sh   # self-installs as /usr/local/bin/frp-manager
```

## The Iran ↔ Foreign topology (the recommended setup)

Two VPSes, one GRE tunnel, all control traffic invisible to filtering:

```
 ┌── Iran VPS ─────────────┐          ┌── Foreign VPS ──────────────┐
 │ frp-panel + frpc       │◄─ GRE ──►│ frps + frp-panel (peer)      │
 │ 10.100.111.2/30  gt11  │  proto47 │ 10.100.111.1/30  gt11        │
 └────────────────────────┘          └──────────────────────────────┘
```

1. **Foreign side** — install the panel (above), open *GRE Tunnels* →
   **New tunnel**. Fill this node's public IP and the Iran VPS public IP,
   leave the private IPs blank (a free `10.100.x.y/30` pair is suggested).
   The unit `gre-tunnel@<name>` comes up with conntrack bypass (proto 47)
   and MSS clamping.
2. Copy the **Mirror config** (one click) and save it as the same tunnel
   name on the Iran VPS via its panel (or `frp-manager gre create …`) —
   local/remote are swapped for you.
3. **Foreign side** — *FRP Servers* → **New server**; pick bind address
   `10.100.111.1` (the tunnel IP) so frps only accepts traffic arriving
   through the tunnel. Copy the generated 32-char token.
4. **Iran side** — *FRP Clients* → **New client**; server address
   `10.100.111.1`, paste the token (or pick it from a local server config),
   enter your ports (`22, 6000-6006`), keep the **TCP+UDP** toggle on for
   dual rules per port. TLS and encryption are already on.
5. Open `http://10.100.111.2:9000` (the Iran-side panel) or reach either
   panel through the tunnel; the dashboard's latency chart shows both the
   public and through-tunnel RTT live. Run *Turbo → Apply* on both nodes
   for BBR + fq + 32 MB buffers over the long-haul link.

Single-node usage works the same way — just skip the GRE steps and bind
frps to `::` (dual-stack).

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
| turbo | `GET/POST /api/system/turbo` |
| monitoring | `GET /api/monitor/latency(/stream)` (SSE) · `GET /api/logs/units` · `GET /api/logs/stream?unit=…` (SSE) · `GET /api/stats` |
| backup | `GET /api/backup/export[?secrets=1]` · `POST /api/backup/import` |
| watchdog | `GET/POST /api/watchdog` |
| misc | `GET /api/health` · `GET /api/version` |
