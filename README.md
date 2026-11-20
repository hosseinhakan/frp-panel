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
   **Iran Node**. Enter the Iran and Foreign public IPs; keep `gt11`, control
   port `7025` and a protocol. The wizard creates:
   - `gt11` with `10.100.111.2/30 ↔ 10.100.111.1/30`, MTU `1400`, `NOTRACK`
     for proto 47 and TCPMSS clamping;
   - a fresh 32-char token and an `frps` instance bound **strictly** to
     `10.100.111.2:<control_port>`, then enables both units;
   - the dual-layer auto-heal watchdog (`frp-watchdog`, 15s interval, 3 strikes,
     60s cooldown) — untick the wizard toggle to opt out.

   Copy the generated **mirror payload** (or the equivalent CLI command).
2. **Foreign (exit)** — run the same wizard on the Foreign node, choose
   **Foreign Node**, paste the payload, and enter the local ports to expose
   (`8443,2053,443`) plus the TCP/UDP toggle. It creates the mirrored `gt11`
   (`10.100.111.1/30 ↔ 10.100.111.2/30`) and an `frpc` instance with
   `tls.enable = true`, per-proxy `useEncryption = true`,
   `useCompression = false`, then pings `10.100.111.2` through `gt11` and
   reports the frpc unit state. It also allocates the loopback metrics
   `webServer` port the watchdog uses for proxy health.
3. Point users/DNS at **`Iran Public IP:<forwarded port>`** (for example
   `1.2.3.4:443`).

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
| reverse wizard | `POST /api/wizard/gre-frp` (`role=iran` creates entry frps + gt11 and returns the mirror payload; `role=foreign` creates the mirrored gt11 + frpc and runs the link test) |
| turbo | `GET/POST /api/system/turbo` |
| monitoring | `GET /api/monitor/latency(/stream)` (SSE) · `GET /api/logs/units` · `GET /api/logs/stream?unit=…` (SSE) · `GET /api/stats` |
| backup | `GET /api/backup/export[?secrets=1]` · `POST /api/backup/import` |
| watchdog | `GET/POST /api/watchdog` |
| misc | `GET /api/health` · `GET /api/version` |
