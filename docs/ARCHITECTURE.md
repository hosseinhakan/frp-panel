# FRP Tunnel Suite — Architecture & Implementation Plan

> Status: **APPROVED — P0–P9 implemented and verified.** The suite ships
> (CLI + web panel + GRE manager + turbo + monitoring + backup/watchdog +
> release pipeline). See CHANGELOG.md for the v1.0.0 inventory.
> Scope: upgrade `frp-setup.sh` into a production-grade Tunnel & FRP Management Suite
> (CLI + Web Panel + GRE Manager + Turbo + Monitoring + Backup/Watchdog).

---

## 0. Locked-in decisions

| Decision | Choice |
|---|---|
| Backend | **Go** (single static binary, `go:embed` UI, ~25 MB artifact, ~30 MB RAM idle) |
| Panel port | **9000** (7500 stays reserved for FRP's own dashboard) |
| Frontend | **Alpine.js + HTMX + Tailwind** (vendored, no CDN at runtime, no Node on the VPS) |
| Target OS | Ubuntu 22.04 / 24.04, Debian 12 (apt + systemd; iptables-nft compat) |
| Delivery | **One-line `curl | bash` installer** pulling a GitHub Release tarball |

---

## 1. Goals & compatibility contract

The suite must feel like one product with two faces (terminal + browser) operating on the
**same state**. Invariants that guarantee CLI ↔ Web stay 100 % synced:

| Invariant | Value (unchanged from current script) |
|---|---|
| FRP server configs | `/root/frp/server/*.toml` |
| FRP client configs | `/root/frp/client/*.toml` |
| systemd templates | `frps@.service`, `frpc@.service` (ExecStart paths identical) |
| CLI command | `/usr/local/bin/frp-manager`, root-only |
| CLI menu items **1–9** | same numbers, same labels, same flows |
| Instance naming | `server-<port>.toml`, `client-<port>.toml` (defaults kept) |
| BBR GC cron | `0 */3 * * * pkill -10 -x frpc; pkill -10 -x frps` preserved (folded into Turbo) |

New state introduced by the suite (all additive):

| Path | Purpose |
|---|---|
| `/etc/frp-panel/panel.toml` | panel config, admin bcrypt hash, JWT secret, node role/labels |
| `/root/frp/gre/*.env` | GRE tunnel definitions (CLI + panel read/write these) |
| `/usr/local/bin/frp-panel` | panel binary (embeds web UI + unit/helper assets) |
| `/usr/local/bin/frp-gre`, `frp-turbo`, `frp-watchdog` | small POSIX-sh helpers |
| `/var/log/frp-panel/` | watchdog/prober event logs |
| units: `frp-panel.service`, `gre-tunnel@.service`, `tunnel-turbo.service`, `frp-zram.service`, `frp-watchdog.service` | systemd surface |

**Intentional behavior changes (requested features, everything else untouched):**

1. `auth.token` default is now a **generated 32-char random alphanumeric** (the static
   `mikeesierrah` default is dropped — insecure). Old configs keep working untouched.
2. Generated client proxies default `transport.useEncryption = true` and
   `transport.tls.enable = true`; `useCompression = false` (RAM).
3. Server setup gains a `bindAddr` choice: `0.0.0.0` / `::` / **private tunnel IP** (e.g. `10.100.111.2`).
4. Client setup gains a **single TCP+UDP toggle** emitting paired `tcp-<p>` / `udp-<p>` proxies.
5. Menu item 7 keeps its position/number; label becomes `7) Optimization Utilities (Turbo)`.

---

## 2. Repository layout

```
frp-opencode/                        # repo root (git init when ready)
├── README.md
├── frp-setup.sh                      # UPGRADED single-file bash CLI (no new deps)
├── docs/ARCHITECTURE.md              # this document
├── panel/                            # Go module: github.com/<owner>/frp-suite/panel
│   ├── go.mod                        # deps: BurntSushi/toml, golang.org/x/crypto (bcrypt),
│   │                                 #       golang-jwt/jwt/v5 — nothing else
│   ├── cmd/frp-panel/main.go         # subcommands: serve | verify | version
│   ├── internal/
│   │   ├── cfg/                      # panel.toml load/save/first-run bootstrap
│   │   ├── frpconf/                  # FRP TOML model: read/write/render/validate
│   │   │   ├── model.go              #   structs mirroring frps/frpc TOML subset
│   │   │   ├── range.go              #   port-range parser (shared semantics w/ CLI)
│   │   │   ├── token.go              #   crypto/rand 32-char token generator
│   │   │   └── golden/               #   golden *.toml fixtures for tests
│   │   ├── svc/                      # systemctl wrapper (exec, whitelisted unit names)
│   │   ├── api/                       # net/http handlers: routes, auth, SSE, middleware
│   │   ├── gre/                      # tunnel env model + ip/iptables command builder
│   │   ├── turbo/                    # sysctl/BBR/ZRAM appliers
│   │   ├── prober/                   # latency goroutine + ring buffer (ICMP + TCP probes)
│   │   ├── stats/                    # scraper for frps/frpc webServer /api/status
│   │   ├── journal/                  # `journalctl -f` streamer (per-SSE-connection proc)
│   │   ├── backup/                   # ZIP export/import with zip-slip guard + manifest
│   │   └── assets/                   # go:embed: web static + systemd units + helpers
│   └── web/                          # (embedded via internal/assets)
│       ├── static/css/app.css        # precompiled Tailwind (dark-first)
│       ├── static/js/vendor/         # alpine.min.js, htmx.min.js, htmx-sse.min.js, uPlot
│       ├── static/js/app.js          # helpers, i18n-ready string table
│       └── pages/*.html              # server-rendered layout + HTMX partials
├── scripts/
│   ├── install.sh                    # the one-line curl installer for the panel
│   ├── build-release.sh              # cross-compile amd64/arm64 + package tarball
│   ├── vendor-web.sh                 # pin & fetch JS libs + build Tailwind (dev-time only)
│   └── check-sync.sh                 # CI guard: bash heredocs == embedded assets
└── .github/workflows/release.yml     # tag → build → attach artifacts
```

**Single-source rule for system assets:** `gre-tunnel@.service`, `frp-gre`, `frp-turbo`, …
are authored once inside `panel/internal/assets/` (embedded in the Go binary via `go:embed`)
and duplicated into `frp-setup.sh` heredocs so the CLI stays self-contained offline.
`scripts/check-sync.sh` (run in CI) fails if the two copies drift.

---

## 3. Component architecture

```
┌───────────────────────── Node (Ubuntu/Debian VPS, root) ─────────────────────────┐
│                                                                                  │
│   frp-manager (bash CLI) ──┐        ┌────────────────────────────────┐           │
│   menu 1–13                │        │ frp-panel (Go, :9000)          │           │
│                            ▼        │  ├ /api  REST + SSE            │           │
│   /root/frp/server/*.toml ◄──┬──────►│  ├ auth  bcrypt + JWT cookie   │           │
│   /root/frp/client/*.toml ◄──┤      │  ├ prober (ping/tcp RTT loop)  │           │
│   /root/frp/gre/*.env    ◄──┤      │  ├ stats  (scrape frp /api/status)         │
│                            │      │  ├ journal (journalctl -f)      │           │
│                            ▼      │  └ embedded web UI (go:embed)   │           │
│                       systemctl    └───────┬────────────────────────┘           │
│                            │                │ exec: ip, sysctl, journalctl,       │
│  ┌──────────────────────────┴───────────────┴───────────────────────────────┐    │
│  │ systemd: frps@*.service   frpc@*.service   gre-tunnel@*.service           │    │
│  │           tunnel-turbo.service  frp-zram.service  frp-watchdog.service    │    │
│  │           frp-panel.service                                              │    │
│  └──────────────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────────────┘
        ▲ browser (Iran side) reaches the panel over: GRE private IP :9000
          (recommended, invisible to filtering), SSH tunnel, or public :9000
```

Both CLI and panel manipulate the **same files and the same systemd units** — there is no
separate database to drift. The panel's only private state is `/etc/frp-panel/panel.toml`
(credentials) and in-memory ring buffers (latency/stats history).

---

## 4. Shared config model (TOML contracts)

### 4.1 Generated frps TOML (changes vs. today)

```toml
# Auto-generated by frp-manager / frp-panel — /root/frp/server/server-7000.toml
bindAddr = "10.100.111.2"          # was hardcoded "::"; now prompted:
                                   #   0.0.0.0 | :: | private tunnel IP (validated against `ip -o addr`)
bindPort = 7000
quicBindPort = 7000                  # or kcpBindPort (unchanged logic)

transport.heartbeatTimeout = 90
transport.maxPoolCount = 65535
transport.tcpMux = false
transport.tcpMuxKeepaliveInterval = 10
transport.tcpKeepalive = 120

auth.method = "token"
auth.token = "K7mQz2xVb9LrT4nY8wPd3cJ6hFgA1sEu"   # 32-char crypto-random, generated + shown once

# NEW: metrics endpoint for the panel (also powers FRP's own dashboard)
webServer.addr = "127.0.0.1"
webServer.port = 7500                # auto-allocated 7500..7599 per instance, no collisions
webServer.user = "admin"
webServer.password = "<random>"      # panel reads it from this file to scrape /api/status
```

### 4.2 Generated frpc TOML

```toml
serverAddr = "10.100.111.2"          # may now be the GRE private IP
serverPort = 7000
loginFailExit = false

auth.method = "token"
auth.token = "<paste from server setup / picked via panel dropdown>"

transport.protocol = "tcp"           # tcp | websocket | quic | kcp (unchanged)
transport.tcpMux = false
transport.dialServerTimeout = 10
transport.dialServerKeepalive = 120
transport.poolCount = 20
transport.heartbeatInterval = 30
transport.heartbeatTimeout = 90
transport.tls.enable = true           # CHANGED default (was false)
transport.useEncryption = true       # NEW default per-proxy (see below)
transport.useCompression = false     # RAM-saving default (unchanged)

# NEW: client-side metrics endpoint for panel stats
webServer.addr = "127.0.0.1"
webServer.port = 7400                # auto-allocated 7400..7499 per instance

[[proxies]]
name = "tcp-6000"
type = "tcp"
localIP = "127.0.0.1"
localPort = 6000
remotePort = 6000
transport.useEncryption = true
transport.useCompression = false

[[proxies]]                           # emitted by the single TCP+UDP toggle
name = "udp-6000"
type = "udp"
localIP = "127.0.0.1"
localPort = 6000
remotePort = 6000
transport.useEncryption = true
transport.useCompression = false
```

### 4.3 Dual TCP+UDP range parser

Port input grammar (CLI and web wizard use the identical semantics — `frpconf/range.go`
is the reference implementation, the bash version is its mirror):

```
ports    := spec ("," spec)*
spec     := port | range
range    := port "-" port           # inclusive
emission := for each port p in expansion(p, udp_toggle, name_prefix):
              tcp block  name = "tcp-<p>"
              udp block  name = "udp-<p>"   (only when toggle ON)
```

The canonical panel renderer emits the compact FRP template form instead of
unrolling every port:

```
{{- range $_, $v := parseNumberRangePair "22,6000-6006" "22,6000-6006" }}
[[proxies]]
...
{{- end }}
```

`frpconf` expands that template back into `Proxies` for the UI, classifies it
as **managed** (never raw-only), and re-renders it on save. Plain
`[[proxies]]` files remain valid and editable; adding/removing an individual
proxy rule converts that client to plain blocks.

- Toggle granularity: **per setup** in CLI (one prompt, default ON);
  **per rule** in the web wizard (each port/range row has its own TCP/UDP checkboxes).
- Explosion guard: a range of >500 ports switches the CLI back to FRP's Go-template
  `parseNumberRangePair` rendering (kept working — it's the current behavior), while the
  panel always writes explicit blocks and warns above 200 proxies.
- Parsing strategy: the panel **renders templates first** (same engine frp uses), so
  template-based configs remain readable. Valid TOML is always structurally editable:
  managed fields are rewritten and keys outside the model (`[log]`, `transport.tls`,
  vhosts, plugins, metadata, …) are merged back from the parsed tree. Only template
  files and unparseable TOML open the raw editor, and clicking `edit` on those routes
  straight to it instead of failing.

### 4.4 Token generator

- Go: `crypto/rand` → 32 chars `[A-Za-z0-9]` (rejection-sampled, constant time not required —
  192 bits of entropy).
- Bash (CLI): `head -c 256 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 32`.
- CLI shows the token **once** at server creation; "show again" requires explicit
  confirmation. Web UI has a **Regenerate** button (writes new token to server TOML,
  offers to propagate to local client TOMLs, restarts affected units).
- webServer passwords: same generator, stored only in the TOMLs.

---

## 5. Go backend (`frp-panel`)

### 5.1 Runtime posture

- Runs as **root** (same trust model as the CLI: it must write `/root/frp`, call systemctl,
  ip, sysctl, journalctl). Hardened unit: `NoNewPrivileges`, `PrivateTmp`,
  `ProtectSystem=full` + `ReadWritePaths=/root/frp /etc/frp-panel`, `RestrictSUIDSGID`.
- Binds `0.0.0.0:9000` (all interfaces) by default so the panel is reachable at
  `http://<public-ip>:9000`; `--bind 127.0.0.1` keeps it loopback-only and a GRE
  private IP like `10.100.111.2` restricts it to the tunnel. The installers add
  `ufw allow <port>/tcp` when `ufw` is present. No TLS by default; self-signed TLS
  toggle available (`panel.toml [server] tls_cert/key`).
- Everything is `exec` of the exact commands a human admin would run — no D-Bus, no
  libraries that fight systemd. Unit names are whitelisted (`^[a-zA-Z0-9_.@-]{1,64}$`,
  must resolve to an existing config file) before any `systemctl` call → **no shell
  injection surface**.

### 5.2 Config first-run bootstrap

`frp-panel serve` with no `/etc/frp-panel/panel.toml`: creates the file, generates
`jwt_secret` (32 B random), creates `admin` with a **one-time random password** printed to
the console + written nowhere else; first login forces a password change (bcrypt, cost 10).

### 5.3 Auth

- `POST /api/auth/login {user, password}` → JWT (HS256, 12 h sliding expiry, claims:
  `sub`, `exp`, `iat`) delivered as `HttpOnly; Secure; SameSite=Strict` cookie
  (`frp_session`). No localStorage tokens.
- Mutating routes require `Origin`/`Referer` match (CSRF defense-in-depth on top of
  SameSite=Strict); HTMX sends `X-Requested-With` natively.
- Login rate limit: 5 attempts/min/IP, exponential lockout; events audited to journal.
- All assets served from same origin (vendored) → strict CSP `default-src 'self'`
  works with zero exceptions.

### 5.4 API surface

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/auth/login` / `/api/auth/logout` / GET `/api/auth/me` | session lifecycle, first-login flag |
| GET | `/api/overview` | node summary: uptime, CPU/RAM, BBR/zram state, service + tunnel roll-up |
| GET/POST | `/api/servers` | list / create frps instance (wizard payload: port, protocol, mux, bindAddr choice) |
| GET/PUT/DELETE | `/api/servers/{name}` | read / update / remove (config + unit disable); the update body covers every transport tunable and an optional `restart` flag |
| POST | `/api/servers/{name}/token/regenerate` | new random token (+ optional propagate) |
| POST | `/api/servers/{name}/foreign-script` | self-contained Foreign installer (GRE helper + units + frpc download + matching TOML) for a linked GRE tunnel or caller-supplied public IPs |
| GET/POST/PUT/DELETE | `/api/clients…` | mirrored CRUD for frpc; `POST /api/clients/{name}/proxies` adds port rules w/ per-rule TCP/UDP toggle |
| POST | `/api/services/{unit}/action` `{action: start\|stop\|restart}` | systemctl wrapper (whitelist) |
| GET/POST | `/api/gre`, DELETE `/api/gre/{name}` | tunnel CRUD (writes `/root/frp/gre/<name>.env`, ensures units) |
| GET | `/api/gre/{name}/mirror` | mirrored env for the remote node (copy-paste/CLI heredoc) |
| GET | `/api/system/turbo`, POST `/api/system/turbo` | BBR/fq/sysctl state, apply/revert, ZRAM on/off + size, and the three mikeesierrah utilities (`gc-cron`, `volatile-logs`, `clear-logs`) |
| GET | `/api/monitor/latency` + `/api/monitor/latency/stream` | snapshot + SSE live probe feed |
| GET | `/api/logs/units`, GET `/api/logs/stream?unit=…&since=…` | SSE journal tail (frps@*/frpc@*/gre/turbo/watchdog/panel units only) |
| GET | `/api/stats?instance=…` | scraped frp webServer metrics + rolling history (conns, in/out bytes per proxy) |
| GET | `/api/backup/export`, POST `/api/backup/import` | ZIP stream down / multipart restore (selective categories) |
| GET | `/api/wizard/gre-frp/defaults` | next free GRE iface, `10.100.<n>.0/30` subnet and frps control port (scans envs, live links, configs, `/proc/net/tcp`) |
| POST | `/api/wizard/gre-frp` | create the Iran entry or Foreign exit half; reuses the existing GRE iface + `/30` when the same public pair (or remote IP) is already live, otherwise auto-allocates a free iface/subnet/port on conflict; optional custom token, frps bind (`GRE IP`/`::`/`0.0.0.0`) and `rawSpeed`. `mirrorPayload` accepts both the plain `KEY=VALUE` block and the generated `FRP_FOREIGN_SETUP` script (shell lines ignored, quoted assignments extracted) |
| GET | `/api/watchdog`, POST `/api/watchdog` | state, config (Telegram token masked), recent heal events |
| POST | `/api/watchdog/test-telegram` | send one test alert using stored or posted credentials |
| GET | `/api/health`, `/api/version` | unauthenticated liveness + build info |

P3/P4 implementation notes (additions to the table above):

- Session endpoints also ship `POST /api/auth/password` (first-login forced
  change) and `frp-panel reset-password [--config PATH]` as a CLI escape
  hatch for lost passwords (prints a new one-time password, re-arms the
  change flag).
- Every config write passes the **write gate**: `frps/frpc verify -c` against
  the candidate file (FRP's own binary), falling back to the internal
  frpconf parser when the binary isn't installed yet (`"verify": "internal"`
  in responses); any previous file is copied to `<file>.bak-<UTC ts>` first.
- Advanced/template-style instances refuse structured edits (409) and route
  to `GET/PUT /api/servers/{name}/raw` and `GET/PUT /api/clients/{name}/raw`.
- Client proxy rules are a sub-resource:
  `POST /api/clients/{name}/proxies` (append, per-request TCP/UDP toggle),
  `PUT …/proxies` (validated full replace), `DELETE …/proxies?ports=…`
  (removes the paired tcp/udp blocks).
- `GET /api/services` lists every suite unit with live is-active/is-enabled
  state; `POST /api/services/{unit}/action` accepts
  `start|stop|restart|enable|disable` only, whitelisted units only, and
  template instances must resolve to an existing config file.
- GRE parity: `POST /api/gre` auto-suggests the next free `10.100.<n>.0/30`
  pair when the private IPs are omitted, writes CLI-byte-identical `.env`
  files, installs the canonical `frp-gre` helper + unit from the embedded
  assets (then `daemon-reload`), and reports `unit_error` instead of failing
  when systemd is unavailable; `POST /api/gre/{name}/test` brings the tunnel
  up, pings the peer through the interface and reports rtt/loss/counters.
- Auth details: JWT in an HttpOnly `frp_session` cookie (SameSite=Strict,
  Secure under TLS), 12 h sliding expiry re-issued past the half-life,
  login rate limit 5/min/IP with exponential lockout (30 s doubling, 15 min
  cap), mutating routes require same-origin Origin/Referer, and every
  security event is audited to stderr (→ journald under systemd).

P5 implementation notes:

- `GET /api/system/turbo` reports the sysctl drop-in presence, live values
  parsed from `frp-turbo status`/`zram-status` (absent helper = fresh
  host), the `tunnel-turbo`/`frp-zram` unit states and the persisted ZRAM
  config from `/etc/frp-panel/zram.env`.
- `POST /api/system/turbo {action}` mirrors the CLI exactly: `apply` →
  install embedded helper + units → `enable` + `restart tunnel-turbo`;
  `revert` → `disable` + `stop` + best-effort `frp-turbo revert` (failures
  surface as `unit_error`); `zram-on {size, algo}` → CLI-byte-identical
  `zram.env` (`.bak` first) → `enable` + `restart frp-zram`; `zram-off`.
  Size/algo validated (128–32768 MB, lz4/zstd/lzo/lzo-rle).
- `GET` also returns `gcCron {active, schedule, command}` parsed from
  `frp-turbo gc-status`. `gc-cron` installs the idempotent 3h cron;
  `volatile-logs` disables rsyslog and writes journald `Storage=volatile`,
  `SystemMaxUse=50M`, `SystemKeepFree=5M`; `clear-logs` vacuums the journal,
  truncates `/var/log/*.log` and `wtmp`/`btmp`, and removes rotated logs.
  The same actions exist as `frp-manager turbo <action>`.

P6 implementation notes:

- Prober targets auto-derive from `/root/frp/gre/*.env` (peer public ICMP +
  peer private ICMP **through the iface**) and client TOMLs (TCP RTT to
  `serverAddr:serverPort`); ring buffer 3 600 samples, loss% over a rolling
  60-sample window, SSE `snapshot` event on connect + `sample` per tick +
  15 s heartbeat.
- Log SSE: `journalctl -f -n <lines> --output=short-iso -u <unit>` via the
  new `svc.Runner.ExecStream` (same allowlist/charset gate as `Exec`, child
  killed on client disconnect); unit whitelist is `svc.ValidateUnit` +
  config-file existence; `?since=` accepts RFC3339 only (free-form
  journalctl expressions rejected); ANSI stripped, 2 000-line ring cap per
  connection, `eof`/`overflow` events end the response for HTMX reconnect.
- Stats scraper per instance kind: frps → `/api/serverinfo` totals +
  `/api/proxy/{type}` rows (falling back to legacy `/api/status`
  server-info on old FRP); frpc → `/api/status` proxy map. camelCase and
  snake_case key spellings both tolerated; loopback webServer addresses
  normalized; history sampled at most once per minute, kept 24 h.

P7 implementation notes:

- Export (`GET /api/backup/export[?secrets=1]`) streams a ZIP whose entry
  names mirror the CLI's tar layout plus `manifest.json`; without
  `secrets=1` every FRP TOML has `auth.token`/`webServer.password` redacted
  to the literal `REDACTED` (table-style and dotted-key styles both
  handled) and `/etc/frp-panel/panel.toml` (bcrypt+JWT) is excluded.
- Import (`POST /api/backup/import`) validates **every entry before
  anything is written** (stage-in-memory then apply): zip-slip family
  (absolute paths, drive letters, backslashes, `..`/`.` segments, NULs),
  symlink entries rejected, 32 MB/entry + 100 MB archive caps, entries must
  map onto whitelisted category paths (unknown → skipped+reported, foreign
  file in a suite path → whole import rejected). Applying takes
  `.bak-<ts>` of each overwritten file, regenerates fresh random tokens
  for `REDACTED` lines, then the handler runs `daemon-reload` and restarts
  affected **active** units (`?restart=1`); restoring panel.toml/unit is
  reported with a restart hint instead of self-restarting.
- Watchdog: `GET /api/watchdog` (unit state, parsed env with the Telegram bot
  token masked, last 50 heal events from `/var/log/frp-panel/watchdog.log`);
  `POST` with pointer fields merges over the current env (explicit zeros/invalids
  → 400), writes `watchdog.env` **byte-identical** to the CLI heredoc (`.bak`
  first), installs the embedded helper + unit and enables/restarts
  `frp-watchdog`. An empty/masked `tgBotToken` keeps the stored secret;
  `clearTelegram` wipes all Telegram fields. `POST /api/watchdog/test-telegram`
  sends one message via the stored or posted token/chat/API base. Secret-free
  backup exports redact `TG_BOT_TOKEN`, and import clears the placeholder.

Validation before any config write: `frps verify -c <file>` / `frpc verify -c <file>`
(FRP's own subcommand — renders templates too). Bad TOML never reaches systemd.

### 5.5 SSE implementation

- One shared goroutine per stream; heartbeat comment `: ping` every 15 s; HTMX
  `sse-connect` auto-reconnects.
- Latency SSE: `{"ts":1732100000,"targets":{"gt11-peer":{"rtt_ms":12.4,"loss":0},"frps-ctrl":{"rtt_ms":11.9}}}`.
- Log SSE: line-canonicalized journalctl output (`--output=short-iso`), ANSI stripped,
  ring-limited to last 2 000 lines per connection; process killed via `context` on
  client disconnect.

---

## 6. Frontend (Alpine.js + HTMX + Tailwind, dark-first)

### 6.1 Design language

- **Dark default** (Tailwind `darkMode:'class'`, persisted toggle in `localStorage`):
  zinc-950 canvas, zinc-900 cards with `rounded-xl` + zinc-800 hairline borders,
  cyan-400 primary actions, emerald-400 healthy status, amber degrading, red failed.
- System font stack + `ui-monospace` for logs and every data value (zero font
  downloads); focus rings, ARIA live regions for SSE updates,
  `prefers-reduced-motion` respected; mobile-first: sidebar collapses to a
  horizontal rail < 920px. String table centralized in `app.js` → i18n (fa) later.
- Vendored assets (~156 KB total): `alpine.min.js` (3.14.9), `htmx.min.js`
  (1.9.12), `htmx-sse.min.js` (sse extension), `uPlot` 1.6.32 (latency/stats
  charts, canvas, dark-tuned). No CDN — the panel works on isolated nodes;
  `scripts/vendor-web.sh` pins each download by sha256.

P8 implementation notes:

- The dashboard is a single embedded page (`panel/web/pages/index.html`) with
  hash-routed views mounted on demand via Alpine `<template x-if>`; one
  Alpine.js component per view (`Alpine.data` factories in `app.js`), global
  stores for toasts/confirm, the latency feed and the log buffer.
- Load order matters and is pinned in both pages: htmx → sse ext → uPlot →
  `app.js` → **alpine.min.js last** — `app.js` registers the `alpine:init`
  factories, and Alpine may start as soon as it loads (a factory registered
  after Alpine boots is never found, which the browser smoke test caught).
- SSE: htmx's sse extension owns the EventSource lifecycle (connect, auto
  reconnect after the server's deliberate eof/overflow, close on cleanup),
  but payloads bypass its DOM events — htmx triggers `htmx:sseMessage`
  (camelCase) while HTML lowercases `@htmx:sseMessage` attributes, so those
  handlers can never match. Instead `app.js` wraps `htmx.createEventSource`
  (the documented factory the extension calls for every connection) and taps
  the EventSource directly with `addEventListener`, feeding the stores. Log
  lines are only ever appended as text nodes — never innerHTML.
- CSP: Alpine's expression evaluator needs `new Function`, so the policy is
  `script-src 'self' 'unsafe-eval'` (see router.go) — the one accepted
  relaxation; inline scripts/styles, foreign loads and framing stay blocked.
  htmx's boot-time indicator `<style>` injection is disabled via the
  `htmx-config` meta so `style-src 'self'` holds with zero exceptions.
- Alpine 3.14 has no component-destroy hook, so view switches run the
  `FRP.cleanup()` registry (poll timers, EventSources, uPlot instances)
  before unmounting; pollers additionally self-check `$el.isConnected`.

### 6.2 Pages (server-rendered layout, HTMX partial swaps)

| Page | Contents |
|---|---|
| Login | centered card, one-time password notice, error shake, lockout hint |
| Dashboard | node role badge (Iran/Foreign/standalone) + uptime; CPU/RAM/net sparklines; GRE + FRP status cards with quick restart; live latency chart (uPlot, per target); recent watchdog events |
| Servers | table: instance, port, protocol, webServer port, status pill, uptime, actions (start/stop/restart/edit/retoken/foreign-setup/toml); edit always opens (raw modal only for non-range templates/unparseable files, merge-preserving form for valid TOML) and exposes every transport field (`tcpMux`, `tcpMuxKeepaliveInterval`, `heartbeatTimeout`, `tcpKeepalive`, `maxPoolCount`, QUIC block) plus a restart-after-save checkbox; **bindAddr is a free-form input with suggestions**, so `0.0.0.0` / `::` / any GRE IP round-trips exactly; **Foreign Setup** generates the one-click installer |
| Clients | instances + proxy table with **tcp/udp type badges**; comma-separated port list with ranges (`8989,8443,6000-6005`) and a single TCP / TCP+UDP selector (edit replaces the list in place and keeps the compact `parseNumberRangePair` layout); edit exposes `loginFailExit`, `tcpMuxKeepaliveInterval`, `dialServerTimeout`, `dialServerKeepalive`, `poolCount`, `heartbeatInterval`, `heartbeatTimeout`, QUIC, TLS, per-proxy encryption/compression and restart-after-save; **Raw speed** forces TLS/FRP encryption/compression/tcpMux off; wizard: server token picker (reads local server TOMLs) or paste |
| GRE | tunnel cards: iface, private pair, MTU, status, peer latency, tx/rx counters; create form with all six inputs + defaults (`gt11`, `10.100.111.1/30`, `…2/30`, MTU 1400); **mirror-config** generator for the far node; delete with teardown confirmation |
| Turbo | BBR/fq/sysctl current-vs-turbo diff table; one-click **Apply**; ZRAM card (size, lz4, on/off); **System utilities** card: 3h FRP GC cron (+ badge), volatile journald logs, clear all logs |
| Logs | unit picker (frps@*/frpc@*/gre-turbo/watchdog), live SSE pane, pause/follow, level filter, colored timestamps |
| Stats | per-instance: active conns, traffic in/out per proxy (from FRP webServer), 24 h history graph |
| Backup | Export ZIP button (with include-secrets toggle); Import with category checkboxes (frp / gre / systemd / turbo / panel) + restore summary; watchdog toggle + interval + event log |

---

## 7. GRE Reverse Tunnel Manager

### 7.1 Tunnel definition — `/root/frp/gre/gt11.env`

```bash
LOCAL_PUBLIC_IP=1.2.3.4
REMOTE_PUBLIC_IP=5.6.7.8
IFACE=gt11                 # default gt11, validated ^gt?[0-9]+$
LOCAL_PRIVATE_IP=10.100.111.1/30
REMOTE_PRIVATE_IP=10.100.111.2/30
MTU=1400
MSS_MODE=clamp             # clamp | 1360 | 1240 | 1220 | off
```

### 7.2 `gre-tunnel@.service` + `frp-gre` helper

```
[Unit]
Description=GRE tunnel %i
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/frp-gre up %i
ExecStop=/usr/local/bin/frp-gre down %i
ExecReload=/usr/local/bin/frp-gre reload %i

[Install]
WantedBy=multi-user.target
```

`frp-gre up <name>` (idempotent — safe on restart/boot):

```
ip tunnel add gt11 mode gre local <LOCAL_PUBLIC_IP> remote <REMOTE_PUBLIC_IP> ttl 255
ip addr add <LOCAL_PRIVATE_IP> dev gt11
ip link set gt11 up mtu 1400
# conntrack bypass for GRE (proto 47):
iptables -t raw -A PREROUTING -p 47 -j CT --notrack   # fallback: -j NOTRACK on old iptables
iptables -t raw -A OUTPUT      -p 47 -j CT --notrack
# MSS clamping both directions:
iptables -t mangle -A FORWARD -o gt11 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t mangle -A FORWARD -i gt11 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
# (MSS_MODE=1240|1220 swaps --clamp-mss-to-pmtu for --set-mss <value>)
# FORWARD accept pair if default policy is DROP; remote-private route implicit via /30 addr
```

`down` = exact inverse (del rules by spec, `ip tunnel del`); `reload` = down+up.
Both CLI and panel only ever write the `.env` and enable/start the unit. The CLI
uses `systemctl enable --now`; the panel issues explicit `enable` + `restart`
(`svc.Systemctl` rejects every argument beginning with `-`), then reads status
from `ip -json addr` + `/sys/class/net/gt11/statistics/` + prober.

### 7.3 Workflow niceties

- Wizard pre-flight: shows `ip -o -4 addr` candidates for public IP default; warns if
  `REMOTE_PUBLIC_IP` == local; optional **link test** (bring up, ping peer private IP,
  report counters) before saving.
- **Mirror config** output: the same six fields with local/remote swapped, printable as a
  ready-made `.env` + one-liner for the far node.
- Multiple tunnels: /30 subnets suggested from `10.100.<n>.0/30` allocator to avoid overlap.

---

## 8. Turbo module (one-click optimizer)

`frp-turbo` (POSIX sh, ~120 lines) + `tunnel-turbo.service` (oneshot, RemainAfterExit,
`ExecStart=frp-turbo apply`, `ExecStop=frp-turbo revert`). The old `optimize()` cron/GC
behavior is preserved inside `apply`.

**`/etc/sysctl.d/99-tunnel-turbo.conf`** (written by `apply`, removed by `revert`):

```
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_base_mss = 1024
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.core.somaxconn = 65535
net.ipv4.ip_forward = 1
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3
vm.swappiness = 10            # only when ZRAM/swap active
```

Plus: `tcp_bbr` via `/etc/modules-load.d/bbr.conf` (unchanged), and the existing
`0 */3 * * * pkill -10 -x frpc; pkill -10 -x frps` GC cron ensured idempotently.

**System utilities (Turbo tab / `frp-manager turbo …`):** `gc-cron` installs and
verifies that 3h cron; `volatile-logs` disables rsyslog and configures journald
(`Storage=volatile`, `SystemMaxUse=50M`, `SystemKeepFree=5M`); `clear-logs`
vacuums the journal, truncates `/var/log/*.log`, `wtmp`, `btmp`, and deletes
rotated `.gz`/`.1`–`.9` files. `gc-status` feeds the UI badge.

**ZRAM (optional, default OFF):** `frp-turbo zram-on --size 2048 --algo lz4` →
modprobe zram → `/sys/block/zram0/{comp_algorithm,disksize}` → `mkswap` → `swapon -p 100`;
persisted via `frp-zram.service` (oneshot, RemainAfterExit). `zram-off` + optional 1 GB
`/swapfile` fallback path for 1 GB-RAM nodes. Panel + CLI expose size/algo/state.

---

## 9. Monitoring, logs, stats

- **Prober** (panel goroutine, 5 s default): per target — GRE peer **public IP** (ICMP),
  GRE peer **private IP** (ICMP through tunnel → true tunnel health), frp control channel
  (TCP connect RTT to `serverAddr:serverPort`). Uses `ping` binary (iputils, present on
  targets) — no raw sockets. Ring buffer 3 600 samples; SSE to UI; loss% computed over
  rolling window. Targets auto-derived from GRE `.env`s + client TOMLs; manual extra
  targets in `panel.toml`. Node labels ("Iran ↔ Foreign") are cosmetic settings per node.
- **Logs**: SSE wrapper over `journalctl -f -u <unit> -n 200 --output=short-iso`;
  unit whitelist `^(frps|frpc|gre-tunnel|tunnel-turbo|frp-zram|frp-watchdog|frp-panel)@?[A-Za-z0-9_.-]*`.
- **Stats**: scraper reads each instance's `webServer` creds from its TOML →
  `GET http://127.0.0.1:<port>/api/status` (basic auth), tolerant-parses the proxy list
  (name, type, status, cur_conns, traffic in/out) — fixtures pinned from the installed
  FRP version; 1-minute history kept 24 h in memory. Enables FRP's own dashboard for the
  user "for free" (same endpoint).
- **Watchdog** `frp-watchdog.service` (loop, 15 s, `Restart=always`): **layer 1** pings
  each GRE peer private IP through its interface (2 packets, 3 strikes →
  `systemctl restart gre-tunnel@x`, 60 s cooldown, then restart every active `frpc@*`);
  **layer 2** (when GRE is healthy) probes the frpc control TCP channel and, if the
  loopback `webServer` exists, requires every proxy in `/api/status` to report `running`
  (3 strikes → restart only that `frpc@*`, cooldown). Structured HEAL events → journal +
  `/var/log/frp-panel/watchdog.log` + surfaced in the UI. When `TG_BOT_TOKEN` and
  `TG_CHAT_ID` are set, each heal also posts a plain-text Telegram alert
  (host/layer/unit/reason/consecutive/result) from a background `curl --max-time 5`,
  so an unreachable or blocked Telegram API never stalls the loop; `TG_API_BASE`
  can point at a Worker reverse proxy. Config lives in
  `/etc/frp-panel/watchdog.env` (`INTERVAL`, `THRESHOLD`, `COOLDOWN`, `PING_TIMEOUT`,
  `TCP_TIMEOUT`, `TG_BOT_TOKEN`, `TG_CHAT_ID`, `TG_API_BASE`).

---

## 10. Backup / restore

- **Export** (panel: ZIP; CLI: `tar.gz` fallback when `zip` missing — panel ZIP includes a
  `manifest.json`): `/root/frp/**` (TOMLs + gre envs), systemd units for the suite,
  `99-tunnel-turbo.conf`, bbr.conf, optional `/etc/frp-panel/panel.toml` (**secrets
  toggle**, off by default — token/bcrypt/jwt included only when explicitly requested;
  without it, restore regenerates credentials).
- **Import**: multipart ZIP → temp dir → **zip-slip guard** (every entry must resolve
  under the temp root) + size limit (100 MB) + manifest version check → selective
  category checkboxes → atomic apply (existing files moved to `<file>.bak.<ts>`) →
  `daemon-reload` + restart of affected units → restore summary in UI.
- CLI: menu item 12 → `frp-manager backup export|import` (same payloads).

---

## 11. CLI upgrade — `frp-setup.sh`

Keeps: `set -e`, colors, print_* helpers, root check, self-install, menu loop, all
existing function behavior. Adds (menu **append-only** — items 1–9 keep exact position):

```
 1) Install FRP                     ← auto-token + webServer blocks now included in templates
 2) Setup FRP Server                ← + bindAddr choice (0.0.0.0 / :: / private tunnel IP w/ validation)
 3) Setup FRP Client                ← + token paste-from-server, tls+encryption defaults, TCP+UDP toggle
 4) Advanced Configuration          ← unchanged (+ mirror of new file types)
 5) Show Status                     ← + GRE tunnels, turbo, zram, panel status
 6) Stop All Services               ← unchanged
 7) Optimization Utilities (Turbo)  ← was "Optimization Utilities": tunnel-turbo.service,
                                      ZRAM on/off, reduce_io, remove_logs (both kept)
 8) Remove FRP                      ← now also offers GRE/panel/turbo removal (each optional)
 9) Exit                            ← unchanged
10) GRE Tunnel Manager              ← create (6 inputs + defaults) / list+health / delete / mirror-print
11) Web Panel Manager               ← install (curl installer) / start / stop / port change / upgrade / uninstall / show one-time password
12) Backup / Restore                ← export / import (tar.gz, or ZIP via panel if installed)
13) Watchdog & Health               ← enable/disable, status, tail heal events, live latency (CLI ping table)
```

Non-interactive hooks added for scripting: `frp-manager gre create …`, `frp-manager panel install --port 9000`, etc.
(subcommand form bypasses menus; plain `frp-manager` = unchanged interactive menu).

Also fixed silently: multiple clients to different servers sharing a port no longer
collide (instance name prompt with old default retained); redundant `sudo` calls inside
root-only script removed.

---

## 12. Installer & release pipeline

- **`scripts/install.sh`** (the curl target): detect arch (amd64/arm64) → download
  `frp-panel_linux_<arch>.tar.gz` from GitHub Releases → install binary → write the
  systemd unit via **`frp-panel install-unit`** (the binary emits its own canonical
  embedded `frp-panel.service` — no second copy of the unit anywhere) →
  `systemctl enable --now` → open the panel port in UFW when the bind is not
  loopback → print access URLs and the one-time password hint. Flags:
  `--port 9000 --bind 0.0.0.0 --version latest --base URL`; pass
  `--bind 127.0.0.1` for loopback-only. `FRP_PANEL_RELEASE_BASE` overrides the
  download base like the CLI.
- **`scripts/build-release.sh`**: `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w"`
  for linux/amd64 + arm64; run `go vet` + `go test` first; package binary +
  install.sh per arch with a `.tar.gz.sha256` sidecar per tarball.
- **GitHub Actions**: `ci.yml` on every push/PR (`go vet`, `go test`, `shellcheck`,
  `bash -n`, `scripts/check-sync.sh`, cross-build sanity); `release.yml` on tag `v*`
  → sync gate → build → binary smoke (`version`, `verify`, `install-unit`) →
  GitHub Release with both tarballs + checksums (`softprops/action-gh-release`).
- **`scripts/vendor-web.sh`** pins the four vendored JS libraries by sha256
  (dev-time only; the checked-in files are what ships via go:embed).
- **Dev/testing on this Windows host**: Go cross-compiles natively (`GOOS=linux`);
  Linux-specific e2e via WSL2 or privileged systemd Docker (`debian:12`, map repo);
  `scripts/dev-up.sh` spins that container. GRE pair testable with `ip netns` namespaces.
  The dashboard was verified on the dev host with the real binary + a browser:
  login → forced password change → every view → wizard create/delete flows, with
  the SSE latency feed live (journalctl-dependent views degrade to a clear
  "stream lost — reconnecting" note without systemd).

---

## 13. Implementation phases

| Phase | Deliverable | Est. |
|---|---|---|
| P0 | Repo scaffolding, Go module, embed skeleton, `/api/health`, build script | 0.5 d |
| P1 | `frpconf` engine: TOML model, range parser, token gen, golden tests | 1–2 d |
| P2 | CLI upgrade (`frp-setup.sh`): new prompts (bindAddr/token/UDP), menu 10–13, GRE helper heredocs | 1 d |
| P3 | Panel core: bootstrap, auth, servers/clients CRUD, systemctl wrapper, `verify` hook, API tests (httptest) | 2–3 d |
| P4 | GRE: env model, `frp-gre`, units, mirror-config, API + CLI parity | 1–2 d |
| P5 | Turbo + ZRAM: `frp-turbo`, units, revert path, API + CLI | 1 d |
| P6 | Prober (ICMP/TCP RTT SSE), journal SSE, stats scraper + history | 2–3 d |
| P7 | Backup/restore (ZIP, zip-slip guard, selective import) + watchdog service | 1–2 d |
| P8 | Frontend: layout, login, dashboard, all pages, SSE wiring, dark theme polish | 2–3 d |
| P9 | Release pipeline, installer, README/quickstart (Iran↔Foreign topology guide), CHANGELOG | 1 d |

Total ≈ 2.5–3 weeks solo. Sequence P0→P9; each phase ends with runnable, testable state.
---

## 14. Risks & mitigations

| Risk | Mitigation |
|---|---|
| FRP version drift (TOML schema, `/api/status` shape) | Pin tested FRP version; tolerant stats parser + fixtures; `verify` gate before every write |
| Some KVM providers drop proto 47 (GRE) | GRE wizard pre-flight link test + counters check before enabling persistence |
| UDP-over-tcpMux edge cases on old FRP | Dual-TCP+UDP docs note: if UDP stalls, toggle mux off for that instance (one click) |
| iptables-nft vs legacy | Use `iptables` (nft compat) commands — identical semantics on all 3 target distros; `frp-gre` falls back to `NOTRACK` on old raw-table syntax |
| MSS black holes over GRE | `tcp_mtu_probing=1` in turbo + explicit MSS modes (clamp/1360/1240/1220) |
| Multi-instance webServer port collisions | 7500–7599 / 7400–7499 allocators with live port check |
| 1 GB RAM nodes | Go binary ~30 MB; compression off by default; ZRAM optional; GC cron preserved |
| Template-managed configs in panel UI | Detected + flagged; structured edit falls back to raw text editor |
| Panel attack surface | Same-origin only, strict CSP, whitelisted units/exec, rate-limited login, zip-slip guard, no token in localStorage |

---

## 15. Out of scope (future)

- TOTP/2FA login, multi-user roles
- Farsi (fa) translation + RTL
- nftables-native rule management
- Multiple-node federation (one panel steering several VPSes)
- WebSocket log multiplexing across nodes
