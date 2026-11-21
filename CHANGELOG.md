# Changelog

## v1.2.7 — editable GRE tunnels, deeper tuning + 3-way link diagnostics

### Added

- **Edit an existing GRE tunnel from the panel.** Every GRE row now has an
  *edit* action backed by `PUT /api/gre/{name}`. It updates both public IPs,
  both private CIDRs, `MTU`, `MSS_MODE` and `TXQUEUELEN`, writes a timestamped
  `.bak` of the old env and (by default) restarts `gre-tunnel@<name>`; a
  *Restart tunnel after save* checkbox defers the restart when unchecked.
  The name/interface stays immutable because it is the systemd instance.
- **`TXQUEUELEN` (default `1000`) end-to-end.** Applied with
  `ip link set dev <iface> txqueuelen`, persisted in `*.env`, rendered by the
  mirror config and both quick-setup payloads, parsed by the Go model and the
  `frp-manager gre create --txqueuelen` / `reverse {iran,foreign}
  --txqueuelen` flags, and pre-filled into the Foreign installer.
- **Three-part GRE link test.** `POST /api/gre/{name}/test` now returns
  `checks.gre` (10 fast pings: loss/RTT), `checks.mtu` (a DF
  `ping -M do -s <mtu-28>` acceptance probe) and `checks.public` (a baseline to
  `REMOTE_PUBLIC_IP`), while keeping the legacy top-level fields. The test
  modal renders each probe separately so protocol-47 loss can be told apart
  from a bad datacenter route or an MTU black hole.
- **Foreign Setup pre-fill.** The one-click Foreign installer shows the linked
  tunnel's `MTU` / `MSS` / `TXQ`, the raw-speed state and the effective
  `proxyBindAddr` with a public/unreachable verdict before generating the
  script.

### Changed

- **Full persisted zero-drop tuning** in `frp-gre`, `frp-turbo` and
  `FRP_FOREIGN_SETUP` (`/etc/sysctl.d/99-tunnel-turbo.conf`): fq + BBR,
  16 MB `rmem/wmem`, `tcp_rmem`/`tcp_wmem` to 16 MB, `netdev_max_backlog=16384`,
  `somaxconn=65535`, `tcp_max_syn_backlog=16384`,
  `tcp_slow_start_after_idle=0`, `tcp_mtu_probing=1`, `tcp_base_mss=1024`,
  `tcp_notsent_lowat=16384`, `ip_local_port_range=10240 65535`,
  `rp_filter=0` (all/default/interface) and `nf_conntrack_max=524288` only when
  conntrack is loaded. BBR is loaded now and at boot via `modules-load.d`.
- frpc warm pool raised `poolCount 10 → 15` (still `heartbeat 15/45`,
  `dial 10/30`, `loginFailExit=false`).
- `frps@`, `frpc@` and `gre-tunnel@` restart faster: `RestartSec=3s → 2s`
  (still `Restart=always`, `StartLimitIntervalSec=0`, `LimitNOFILE=1048576`).

### Verification

- `go test -count=1 ./...`, `go vet ./...`, `node --check …/app.js`,
  `bash -n scripts/install.sh`, `bash -n frp-setup.sh`,
  `scripts/check-sync.sh`, and `bash -n` on the generated
  `FRP_FOREIGN_SETUP` payload.
- New regression tests: `TestGREUpdate` and the expanded `TestGRELinkTest`
  (MTU probe + three check blocks).

## v1.2.6 — production fixes + GRE/FRP anti-disconnect hardening

### Fixed

- **Forwarded ports were unreachable behind a GRE bind.** When frps
  `bindAddr` is a specific address (the Iran GRE IP), FRP binds every forwarded
  user port to that same address, so `1.2.3.4:<port>` never accepted a
  connection. The suite now emits `proxyBindAddr = "0.0.0.0"` whenever
  `bindAddr` is not `""`, `0.0.0.0` or `::`: the panel wizard, `POST
  /api/servers`, the `frps` Edit modal (new field, defaulting to `0.0.0.0` for a
  GRE IP and preserved on structured edits) and `frp-manager` / `frp-setup.sh`.
- **`add tunnel "gre0" failed: File exists`.** Both `frp-gre up` and the
  Foreign installer now tear down any other keyless GRE interface already
  pointing at the same remote public IP before `ip tunnel add`.
- **Raw speed is now the default.** The Reverse Wizard (Foreign step), the
  Foreign Setup generator and the Client Create modal start with raw speed ON
  (`tls.enable=false`, per-proxy encryption/compression off, `tcpMux=false`);
  it stays toggleable.

### Hardened

- Default GRE MTU lowered `1400 → 1320` (GRE adds 24 bytes and 1400
  black-holes on some Iran ISP/MPLS/PPPoE paths).
- Idempotent anti-disconnect rules in `frp-gre` and the Foreign installer:
  `TCPMSS --set-mss 1220` on `POSTROUTING -o <iface>` (host-originated SYNs
  bypass `FORWARD`) plus the `-i` direction, `NOTRACK` for protocol 47 on
  `PREROUTING`/`OUTPUT`, and `rp_filter=0` / `tcp_mtu_probing=1` /
  `tcp_base_mss=1024`. The POSTROUTING rule is purged on `down`.
- Faster failure detection without flapping: frpc `poolCount=10`,
  `heartbeatInterval=15`, `heartbeatTimeout=45`, `dialServerTimeout=10`,
  `dialServerKeepalive=30`; frps `heartbeatTimeout=45`, `tcpKeepalive=30`;
  `tcpMux=false` and `loginFailExit=false` kept.
- `frps@`, `frpc@` and `gre-tunnel@` units use `StartLimitIntervalSec=0`,
  `Restart=always` and `RestartSec=3s` across `scripts/install.sh`,
  `frp-setup.sh`, the embedded unit writers and the Foreign installer.

### Verification

- `go test -count=1 ./...`, `go vet ./...`, `node --check …/app.js`,
  `bash -n scripts/install.sh`, `bash -n frp-setup.sh`,
  `scripts/check-sync.sh`, and `bash -n` on the generated
  `FRP_FOREIGN_SETUP` payload.
- New regression tests: `TestServerProxyBindAddrForPrivateBindAddr` and
  `TestServerProxyBindAddrWildcard`.

## v1.2.5 — reuse an existing GRE tunnel for a repeated public pair

### Fixed

- **No more `add tunnel "gre0" failed: File exists`.** Both the Iran and the
  Foreign wizard (and the `frp-manager reverse` CLI) now scan the live kernel
  tunnels (`ip -d tunnel show`) in addition to `/root/frp/gre/*.env`. When the
  requested `(local_public, remote_public)` pair already has a GRE interface —
  exact match, mirrored orientation, or the same remote public IP after the
  local public IP changed — that interface and its existing `10.100.<n>.0/30`
  are reused instead of allocating a duplicate `gt12`. A clear warning is
  returned: `reused existing GRE tunnel gt11 for 206.1.100.7`.
- **A live-only tunnel is honoured.** A GRE interface created manually or by an
  interrupted wizard run has no `.env`; it is still discovered, and its private
  `/30` is read from `ip -o -4 addr show dev <iface>`. If that tunnel has no
  IPv4 `/30`, the wizard now fails with an actionable message rather than
  creating a duplicate.
- The Foreign wizard previously validated the mirrored `/30` before choosing
  the reused interface; the conflict check now runs against the selected
  interface, so a legitimate reuse is never rejected.

### CLI

- `reverse_live_tunnels`, `reverse_iface_private`, `reverse_iface_own`,
  `reverse_iface_reusable` and `reverse_find_reusable_iface` mirror the panel
  logic. `frp-manager reverse --iran|--foreign` prints
  `reused existing GRE tunnel gt11 for <remote-ip> (10.100.<n>.0/30)` and keeps
  the established `/30`.

### Verification

- `go test -count=1 ./...`, `go vet ./...`, `node --check …/app.js`,
  `bash -n scripts/install.sh`, `bash -n frp-setup.sh`,
  `scripts/check-sync.sh`.
- New regression tests: `TestParseLiveGRETunnels`, `TestPeerPrivateCIDR`,
  `TestWizardIranReusesLiveTunnelForRemote`,
  `TestWizardIranReusesTunnelWhenLocalPublicChanged` and
  `TestWizardForeignReusesLiveTunnelForRemote`.

## v1.2.4 — systemctl `--now` fix + paste-friendly Foreign payload

### Fixed

- **`systemctl … --now` no longer reaches the host.** `svc.Systemctl` rejects
  every argument that starts with `-` (a deliberate injection guard), so the
  `enable --now` / `disable --now` shorthand used by the wizard, CRUD, GRE,
  Turbo and Watchdog handlers failed at runtime with
  `svc: systemctl arguments may not start with '-'`. Every call now issues the
  explicit `enable` + `restart` (or `disable` + `stop`) pair through the new
  `enableUnitNow` / `disableUnitNow` helpers in `services.go`. This fixes the
  Reverse GRE+FRP wizard on both the Iran (frps, gre-tunnel) and Foreign
  (frpc) roles, plus instance create/delete and Turbo/Watchdog toggles.
- **Mirror payload accepts the generated installer.** Pasting the
  `sudo bash <<'FRP_FOREIGN_SETUP' …` block from Option 1 into the Foreign
  panel's “Mirror payload from the Iran node” box now works: shell lines are
  ignored and the embedded `KEY='VALUE'` assignments are extracted (with
  quotes stripped). Both the canonical names (`LOCAL_PUBLIC_IP`,
  `CONTROL_PORT`) and the installer names (`FOREIGN_PUBLIC_IP`,
  `IRAN_PUBLIC_IP`, `SERVER_PORT`) are understood, heredoc `${…}` expansions
  are skipped so concrete values win, and `PORTS` supplies the local-port list
  when the form leaves it blank.
- The generated installer now prints `PROTOCOL`, `TOKEN` and `PORTS` in its
  header, so the whole Option 1 script is also a complete Option 2 payload.

### UI

- The Iran wizard result now labels the two hand-off paths explicitly:
  **Option 1 — Run in Foreign SSH Terminal (no panel needed)** and
  **Option 2 — Paste into Foreign Web Panel (Mirror Payload)**.
- The mirror textarea hint notes that both formats are accepted.

### Verification

- `go test -count=1 ./...`, `go vet ./...`, `node --check …/app.js`,
  `bash -n scripts/install.sh`, `bash -n frp-setup.sh`,
  `scripts/check-sync.sh`.
- New regression tests: `TestWizardRolesNeverPassNowFlag`,
  `TestParseMirrorPayloadAcceptsForeignInstaller`,
  `TestParseMirrorPayloadStillRejectsGarbage`,
  `TestWizardForeignAcceptsInstallerPaste`. The API test fake now mirrors the
  production leading-dash guard, so any reintroduced `--now` fails the suite.

## v1.2.3 — mikeesierrah profile, full editors + one-click Foreign installer

### Config profile (`frpconf`)

- Generated/edited configs now match the proven `mikeesierrah/frp-script`
  profile exactly:
  - **frps**: `heartbeatTimeout = 90`, `maxPoolCount = 65535`, `tcpMux = false`,
    `tcpMuxKeepaliveInterval = 10`, `tcpKeepalive = 120`, QUIC
    `10 / 30 / 100000`, `auth.method = "token"`.
  - **frpc**: `loginFailExit = false`, `protocol = "tcp"`, `tcpMux = false`,
    `tcpMuxKeepaliveInterval = 10`, `dialServerTimeout = 10`,
    `dialServerKeepalive = 120`, `poolCount = 20`, `heartbeatInterval = 30`,
    `heartbeatTimeout = 90`, `tls.enable = false`, QUIC `10 / 30 / 100000`,
    per-proxy `useEncryption = false`, `useCompression = false`.
- Ports are rendered with FRP's compact
  `{{- range $_, $v := parseNumberRangePair "..." "..." }}` template (TCP and,
  when selected, UDP). Existing plain `[[proxies]]` files and range templates
  are both parsed structurally, and ranges such as `22,6000-6006,8443` are
  editable in the form without switching to Raw TOML.
- Editing a range template keeps the compact layout; adding/removing individual
  proxy rules converts that client to plain blocks so the result is exact.

### Editing

- The frps `bindAddr` field is now a free-form input backed by a datalist, so
  the exact current value (`0.0.0.0`, `::`, a GRE IP, or any custom address)
  round-trips unchanged. Opening `server-7018` with `bindAddr = "0.0.0.0"` no
  longer shows or saves `::`.
- The frps editor exposes every transport tunable: `bindAddr`, `bindPort`,
  `auth.token` (generate/copy), protocol (QUIC/KCP/plain TCP), `tcpMux`,
  `tcpMuxKeepaliveInterval`, `heartbeatTimeout`, `tcpKeepalive`,
  `maxPoolCount` and the QUIC `keepalivePeriod` / `maxIdleTimeout` /
  `maxIncomingStreams` block.
- The frpc editor exposes `serverAddr`, `serverPort`, `protocol`, `tcpMux`,
  `tcpMuxKeepaliveInterval`, `dialServerTimeout`, `dialServerKeepalive`,
  `poolCount`, `heartbeatInterval`, `heartbeatTimeout`, `loginFailExit`,
  `tls.enable`, the QUIC block, forwarded ports / ranges / `proto` / `localIP`,
  per-proxy encryption and compression, plus the Raw Speed preset.
- Both editors have **Restart service after save** (checked by default when the
  unit is active); unchecking writes the file without touching the running unit.
- Both editors keep a **Raw TOML** shortcut, and unknown keys are still
  preserved on structured saves.

### Turbo → System utilities

- **FRP auto-GC cron** — one click installs/verifies
  `0 */3 * * * pkill -10 -x frpc; pkill -10 -x frps` in root's crontab (Go GC
  without dropping connections) and shows an active/missing badge.
- **Volatile logs** — disables rsyslog and sets journald
  `Storage=volatile`, `SystemMaxUse=50M`, `SystemKeepFree=5M`.
- **Clear all system logs** — `journalctl --vacuum-time=1s`, truncates
  `/var/log/*.log`, `wtmp`, `btmp`, and deletes rotated `.gz` / `.1`–`.9` logs.
- All three are available in the Web UI, the JSON API
  (`POST /api/system/turbo {action}`), and the CLI
  (`frp-manager turbo gc-cron|volatile-logs|clear-logs`).

### Foreign node provisioning

- Every frps row has a **Foreign Setup** action, and the Iran wizard result
  includes a **1-click Foreign setup** block. It takes the Foreign public IP,
  ports/ranges (`8989` default), TCP/`both`, Local IP, and an optional GRE
  `/30` (blank = auto-allocate the next free `gtNN` / `10.100.NN.0/30`).
- The generated block is entirely self-contained (root SSH only): it installs
  the GRE helper + systemd units, creates the mirrored tunnel (`ip tunnel add
  … mode gre … ttl 255`, MTU 1400, `/30` address, `rp_filter=0`, NOTRACK proto
  47, TCPMSS clamp), downloads `frpc` and installs `frpc@.service` when missing,
  writes `/root/frp/client/<name>.toml` with the Iran GRE IP / port / token /
  mikeesierrah transport settings and the compact range template, applies
  BBR+fq and the 3h GC cron, enables both units and verifies with `ping` +
  `systemctl is-active`.
- Copy works on plain `http://<ip>:9000` through the textarea +
  `execCommand('copy')` fallback already used elsewhere in the panel.

## v1.2.2 — faster, reliable edit + quick-setup workflow

### Editing

- `edit` now opens reliably for both frps and frpc. Template or unparseable
  configs automatically open the raw TOML editor instead of doing nothing.
- Valid TOML configs with extra keys (`[log]`, `transport.tls`, HTTP/HTTPS
  vhosts, plugins, metadata, …) are structurally editable: only managed fields
  are rewritten and every unknown key is merged back into the file.
- Configs using `bindAddr = "::"`, `tcpMuxKeepaliveInterval`, `quic.*` and
  `tls.enable` no longer get stuck behind `advanced — raw edits only`.
- The table's `toml` action is a normal button like `edit`/`retoken`.

### UI / status

- Sidebar version strips any leading `v` (`1.2.2`, `v1.2.2`, `vv1.2.2` all
  display as `v1.2.2`).
- Missing/not-found/inactive units display `stopped`, and disabled units
  display `disabled`, instead of `unknown`.

### Quick setup & clients

- Reverse wizard accepts a custom token (with one-click generation) and lets
  frps bind to the GRE IP, `::`, or `0.0.0.0`.
- New **Raw speed** toggle sets `tls.enable=false`, `useEncryption=false`,
  compression off and `tcpMux=false` for already-encrypted inner protocols.
- Clients and the wizard use a comma-separated port list
  (`8989,8443,2053`) as the primary port editor; editing a client replaces the
  forwarded list in place.

### Installer

- `scripts/install.sh` now runs `systemctl enable frp-panel` followed by
  `systemctl restart frp-panel`, so upgrades actually restart an already-running
  unit.

## v1.2.1 — public panel access by default

- The panel bootstraps `bind = "0.0.0.0"` (all interfaces) instead of
  `127.0.0.1`, so a fresh install is reachable at
  `http://<public-ip>:9000`. `--bind 127.0.0.1` still gives loopback-only.
- `scripts/install.sh` and `frp-manager panel install|port` run
  `ufw allow <port>/tcp` (best-effort) when the bind is not loopback and
  `ufw` is installed. The curl installer advertises the public URL.
- Existing installs keep the bind already in their `panel.toml`; only fresh
  bootstraps use `0.0.0.0`, and a missing/blank bind falls back to it.

## v1.2.0 — Telegram alerts and multi-tunnel wizard

### Telegram alerts (`frp-watchdog`)

- Optional `TG_BOT_TOKEN`, `TG_CHAT_ID` and `TG_API_BASE` in
  `/etc/frp-panel/watchdog.env`; every heal posts a plain-text alert
  (host/layer/unit/reason/consecutive/result) from a background
  `curl --max-time 5`, so delivery can never stall the heal loop.
- Watchdog UI + API: token input (masked on `GET`, preserved on blank `POST`),
  chat ID, API base (Worker proxy for blocked hosts) and
  `POST /api/watchdog/test-telegram` with a **Send test alert** button.
- `frp-manager watchdog telegram|test-telegram`.
- Bot token redacted in secret-free backup exports and cleared on import.

### Multi-tunnel reverse wizard

- `GET /api/wizard/gre-frp/defaults` returns the next free interface, `/30`
  subnet and control port (scans envs, live links, frps configs and
  `/proc/net/tcp`); the wizard pre-fills the Iran form.
- `POST /api/wizard/gre-frp` and `frp-manager reverse` auto-allocate on
  conflict (`gt11`→`gt12`, `10.100.111.0/30`→`10.100.112.0/30`,
  `7025`→`7026`) and report each switch in `warnings`.
- Foreign exits rename only their local interface when it is already taken,
  keeping the mirrored `/30` intact.

## v1.0.0 — the complete Tunnel & FRP Management Suite

First tagged release: `frp-manager` (bash CLI) + `frp-panel` (Go web panel,
single static binary with the dashboard embedded) operating on the exact
same configs, GRE envs and systemd units — one product, two faces.

### Web panel (`frp-panel`, port 9000)

- **Dashboard** — live service status cards for every suite unit
  (`frps@*`, `frpc@*`, `gre-tunnel@*`, `tunnel-turbo`, `frp-zram`,
  `frp-watchdog`, `frp-panel`) with start/stop/restart, the live
  ICMP/TCP-RTT latency chart (SSE, uPlot), active connections and
  bandwidth totals scraped from FRP's webServer.
- **Servers & Clients managers** — create/edit/delete with the 32-char
  token generator + copy, bindAddr selector (dual-stack / IPv4 / GRE
  tunnel IPs), TLS + encryption defaults on, single TCP+UDP emission
  toggle per port range, per-instance proxy tables, and a raw TOML
  editor fallback for advanced/template configs.
- **GRE tunnel manager** — create/delete with auto-suggested /30
  subnets, live link test (RTT/loss through the interface), and the
  one-click mirror-config modal for the peer node.
- **Turbo & ZRAM** — one-click apply/revert of the persistent BBR+fq
  sysctl drop-in, ZRAM on/off with size + algorithm.
- **Live logs** — streaming `journalctl -f` viewer over SSE with unit
  filter, pause/clear/follow and level coloring; strictly whitelisted
  to suite units server-side.
- **Stats** — per-instance active connections, per-proxy traffic and a
  24 h history chart.
- **Backup & restore** — ZIP export with a secrets toggle, drag-and-drop
  restore with zip-slip/path-traversal protection, selective
  categories, automatic credential regeneration for redacted secrets.
- **Watchdog** — threshold/cooldown/interval tuning with the heal-event
  log.

Everything above is also scriptable through the REST+SSE API under
`/api` (see README for the surface).

### Security posture

- Sessions are bcrypt + JWT cookies (`HttpOnly`, `SameSite=Strict`),
  login rate-limited per IP with exponential lockout, forced password
  change on first login, `frp-panel reset-password` escape hatch.
- Every config write passes the `frps/frpc verify -c` gate (internal
  parser fallback when the binary is absent) and takes a `.bak-<ts>`
  copy first — bad TOML never reaches systemd.
- Strict same-origin CSP, vendored frontend (zero CDN calls), unit and
  exec whitelists on every systemctl/exec surface.

### CLI (`frp-setup.sh` → `/usr/local/bin/frp-manager`)

- Menu items 1–9 keep their exact numbers and flows; 10–13 add the GRE
  tunnel manager, web panel manager, backup/restore and watchdog views.
- Auto-generated 32-char `auth.token` (the static default is gone),
  `bindAddr` choice for servers, dual TCP+UDP emission for clients.
- Non-interactive hooks: `frp-manager gre create …`, `panel install`,
  `backup export|import`, `turbo …`, `watchdog …` for scripting.

### Install & upgrade

- One-line installer with arch detection, the canonical unit written
  from inside the binary (`frp-panel install-unit`), access URL
  printing and the one-time password hint:
  `curl -fsSL https://raw.githubusercontent.com/frp-suite/frp-panel/main/scripts/install.sh | bash`
- `scripts/build-release.sh` produces `frp-panel_linux_{amd64,arm64}.tar.gz`
  with sha256 sidecars; `scripts/vendor-web.sh` pins the vendored JS
  libraries; `scripts/check-sync.sh` guards the CLI ↔ panel asset
  invariant in CI.

### Verified

- 142 Go test functions across config engine, API handlers (httptest,
  including SSE over real connections), backup guards, watchdog/turbo
  env parity, plus `go vet`, `bash -n`, `shellcheck`, heredoc↔asset sync
  (10/10) and Linux amd64/arm64 cross-builds.
- The dashboard was exercised end-to-end in a real browser: login →
  forced password change → all nine views → wizard create → token
  modal → delete flow.
