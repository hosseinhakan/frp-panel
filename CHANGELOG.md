# Changelog

## v1.2.3 — full transport editors + one-click Foreign installer

### Editing

- The frps `bindAddr` field is now a free-form input backed by a datalist, so
  the exact current value (`0.0.0.0`, `::`, a GRE IP, or any custom address)
  round-trips unchanged. Opening `server-7018` with `bindAddr = "0.0.0.0"` no
  longer shows or saves `::`.
- The frps editor exposes every transport tunable: `bindAddr`, `bindPort`,
  `auth.token` (generate/copy), protocol (QUIC/KCP/none), `tcpMux`,
  `tcpMuxKeepaliveInterval`, `heartbeatTimeout`, `tcpKeepalive`,
  `maxPoolCount` and the QUIC `keepalivePeriod` / `maxIdleTimeout` /
  `maxIncomingStreams` block.
- The frpc editor exposes `serverAddr`, `serverPort`, `protocol`, `tcpMux`,
  `tcpMuxKeepaliveInterval`, `dialServerTimeout`, `dialServerKeepalive`,
  `poolCount`, `heartbeatInterval`, `heartbeatTimeout`, `loginFailExit`,
  `tls.enable`, forwarded ports / `proto` / `localIP`, per-proxy encryption and
  compression, plus the Raw Speed preset.
- Both editors have **Restart service after save** (checked by default when the
  unit is active); unchecking writes the file without touching the running unit.
- Both editors keep a **Raw TOML** shortcut, and unknown keys are still
  preserved on structured saves.

### Foreign node provisioning

- Every frps row now has a **foreign** action, and the Iran wizard result
  includes a **1-click Foreign setup** block. It takes the Foreign public IP,
  forwarded ports (`8989` default) and a Raw Speed toggle.
- The generated block is entirely self-contained (root SSH only): it installs
  the GRE helper + systemd units, creates the mirrored tunnel (`ip tunnel add
  … mode gre … ttl 255`, MTU 1400, `/30` address, `rp_filter=0`, NOTRACK proto
  47, TCPMSS clamp), downloads `frpc` when missing, writes
  `/root/frp/client/<name>.toml` with the Iran GRE IP / port / token / exact
  transport settings, enables both units and verifies with `ping` +
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
