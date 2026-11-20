# Changelog

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
