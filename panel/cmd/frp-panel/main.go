// frp-panel — Web Panel backend for the FRP Tunnel Suite (Go, single binary).
//
// Subcommands:
//
//	serve          start the API + embedded web UI (bootstraps panel.toml on
//	               first run and prints a one-time admin password)
//	verify         parse an frps/frpc TOML config and print a summary
//	reset-password generate a new one-time admin password
//	install-unit   write the canonical embedded frp-panel.service
//	version        print the build version
//
// See docs/ARCHITECTURE.md for the full roadmap.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/frp-suite/panel/internal/api"
	"github.com/frp-suite/panel/internal/assets"
	"github.com/frp-suite/panel/internal/cfg"
	"github.com/frp-suite/panel/internal/frpconf"
	"github.com/frp-suite/panel/internal/svc"
)

// version is set at build time: -ldflags "-X main.version=...".
var version = "dev"

const usageText = `frp-panel — Web Panel backend for the FRP Tunnel Suite

Usage:
  frp-panel serve  [--config PATH] [--bind ADDR] [--port N]
  frp-panel verify --kind server|client --file PATH
  frp-panel reset-password [--config PATH]
  frp-panel version

serve:
  --config   panel config path            (default /etc/frp-panel/panel.toml)
  --bind     listen address override       (default: panel.toml [server] bind, 0.0.0.0)
  --port     listen port override          (default: panel.toml [server] port)
  First run with no panel.toml bootstraps it and prints a ONE-TIME admin
  password to the console (change it after first login).
verify:
  --kind     config kind: server or client (required)
  --file     path to the TOML config       (required)
reset-password:
  --config   panel config path             (default /etc/frp-panel/panel.toml)
  Generates a new one-time admin password and prints it (use when the
  password is lost; a first login forces changing it).
install-unit:
  --unit-dir systemd unit directory        (default /etc/systemd/system)
  Writes the canonical embedded frp-panel.service (same bytes the CLI's
  heredoc installs). Run systemctl daemon-reload afterwards. Used by
  scripts/install.sh so the unit has exactly one source of truth.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	case "reset-password":
		err = runResetPassword(os.Args[2:])
	case "install-unit":
		err = runInstallUnit(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("frp-panel", version)
	case "help", "-h", "--help":
		fmt.Print(usageText)
	default:
		fmt.Fprintf(os.Stderr, "frp-panel: unknown command %q\n\n", os.Args[1])
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "frp-panel:", err)
		os.Exit(1)
	}
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/frp-panel/panel.toml", "panel config path")
	bind := fs.String("bind", "", "listen address override")
	port := fs.Int("port", 0, "listen port override")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Load-or-bootstrap panel.toml (first run prints a one-time password).
	c, oneTime, err := cfg.Load(*cfgPath)
	if err != nil {
		return err
	}
	if oneTime != "" {
		printOneTimePassword(c.Auth.AdminUsername, oneTime)
	}

	addr := listenAddr(*bind, *port, c)
	runner := svc.SystemdRunner{}
	srv := api.New(version, c, *cfgPath, svc.DefaultPaths(), runner)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Background latency prober (GRE peers + frpc control channels); it
	// stops with the serve context below.
	srv.StartMonitor(ctx)

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	fmt.Printf("frp-panel %s listening on http://%s\n", version, addr)
	err = httpSrv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// printOneTimePassword shows first-run credentials once — they exist only
// as a bcrypt hash afterwards.
func printOneTimePassword(user, password string) {
	line := "==================================================================="
	fmt.Println(line)
	fmt.Println(" First run: panel admin credentials generated.")
	fmt.Println()
	fmt.Printf("     username: %s\n", user)
	fmt.Printf(" one-time password: %s\n", password)
	fmt.Println()
	fmt.Println(" This password is shown ONCE and never stored in clear text.")
	fmt.Println(" Change it after first login (the panel will insist).")
	fmt.Println(line)
}

func runResetPassword(args []string) error {
	fs := flag.NewFlagSet("reset-password", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/frp-panel/panel.toml", "panel config path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	password, err := cfg.ResetPassword(*cfgPath)
	if err != nil {
		return err
	}
	printOneTimePassword("admin", password)
	fmt.Println("The password change is forced on first login.")
	return nil
}

// runInstallUnit writes the canonical embedded frp-panel.service into the
// systemd unit directory (only when the bytes differ). install.sh calls this
// so the unit file ships from the binary itself — the same canonical asset
// the CLI's heredoc installs and check-sync.sh guards.
func runInstallUnit(args []string) error {
	fs := flag.NewFlagSet("install-unit", flag.ExitOnError)
	unitDir := fs.String("unit-dir", "/etc/systemd/system", "systemd unit directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	path, changed, err := writePanelUnit(*unitDir)
	if err != nil {
		return err
	}
	if changed {
		fmt.Printf("installed %s — run: systemctl daemon-reload\n", path)
	} else {
		fmt.Printf("%s already up to date\n", path)
	}
	return nil
}

// writePanelUnit drops the embedded canonical frp-panel.service into
// unitDir, 0644, unless the existing file is byte-identical. Returns the
// destination path and whether it changed.
func writePanelUnit(unitDir string) (string, bool, error) {
	raw, err := assets.FS.ReadFile("systemd/frp-panel.service")
	if err != nil {
		return "", false, fmt.Errorf("embedded frp-panel.service missing: %w", err)
	}
	dst := filepath.Join(unitDir, "frp-panel.service")
	if old, rerr := os.ReadFile(dst); rerr == nil && bytes.Equal(old, raw) {
		return dst, false, nil
	}
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		return "", false, err
	}
	if err := os.WriteFile(dst, raw, 0o644); err != nil {
		return "", false, err
	}
	return dst, true, nil
}

// listenAddr resolves flags → panel.toml → defaults.
func listenAddr(bind string, port int, c *cfg.Config) string {
	if bind == "" {
		bind = c.Server.Bind
	}
	if port <= 0 {
		port = c.Server.Port
	}
	if bind == "" {
		bind = cfg.DefaultBind
	}
	if port <= 0 {
		port = 9000
	}
	return net.JoinHostPort(bind, strconv.Itoa(port))
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	kind := fs.String("kind", "", "config kind: server or client")
	file := fs.String("file", "", "path to the TOML config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *kind == "" || *file == "" {
		return errors.New("verify: both --kind and --file are required")
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		return err
	}

	switch *kind {
	case "server":
		cfg, err := frpconf.ParseServer(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", *file, err)
		}
		style, unknown, _ := frpconf.Classify(raw, frpconf.KindServer)
		fmt.Printf("ok: server config %s (style=%s%s)\n", *file, style, styleSuffix(style, unknown))
		fmt.Printf("  bindAddr     = %s\n", cfg.BindAddr)
		fmt.Printf("  bindPort     = %d\n", cfg.BindPort)
		fmt.Printf("  protocol     = %s\n", serverProtocol(cfg))
		fmt.Printf("  token        = %s\n", tokenSummary(cfg.Auth.Token))
		fmt.Printf("  webServer    = %s\n", webSummary(cfg.WebServer))
	case "client":
		cfg, err := frpconf.ParseClient(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", *file, err)
		}
		style, unknown, _ := frpconf.Classify(raw, frpconf.KindClient)
		tcp, udp := 0, 0
		for _, p := range cfg.Proxies {
			if p.Type == "udp" {
				udp++
			} else {
				tcp++
			}
		}
		fmt.Printf("ok: client config %s (style=%s%s)\n", *file, style, styleSuffix(style, unknown))
		fmt.Printf("  server       = %s:%d\n", cfg.ServerAddr, cfg.ServerPort)
		fmt.Printf("  transport    = %s, tls=%t, mux=%t\n", cfg.Transport.Protocol, cfg.Transport.TLS.Enable, cfg.Transport.TCPMux)
		fmt.Printf("  token        = %s\n", tokenSummary(cfg.Auth.Token))
		fmt.Printf("  webServer    = %s\n", webSummary(cfg.WebServer))
		fmt.Printf("  proxies      = %d (tcp=%d udp=%d)\n", len(cfg.Proxies), tcp, udp)
	default:
		return fmt.Errorf("verify: unknown kind %q (want server|client)", *kind)
	}
	return nil
}

func serverProtocol(c *frpconf.ServerConfig) string {
	switch {
	case c.QUICBindPort > 0:
		return "quic"
	case c.KCPBindPort > 0:
		return "kcp"
	default:
		return "tcp"
	}
}

func tokenSummary(tok string) string {
	if tok == "" {
		return "NOT SET"
	}
	return fmt.Sprintf("set (%d chars)", len(tok))
}

func webSummary(w frpconf.WebServer) string {
	if !w.Enabled() {
		return "disabled"
	}
	return fmt.Sprintf("%s:%d (user %s)", w.Addr, w.Port, w.User)
}

func styleSuffix(style frpconf.Style, unknown string) string {
	if style == frpconf.StyleAdvanced && unknown != "" {
		return fmt.Sprintf(", first unknown key: %s", unknown)
	}
	return ""
}
