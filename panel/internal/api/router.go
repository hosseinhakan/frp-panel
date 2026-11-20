// Package api exposes the panel's HTTP surface.
//
// P3/P4: bcrypt+JWT cookie auth with rate-limited login, servers/clients
// CRUD over the same TOML files the bash CLI edits (with the frps/frpc
// verify gate and .bak backups on every write), the systemctl wrapper and
// the GRE tunnel manager. Monitoring/SSE/backup endpoints land in P6/P7 —
// see docs/ARCHITECTURE.md §5.4.
package api

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"sync"
	"time"

	"github.com/frp-suite/panel/internal/cfg"
	"github.com/frp-suite/panel/internal/prober"
	"github.com/frp-suite/panel/internal/stats"
	"github.com/frp-suite/panel/internal/svc"
	"github.com/frp-suite/panel/web"
)

// Server holds panel-wide state.
type Server struct {
	Version string
	started time.Time
	webFS   fs.FS

	cfg     *cfg.Config
	cfgPath string
	cfgMu   sync.Mutex // guards cfg mutations + saves (password change)

	paths   svc.Paths
	runner  svc.Runner
	prober  *prober.Prober
	scraper *stats.Scraper

	limiter *loginLimiter

	// now is swappable so tests can time-travel sessions.
	now func() time.Time
}

// New builds a Server. Version is the build version string; c is the loaded
// panel config (with cfgPath for password changes), paths locates the host
// files, runner is the systemctl/exec gateway.
func New(version string, c *cfg.Config, cfgPath string, paths svc.Paths, runner svc.Runner) *Server {
	sub, err := fs.Sub(web.FS, "static")
	if err != nil { // cannot happen: embedded FS always contains static/
		panic(err)
	}
	s := &Server{
		Version: version,
		started: time.Now(),
		webFS:   sub,
		cfg:     c,
		cfgPath: cfgPath,
		paths:   paths,
		runner:  runner,
		limiter: newLoginLimiter(),
		now:     time.Now,
	}
	s.prober = prober.New(prober.DefaultInterval, s.runnerPing, tcpProbe, s.now, s.probeTargets)
	s.scraper = stats.New(nil, time.Now)
	return s
}

// Routes assembles the HTTP handler.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// --- public ---
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/version", s.handleVersion)
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)

	// --- session lifecycle (auth) ---
	mux.HandleFunc("POST /api/auth/logout", s.authed(s.handleLogout))
	mux.HandleFunc("GET /api/auth/me", s.authed(s.handleMe))
	mux.HandleFunc("POST /api/auth/password", s.authed(s.handleChangePassword))

	// --- frps servers ---
	mux.HandleFunc("GET /api/servers", s.authed(s.handleServersList))
	mux.HandleFunc("POST /api/servers", s.authed(s.handleServersCreate))
	mux.HandleFunc("GET /api/servers/{name}", s.authed(s.handleServerGet))
	mux.HandleFunc("PUT /api/servers/{name}", s.authed(s.handleServerUpdate))
	mux.HandleFunc("DELETE /api/servers/{name}", s.authed(s.handleServerDelete))
	mux.HandleFunc("POST /api/servers/{name}/token/regenerate", s.authed(s.handleServerTokenRegenerate))
	mux.HandleFunc("POST /api/servers/{name}/foreign-script", s.authed(s.handleServerForeignScript))
	mux.HandleFunc("GET /api/servers/{name}/raw", s.authed(s.handleServerRawGet))
	mux.HandleFunc("PUT /api/servers/{name}/raw", s.authed(s.handleServerRawPut))

	// --- frpc clients ---
	mux.HandleFunc("GET /api/clients", s.authed(s.handleClientsList))
	mux.HandleFunc("POST /api/clients", s.authed(s.handleClientsCreate))
	mux.HandleFunc("GET /api/clients/{name}", s.authed(s.handleClientGet))
	mux.HandleFunc("PUT /api/clients/{name}", s.authed(s.handleClientUpdate))
	mux.HandleFunc("DELETE /api/clients/{name}", s.authed(s.handleClientDelete))
	mux.HandleFunc("POST /api/clients/{name}/proxies", s.authed(s.handleClientProxiesAdd))
	mux.HandleFunc("PUT /api/clients/{name}/proxies", s.authed(s.handleClientProxiesReplace))
	mux.HandleFunc("DELETE /api/clients/{name}/proxies", s.authed(s.handleClientProxiesDelete))
	mux.HandleFunc("GET /api/clients/{name}/raw", s.authed(s.handleClientRawGet))
	mux.HandleFunc("PUT /api/clients/{name}/raw", s.authed(s.handleClientRawPut))

	// --- systemctl wrapper ---
	mux.HandleFunc("GET /api/services", s.authed(s.handleServicesList))
	mux.HandleFunc("POST /api/services/{unit}/action", s.authed(s.handleServiceAction))

	// --- GRE tunnel manager ---
	mux.HandleFunc("GET /api/gre", s.authed(s.handleGREList))
	mux.HandleFunc("POST /api/gre", s.authed(s.handleGRECreate))
	mux.HandleFunc("GET /api/gre/{name}", s.authed(s.handleGREGet))
	mux.HandleFunc("DELETE /api/gre/{name}", s.authed(s.handleGREDelete))
	mux.HandleFunc("GET /api/gre/{name}/mirror", s.authed(s.handleGREMirror))
	mux.HandleFunc("POST /api/gre/{name}/test", s.authed(s.handleGRETest))

	// --- FRP over GRE Reverse quick-setup wizard (Iran entry + Foreign exit) ---
	mux.HandleFunc("GET /api/wizard/gre-frp/defaults", s.authed(s.handleWizardDefaults))
	mux.HandleFunc("POST /api/wizard/gre-frp", s.authed(s.handleWizardGREFRP))

	// --- turbo (kernel tuning + ZRAM) ---
	mux.HandleFunc("GET /api/system/turbo", s.authed(s.handleTurboGet))
	mux.HandleFunc("POST /api/system/turbo", s.authed(s.handleTurboPost))

	// --- live monitoring ---
	mux.HandleFunc("GET /api/monitor/latency", s.authed(s.handleLatency))
	mux.HandleFunc("GET /api/monitor/latency/stream", s.authed(s.handleLatencyStream))
	mux.HandleFunc("GET /api/logs/units", s.authed(s.handleLogUnits))
	mux.HandleFunc("GET /api/logs/stream", s.authed(s.handleLogStream))
	mux.HandleFunc("GET /api/stats", s.authed(s.handleStats))

	// --- backup / restore ---
	mux.HandleFunc("GET /api/backup/export", s.authed(s.handleBackupExport))
	mux.HandleFunc("POST /api/backup/import", s.authed(s.handleBackupImport))

	// --- watchdog ---
	mux.HandleFunc("GET /api/watchdog", s.authed(s.handleWatchdogGet))
	mux.HandleFunc("POST /api/watchdog", s.authed(s.handleWatchdogPost))
	mux.HandleFunc("POST /api/watchdog/test-telegram", s.authed(s.handleWatchdogTestTelegram))

	// --- embedded frontend (Alpine.js + HTMX dashboard) ---
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(s.webFS))))
	mux.HandleFunc("GET /{$}", s.handlePage("pages/index.html"))
	mux.HandleFunc("GET /login", s.handlePage("pages/login.html"))
	mux.HandleFunc("/", s.handleNotFound)

	return secureHeaders(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"version":        s.Version,
		"uptime_seconds": int(time.Since(s.started).Seconds()),
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"version": s.Version})
}

func (s *Server) handlePage(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := web.FS.ReadFile(name)
		if err != nil {
			http.Error(w, "page not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
	}
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.Path) >= 4 && r.URL.Path[:4] == "/api" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	http.NotFound(w, r)
}

// secureHeaders applies the baseline response hardening. The frontend is fully
// same-origin (vendored assets, no CDN, no inline handlers/styles). Alpine.js
// evaluates directive expressions via the Function constructor, which CSP
// classifies as 'unsafe-eval' — the one accepted trade-off for a single-admin,
// login-gated, same-origin console. Inline <script>/<style> and every
// cross-origin load stay blocked.
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self'; "+
				"img-src 'self' data:; connect-src 'self'; object-src 'none'; "+
				"base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr emits the standard error envelope.
func writeErr(w http.ResponseWriter, status int, format string, a ...any) {
	writeJSON(w, status, map[string]string{"error": fmt.Sprintf(format, a...)})
}

// decodeJSON reads a bounded JSON body into dst.
func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}
