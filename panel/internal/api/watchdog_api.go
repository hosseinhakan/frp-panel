// Watchdog API — the panel face of the CLI's menu 13. Writes the same
// /etc/frp-panel/watchdog.env the CLI heredoc produces (the helper sources
// it on start), installs the canonical helper + unit from the embedded
// assets, and enables/disables frp-watchdog.
package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/frp-suite/panel/internal/watchdog"
)

// handleWatchdogGet reports unit state, the tuning env (if configured) and
// the tail of the watchdog event log.
func (s *Server) handleWatchdogGet(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"unit": s.unitState("frp-watchdog"),
	}
	if env, ok := watchdog.Read(s.watchdogEnvPath()); ok {
		resp["config"] = env
	} else {
		resp["config"] = nil
	}
	resp["events"] = s.tailWatchdogLog(50)
	writeJSON(w, http.StatusOK, resp)
}

// watchdogEnvPath locates /etc/frp-panel/watchdog.env.
func (s *Server) watchdogEnvPath() string {
	return filepath.Join(s.paths.EtcPanelDir, "watchdog.env")
}

// tailWatchdogLog returns the last n lines of /var/log/frp-panel/watchdog.log.
func (s *Server) tailWatchdogLog(n int) []string {
	raw, err := os.ReadFile(filepath.Join(s.paths.LogDir, "watchdog.log"))
	if err != nil {
		return []string{}
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	if len(lines) == 1 && lines[0] == "" {
		return []string{}
	}
	return lines
}

type watchdogReq struct {
	Enabled     *bool `json:"enabled"`     // required switch
	Interval    *int  `json:"interval"`    // default 15
	Threshold   *int  `json:"threshold"`   // default 3
	Cooldown    *int  `json:"cooldown"`    // default 60
	PingTimeout *int  `json:"pingTimeout"` // default 2
	TCPTimeout  *int  `json:"tcpTimeout"`  // default 3
}

// handleWatchdogPost configures + enables or disables the watchdog.
// Values merge over the current env (or defaults) so the UI can post a
// partial form; validation mirrors the CLI (interval >= 10 etc.) and an
// explicitly-posted invalid value is rejected, never silently defaulted.
func (s *Server) handleWatchdogPost(w http.ResponseWriter, r *http.Request) {
	var req watchdogReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Enabled == nil {
		writeErr(w, http.StatusBadRequest, "missing \"enabled\" field")
		return
	}

	if !*req.Enabled {
		if out, err := s.runner.Systemctl("disable", "--now", "frp-watchdog"); err != nil {
			writeErr(w, http.StatusConflict, "systemctl disable frp-watchdog failed: %s",
				strings.TrimSpace(strings.TrimSpace(out)+" "+err.Error()))
			return
		}
		audit("watchdog disabled")
		writeJSON(w, http.StatusOK, map[string]any{"status": "disabled", "unit": s.unitState("frp-watchdog")})
		return
	}

	env, ok := watchdog.Read(s.watchdogEnvPath())
	if !ok {
		env = watchdog.Default()
	}
	if req.Interval != nil {
		env.Interval = *req.Interval
	}
	if req.Threshold != nil {
		env.Threshold = *req.Threshold
	}
	if req.Cooldown != nil {
		env.Cooldown = *req.Cooldown
	}
	if req.PingTimeout != nil {
		env.PingTimeout = *req.PingTimeout
	}
	if req.TCPTimeout != nil {
		env.TCPTimeout = *req.TCPTimeout
	}
	if err := env.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}

	if err := s.ensureWatchdogAssets(); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to install watchdog assets: %v", err)
		return
	}

	// Write the env byte-identically to the CLI heredoc, .bak the old one.
	envPath := s.watchdogEnvPath()
	backup := ""
	if old, rerr := os.ReadFile(envPath); rerr == nil {
		bak := envPath + ".bak-" + backupTimestamp(s.now())
		if werr := os.WriteFile(bak, old, 0o600); werr == nil {
			backup = bak
		}
	}
	if err := os.MkdirAll(s.paths.EtcPanelDir, 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if err := os.WriteFile(envPath, []byte(watchdog.Render(env)), 0o600); err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}

	unitErr := ""
	if _, err := s.runner.Systemctl("enable", "--now", "frp-watchdog"); err != nil {
		unitErr = err.Error()
	}
	// The helper sources the env on start — restart when it was already
	// running so new tuning takes effect immediately.
	s.restartIfActive("frp-watchdog")

	audit("watchdog enabled (interval=%ds threshold=%d cooldown=%ds)", env.Interval, env.Threshold, env.Cooldown)
	resp := map[string]any{
		"status": "enabled", "config": env, "unit": s.unitState("frp-watchdog"), "backup": backup,
	}
	if unitErr != "" {
		resp["unit_error"] = unitErr
	}
	writeJSON(w, http.StatusOK, resp)
}

// ensureWatchdogAssets installs the canonical frp-watchdog helper + unit
// from the embedded assets (same bytes the CLI's heredocs write).
func (s *Server) ensureWatchdogAssets() error {
	helperChanged, err := syncAssetFile("helpers/frp-watchdog", filepath.Join(s.paths.BinDir, "frp-watchdog"), 0o755)
	if err != nil {
		return err
	}
	unitChanged, err := syncAssetFile("systemd/frp-watchdog.service", filepath.Join(s.paths.UnitDir, "frp-watchdog.service"), 0o644)
	if err != nil {
		return err
	}
	if helperChanged || unitChanged {
		if _, err := s.runner.Systemctl("daemon-reload"); err != nil {
			audit("daemon-reload after watchdog asset sync failed: %v", err)
		}
	}
	return nil
}
