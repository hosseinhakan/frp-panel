// Turbo API — the panel face of the CLI's menu 7 (Optimization Utilities).
// The panel never touches sysctls directly: it installs the canonical
// frp-turbo helper + tunnel-turbo/frp-zram units from the embedded assets
// and drives them with systemctl, exactly like `frp-manager turbo …`.
package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/frp-suite/panel/internal/turbo"
)

type turboReq struct {
	Action string `json:"action"` // apply | revert | zram-on | zram-off
	Size   int    `json:"size"`   // MB, zram-on only (default 2048)
	Algo   string `json:"algo"`  // zram-on only (default lz4)
}

// handleTurboGet reports the current kernel/tuning state: unit states,
// the sysctl drop-in presence, live values from `frp-turbo status` and the
// ZRAM config + live swap line.
func (s *Server) handleTurboGet(w http.ResponseWriter, r *http.Request) {
	dropin := "missing"
	if st, err := os.Stat(filepath.Join(s.paths.SysctlDir, "99-tunnel-turbo.conf")); err == nil && st.Mode().IsRegular() {
		dropin = "installed"
	}

	resp := map[string]any{
		"dropin": dropin,
		"units": map[string]any{
			"tunnel-turbo": s.unitState("tunnel-turbo"),
			"frp-zram":     s.unitState("frp-zram"),
		},
	}

	// Live sysctl values straight from the helper (a missing binary on a
	// fresh host simply means "not applied yet" — the field stays absent).
	if out, err := s.runner.Exec("frp-turbo", "status"); err == nil {
		resp["sysctl"] = turbo.ParseStatus(out)
	}
	if zenv, ok := turbo.ReadZramEnv(filepath.Join(s.paths.EtcPanelDir, turbo.ZramEnvName)); ok {
		resp["zram"] = map[string]any{"config": zenv}
		if out, err := s.runner.Exec("frp-turbo", "zram-status"); err == nil {
			if st, active := turbo.ParseZramStatus(out); active {
				resp["zram"].(map[string]any)["active"] = st
			} else {
				resp["zram"].(map[string]any)["active"] = nil
			}
		}
	} else {
		resp["zram"] = map[string]any{"config": nil}
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleTurboPost applies/reverts the tuning or toggles ZRAM. Mirrors the
// CLI's turbo_apply / turbo_revert / zram_on / zram_off flows.
func (s *Server) handleTurboPost(w http.ResponseWriter, r *http.Request) {
	var req turboReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	switch req.Action {
	case "apply":
		s.turboApply(w, r)
	case "revert":
		s.turboRevert(w)
	case "zram-on":
		s.zramOn(w, req)
	case "zram-off":
		s.zramOff(w)
	default:
		writeErr(w, http.StatusBadRequest, "invalid action %q (want apply|revert|zram-on|zram-off)", req.Action)
	}
}

func (s *Server) turboApply(w http.ResponseWriter, r *http.Request) {
	if err := s.ensureTurboAssets(); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to install turbo assets: %v", err)
		return
	}
	if _, err := s.runner.Systemctl("enable", "tunnel-turbo"); err != nil {
		writeErr(w, http.StatusConflict, "systemctl enable tunnel-turbo failed: %s", err)
		return
	}
	out, err := s.runner.Systemctl("restart", "tunnel-turbo")
	if err != nil {
		writeErr(w, http.StatusConflict, "systemctl restart tunnel-turbo failed: %s",
			strings.TrimSpace(strings.TrimSpace(out)+" "+err.Error()))
		return
	}
	audit("turbo applied")
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "applied persistently (tunnel-turbo.service)", "output": strings.TrimSpace(out),
	})
}

func (s *Server) turboRevert(w http.ResponseWriter) {
	// The CLI treats revert as best-effort (|| true); failures are
	// reported but the drop-in removal is what matters.
	if out, err := s.runner.Systemctl("disable", "--now", "tunnel-turbo"); err != nil {
		audit("turbo revert: disable failed: %s", strings.TrimSpace(out))
	}
	unitErr := ""
	if out, err := s.runner.Exec("frp-turbo", "revert"); err != nil {
		unitErr = strings.TrimSpace(strings.TrimSpace(out) + " " + err.Error())
		audit("turbo revert: frp-turbo revert failed: %s", unitErr)
	}
	audit("turbo reverted")
	resp := map[string]any{"status": "reverted (drop-in removed; kernel keeps values until reboot)"}
	if unitErr != "" {
		resp["unit_error"] = unitErr
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) zramOn(w http.ResponseWriter, req turboReq) {
	if req.Size == 0 {
		req.Size = turbo.DefaultZramSizeMB
	}
	if req.Algo == "" {
		req.Algo = turbo.DefaultZramAlgo
	}
	env := turbo.ZramEnv{SizeMB: req.Size, Algo: req.Algo}
	if err := env.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	if err := s.ensureTurboAssets(); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to install turbo assets: %v", err)
		return
	}
	// Persist the config byte-identically to the CLI's zram_on (with a
	// .bak of the previous file, like every other panel write).
	envPath := filepath.Join(s.paths.EtcPanelDir, turbo.ZramEnvName)
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
	if err := os.WriteFile(envPath, []byte(turbo.RenderZramEnv(env)), 0o600); err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if _, err := s.runner.Systemctl("enable", "frp-zram"); err != nil {
		writeErr(w, http.StatusConflict, "systemctl enable frp-zram failed: %s", err)
		return
	}
	out, err := s.runner.Systemctl("restart", "frp-zram")
	if err != nil {
		writeErr(w, http.StatusConflict, "systemctl restart frp-zram failed: %s",
			strings.TrimSpace(strings.TrimSpace(out)+" "+err.Error()))
		return
	}
	audit("zram enabled (%dMB %s)", env.SizeMB, env.Algo)
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "zram enabled", "zram": env, "output": strings.TrimSpace(out), "backup": backup,
	})
}

func (s *Server) zramOff(w http.ResponseWriter) {
	if out, err := s.runner.Systemctl("disable", "--now", "frp-zram"); err != nil {
		audit("zram off: disable failed: %s", strings.TrimSpace(out))
	}
	unitErr := ""
	if out, err := s.runner.Exec("frp-turbo", "zram-off"); err != nil {
		unitErr = strings.TrimSpace(strings.TrimSpace(out) + " " + err.Error())
		audit("zram off: frp-turbo zram-off failed: %s", unitErr)
	}
	audit("zram disabled")
	resp := map[string]any{"status": "zram disabled"}
	if unitErr != "" {
		resp["unit_error"] = unitErr
	}
	writeJSON(w, http.StatusOK, resp)
}

// ensureTurboAssets installs the canonical frp-turbo helper plus the
// tunnel-turbo and frp-zram units from the embedded assets (same bytes the
// CLI's heredocs write), then reloads systemd.
func (s *Server) ensureTurboAssets() error {
	helperChanged, err := syncAssetFile("helpers/frp-turbo", filepath.Join(s.paths.BinDir, "frp-turbo"), 0o755)
	if err != nil {
		return err
	}
	turboUnit, err := syncAssetFile("systemd/tunnel-turbo.service", filepath.Join(s.paths.UnitDir, "tunnel-turbo.service"), 0o644)
	if err != nil {
		return err
	}
	zramUnit, err := syncAssetFile("systemd/frp-zram.service", filepath.Join(s.paths.UnitDir, "frp-zram.service"), 0o644)
	if err != nil {
		return err
	}
	if helperChanged || turboUnit || zramUnit {
		if _, err := s.runner.Systemctl("daemon-reload"); err != nil {
			audit("daemon-reload after turbo asset sync failed: %v", err)
		}
	}
	return nil
}
