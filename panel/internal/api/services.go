// systemctl wrapper: list the suite's units with their state and run
// whitelisted actions. Every unit string is validated (svc.ValidateUnit)
// and template instances must resolve to an existing config file, so the
// attack surface is exactly the units this suite manages.
package api

import (
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/frp-suite/panel/internal/frpconf"
	"github.com/frp-suite/panel/internal/svc"
)

// suiteSingletons are the non-template units the suite ships.
var suiteSingletons = []string{"tunnel-turbo", "frp-zram", "frp-watchdog", "frp-panel"}

type serviceInfo struct {
	Unit    string `json:"unit"`
	Active  string `json:"active"`
	Enabled string `json:"enabled"`
}

func (s *Server) handleServicesList(w http.ResponseWriter, r *http.Request) {
	units := []string{}

	if srvNames, err := frpconf.ListConfigs(s.paths.ServerDir); err == nil {
		for _, n := range srvNames {
			units = append(units, "frps@"+n)
		}
	}
	if cliNames, err := frpconf.ListConfigs(s.paths.ClientDir); err == nil {
		for _, n := range cliNames {
			units = append(units, "frpc@"+n)
		}
	}
	if greNames, err := listEnvNames(s.paths.GREDir); err == nil {
		for _, n := range greNames {
			units = append(units, "gre-tunnel@"+n)
		}
	}
	units = append(units, suiteSingletons...)
	sort.Strings(units)

	out := make([]serviceInfo, len(units))
	for i, u := range units {
		out[i] = serviceInfo{Unit: u, Active: "inactive", Enabled: "disabled"}
	}
	if len(units) > 0 {
		// systemctl is-active/is-enabled accept multiple units and print
		// one state per line — two calls total, not 2N.
		if lines, err := s.runner.Systemctl(append([]string{"is-active"}, units...)...); err == nil {
			setStates(out, strings.Fields(strings.TrimSpace(lines)), func(i int, v string) { out[i].Active = normalizeActive(v, nil) })
		}
		if lines, err := s.runner.Systemctl(append([]string{"is-enabled"}, units...)...); err == nil {
			setStates(out, strings.Fields(strings.TrimSpace(lines)), func(i int, v string) { out[i].Enabled = normalizeEnabled(v, nil) })
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": out})
}

// normalizeActive turns a missing/not-found unit into "inactive" so the UI
// can show "stopped" instead of a scary "unknown".
func normalizeActive(out string, err error) string {
	v := strings.TrimSpace(out)
	if i := strings.IndexByte(v, '\n'); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	switch v {
	case "active", "activating", "deactivating", "inactive", "failed", "reloading", "maintenance", "refreshing":
		return v
	}
	if err != nil || v == "" || v == "unknown" || v == "not-found" || v == "dead" {
		return "inactive"
	}
	return v
}

// normalizeEnabled maps not-found/unknown states to "disabled".
func normalizeEnabled(out string, err error) string {
	v := strings.TrimSpace(out)
	if i := strings.IndexByte(v, '\n'); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	switch v {
	case "enabled", "disabled", "static", "masked", "indirect", "generated",
		"transient", "enabled-runtime", "disabled-runtime", "alias", "linked":
		return v
	}
	if err != nil || v == "" || v == "unknown" || v == "not-found" {
		return "disabled"
	}
	return v
}

func setStates(out []serviceInfo, states []string, set func(int, string)) {
	for i := range out {
		if i < len(states) {
			set(i, states[i])
		}
	}
}

// unitIsActive reports whether a unit is currently running.
func (s *Server) unitIsActive(unit string) bool {
	out, err := s.runner.Systemctl("is-active", unit)
	return err == nil && strings.HasPrefix(strings.TrimSpace(out), "active")
}

// enableUnitNow is the safe replacement for `systemctl enable --now`.
//
// svc.Systemctl rejects every argument that starts with "-", so the `--now`
// shorthand can never reach systemctl through the panel. Issue the two
// explicit commands instead: `enable` persists the unit at boot, while
// `restart` starts it immediately (and reloads a running unit with the config
// that was just written).
func (s *Server) enableUnitNow(unit string) (string, error) {
	if out, err := s.runner.Systemctl("enable", unit); err != nil {
		return out, err
	}
	return s.runner.Systemctl("restart", unit)
}

// ensureGREUnit persists a gre-tunnel@ unit at boot and starts it only when it
// is not already running. Re-running a wizard or creating an already-live
// tunnel must never restart (and therefore drop) a healthy carrying tunnel.
func (s *Server) ensureGREUnit(unit string) (string, error) {
	out, err := s.runner.Systemctl("enable", unit)
	if err != nil {
		return out, err
	}
	if s.unitIsActive(unit) {
		return out, nil
	}
	return s.runner.Systemctl("start", unit)
}

// disableUnitNow is the safe replacement for `systemctl disable --now`:
// disable removes the boot links, stop halts the running instance.
func (s *Server) disableUnitNow(unit string) (string, error) {
	out, err := s.runner.Systemctl("disable", unit)
	stopOut, stopErr := s.runner.Systemctl("stop", unit)
	if err != nil {
		return out, err
	}
	if stopErr != nil {
		return stopOut, stopErr
	}
	return stopOut, nil
}

type serviceActionReq struct {
	Action string `json:"action"` // start | stop | restart | enable | disable
}

func (s *Server) handleServiceAction(w http.ResponseWriter, r *http.Request) {
	unit := r.PathValue("unit")
	family, instance, err := svc.ValidateUnit(unit)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	var req serviceActionReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	switch req.Action {
	case "start", "stop", "restart", "enable", "disable":
	default:
		writeErr(w, http.StatusBadRequest, "invalid action %q (want start|stop|restart|enable|disable)", req.Action)
		return
	}

	// Template instances must have a config to run with.
	if instance != "" {
		if _, err := os.Stat(s.unitConfigPath(family, instance)); err != nil {
			writeErr(w, http.StatusNotFound, "unit %q has no config file", unit)
			return
		}
	}

	out, err := s.runner.Systemctl(req.Action, unit)
	if err != nil {
		writeErr(w, http.StatusConflict, "systemctl %s %s failed: %s", req.Action, unit, strings.TrimSpace(out+err.Error()))
		return
	}
	audit("systemctl %s %s", req.Action, unit)
	writeJSON(w, http.StatusOK, map[string]any{
		"unit": unit, "action": req.Action, "output": strings.TrimSpace(out),
	})
}
