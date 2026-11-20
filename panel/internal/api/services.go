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
		out[i] = serviceInfo{Unit: u, Active: "unknown", Enabled: "unknown"}
	}
	if len(units) > 0 {
		// systemctl is-active/is-enabled accept multiple units and print
		// one state per line — two calls total, not 2N.
		if lines, err := s.runner.Systemctl(append([]string{"is-active"}, units...)...); err == nil {
			setStates(out, strings.Fields(strings.TrimSpace(lines)), func(i int, v string) { out[i].Active = v })
		}
		if lines, err := s.runner.Systemctl(append([]string{"is-enabled"}, units...)...); err == nil {
			setStates(out, strings.Fields(strings.TrimSpace(lines)), func(i int, v string) { out[i].Enabled = v })
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": out})
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
