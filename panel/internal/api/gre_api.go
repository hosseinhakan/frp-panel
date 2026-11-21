// GRE tunnel manager API — the panel face of the CLI's menu 10. Writes the
// same /root/frp/gre/*.env files (byte-identical, validated values only —
// frp-gre sources these), ensures the canonical frp-gre helper + unit are
// installed from the embedded assets, and drives gre-tunnel@<name>.
package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/frp-suite/panel/internal/assets"
	"github.com/frp-suite/panel/internal/gre"
)

// ---- DTOs ------------------------------------------------------------------

type greCreateReq struct {
	Name            string `json:"name"` // tunnel + interface name (default gt11)
	LocalPublicIP   string `json:"localPublicIp"`
	RemotePublicIP  string `json:"remotePublicIp"`
	LocalPrivateIP  string `json:"localPrivateIp"`  // default: suggested /30
	RemotePrivateIP string `json:"remotePrivateIp"` // default: suggested /30
	MTU             int    `json:"mtu"`             // default 1320
	MSSMode         string `json:"mssMode"`         // default clamp
	TXQueuelen      int    `json:"txqueuelen"`      // default 1000
}

type greUpdateReq struct {
	LocalPublicIP   string `json:"localPublicIp"`
	RemotePublicIP  string `json:"remotePublicIp"`
	LocalPrivateIP  string `json:"localPrivateIp"`
	RemotePrivateIP string `json:"remotePrivateIp"`
	MTU             int    `json:"mtu"`
	MSSMode         string `json:"mssMode"`
	TXQueuelen      int    `json:"txqueuelen"`
	Restart         *bool  `json:"restart"` // default true: restart the unit after saving
}

type greStatus struct {
	UnitActive string `json:"unitActive"`
	IfaceUp    bool   `json:"ifaceUp"`
	RxBytes    int64  `json:"rxBytes"`
	RxPackets  int64  `json:"rxPackets"`
	TxBytes    int64  `json:"txBytes"`
	TxPackets  int64  `json:"txPackets"`
}

type greTunnelResp struct {
	gre.Tunnel
	EnvFile string    `json:"envFile"`
	Status  greStatus `json:"status"`
}

// ---- list / detail ------------------------------------------------------------

func (s *Server) handleGREList(w http.ResponseWriter, r *http.Request) {
	tunnels, bad, err := gre.List(s.paths.GREDir)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot list GRE tunnels: %v", err)
		return
	}
	out := []greTunnelResp{}
	for _, t := range tunnels {
		out = append(out, s.greResp(t))
	}
	resp := map[string]any{"tunnels": out}
	if len(bad) > 0 {
		errs := map[string]string{}
		for n, e := range bad {
			errs[n] = e.Error()
		}
		resp["unreadable"] = errs
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleGREGet(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	t, err := gre.Read(s.paths.GREDir, name)
	if err != nil {
		writeGREErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.greResp(t))
}

func (s *Server) greResp(t gre.Tunnel) greTunnelResp {
	resp := greTunnelResp{Tunnel: t, EnvFile: filepath.Join(s.paths.GREDir, t.Name+".env")}

	if out, err := s.runner.Systemctl("is-active", "gre-tunnel@"+t.Name); err == nil {
		resp.Status.UnitActive = normalizeActive(out, nil)
	} else {
		resp.Status.UnitActive = normalizeActive("", err)
	}
	if st, err := os.Stat(filepath.Join(s.paths.SysNetDir, t.Iface)); err == nil && st.IsDir() {
		resp.Status.IfaceUp = true
	}
	resp.Status.RxBytes = readNetStat(s.paths.SysNetDir, t.Iface, "rx_bytes")
	resp.Status.RxPackets = readNetStat(s.paths.SysNetDir, t.Iface, "rx_packets")
	resp.Status.TxBytes = readNetStat(s.paths.SysNetDir, t.Iface, "tx_bytes")
	resp.Status.TxPackets = readNetStat(s.paths.SysNetDir, t.Iface, "tx_packets")
	return resp
}

func readNetStat(sysNetDir, iface, key string) int64 {
	b, err := os.ReadFile(filepath.Join(sysNetDir, iface, "statistics", key))
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n
}

// ---- create --------------------------------------------------------------------

func (s *Server) handleGRECreate(w http.ResponseWriter, r *http.Request) {
	var req greCreateReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Name == "" {
		req.Name = gre.DefaultName
	}
	if req.MTU == 0 {
		req.MTU = gre.DefaultMTU
	}
	if req.MSSMode == "" {
		req.MSSMode = gre.DefaultMSSMode
	}
	if req.TXQueuelen == 0 {
		req.TXQueuelen = gre.DefaultTXQueuelen
	}

	existing, _, err := gre.List(s.paths.GREDir)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot list GRE tunnels: %v", err)
		return
	}

	// Private /30 pair: explicit wins; both default to the next free /30
	// (10.100.<n>.0/30 allocator — never overlaps an existing tunnel).
	if req.LocalPrivateIP == "" && req.RemotePrivateIP == "" {
		req.LocalPrivateIP, req.RemotePrivateIP = gre.SuggestSubnet(existing)
	} else if req.LocalPrivateIP == "" || req.RemotePrivateIP == "" {
		writeErr(w, http.StatusBadRequest, "private IPs must be given as a pair (or both omitted to auto-suggest)")
		return
	}

	t := gre.Tunnel{
		Name:            req.Name,
		LocalPublicIP:   req.LocalPublicIP,
		RemotePublicIP:  req.RemotePublicIP,
		Iface:           req.Name, // CLI invariant: file stem == IFACE == unit instance
		LocalPrivateIP:  req.LocalPrivateIP,
		RemotePrivateIP: req.RemotePrivateIP,
		MTU:             req.MTU,
		MSSMode:         req.MSSMode,
		TXQueuelen:      req.TXQueuelen,
	}
	warnings, err := t.Validate()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}

	// Same-name tunnel: keep a .bak like the CLI does before overwriting.
	envPath := filepath.Join(s.paths.GREDir, t.Name+".env")
	backup := ""
	if old, rerr := os.ReadFile(envPath); rerr == nil {
		bak := envPath + ".bak-" + backupTimestamp(s.now())
		if werr := os.WriteFile(bak, old, 0o600); werr == nil {
			backup = bak
		}
	}

	if err := s.ensureGREAssets(); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to install GRE assets: %v", err)
		return
	}
	if err := gre.Write(s.paths.GREDir, t); err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}

	unit := "gre-tunnel@" + t.Name
	unitErr := ""
	if out, err := s.ensureGREUnit(unit); err != nil {
		unitErr = strings.TrimSpace(strings.TrimSpace(out) + " " + err.Error())
		audit("created GRE tunnel %s but enable failed: %s", t.Name, unitErr)
	}

	resp := s.greResp(t)
	body := map[string]any{
		"tunnel":   resp,
		"warnings": warnings,
		"backup":   backup,
	}
	if unitErr != "" {
		// 201 stands: the definition is saved; only systemd failed.
		body["unit_error"] = unitErr
	}
	writeJSON(w, http.StatusCreated, body)
}

// ---- update --------------------------------------------------------------------

// handleGREUpdate edits an existing tunnel definition in place (name/iface are
// immutable — they are the systemd instance and the env file stem). With
// restart=true (the default) the unit is restarted so the new endpoints, MTU
// and queue length take effect immediately.
func (s *Server) handleGREUpdate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	existing, err := gre.Read(s.paths.GREDir, name)
	if err != nil {
		writeGREErr(w, err)
		return
	}

	var req greUpdateReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	t := existing
	if v := strings.TrimSpace(req.LocalPublicIP); v != "" {
		t.LocalPublicIP = v
	}
	if v := strings.TrimSpace(req.RemotePublicIP); v != "" {
		t.RemotePublicIP = v
	}
	if v := strings.TrimSpace(req.LocalPrivateIP); v != "" {
		t.LocalPrivateIP = v
	}
	if v := strings.TrimSpace(req.RemotePrivateIP); v != "" {
		t.RemotePrivateIP = v
	}
	if req.MTU > 0 {
		t.MTU = req.MTU
	}
	if v := strings.TrimSpace(req.MSSMode); v != "" {
		t.MSSMode = v
	}
	if req.TXQueuelen > 0 {
		t.TXQueuelen = req.TXQueuelen
	}
	if t.TXQueuelen == 0 {
		t.TXQueuelen = gre.DefaultTXQueuelen
	}

	warnings, err := t.Validate()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}

	envPath := filepath.Join(s.paths.GREDir, t.Name+".env")
	backup := ""
	if old, rerr := os.ReadFile(envPath); rerr == nil {
		bak := envPath + ".bak-" + backupTimestamp(s.now())
		if werr := os.WriteFile(bak, old, 0o600); werr == nil {
			backup = bak
		}
	}
	if err := s.ensureGREAssets(); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to install GRE assets: %v", err)
		return
	}
	if err := gre.Write(s.paths.GREDir, t); err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}

	restart := true
	if req.Restart != nil {
		restart = *req.Restart
	}
	unitErr := ""
	restarted := false
	if restart {
		unit := "gre-tunnel@" + t.Name
		if out, rerr := s.runner.Systemctl("restart", unit); rerr != nil {
			unitErr = strings.TrimSpace(strings.TrimSpace(out) + " " + rerr.Error())
			audit("updated GRE tunnel %s but restart failed: %s", t.Name, unitErr)
		} else {
			restarted = true
			audit("updated GRE tunnel %s (restarted)", t.Name)
		}
	} else {
		audit("updated GRE tunnel %s (restart deferred)", t.Name)
	}

	resp := s.greResp(t)
	body := map[string]any{
		"tunnel":    resp,
		"warnings":  warnings,
		"backup":    backup,
		"restarted": restarted,
	}
	if unitErr != "" {
		body["unit_error"] = unitErr
	}
	writeJSON(w, http.StatusOK, body)
}

// ensureGREAssets installs the canonical frp-gre helper and gre-tunnel@.service
// from the embedded assets when missing or outdated (same bytes the CLI's
// heredocs write), then reloads systemd.
func (s *Server) ensureGREAssets() error {
	helperChanged, err := syncAssetFile("helpers/frp-gre", filepath.Join(s.paths.BinDir, "frp-gre"), 0o755)
	if err != nil {
		return err
	}
	unitChanged, err := syncAssetFile("systemd/gre-tunnel@.service", filepath.Join(s.paths.UnitDir, "gre-tunnel@.service"), 0o644)
	if err != nil {
		return err
	}
	if helperChanged || unitChanged {
		if _, err := s.runner.Systemctl("daemon-reload"); err != nil {
			audit("daemon-reload after GRE asset sync failed: %v", err)
		}
	}
	return nil
}

// syncAssetFile writes an embedded asset to dst unless the bytes already match.
// Returns whether the file changed.
func syncAssetFile(embedPath, dst string, perm os.FileMode) (bool, error) {
	raw, err := assets.FS.ReadFile(embedPath)
	if err != nil {
		return false, err
	}
	if old, rerr := os.ReadFile(dst); rerr == nil && string(old) == string(raw) {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return false, err
	}
	if err := os.WriteFile(dst, raw, perm); err != nil {
		return false, err
	}
	return true, nil
}

// ---- mirror --------------------------------------------------------------------

func (s *Server) handleGREMirror(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	t, err := gre.Read(s.paths.GREDir, name)
	if err != nil {
		writeGREErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":     name,
		"mirror":   t.Mirror(),
		"env_file": t.MirrorText(s.paths.GREDir),
	})
}

// ---- link test -------------------------------------------------------------------

func (s *Server) handleGRETest(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	t, err := gre.Read(s.paths.GREDir, name)
	if err != nil {
		writeGREErr(w, err)
		return
	}

	// Bring the tunnel up if it isn't (restart also starts inactive units).
	unit := "gre-tunnel@" + t.Name
	if out, err := s.runner.Systemctl("is-active", unit); err != nil ||
		!strings.HasPrefix(strings.TrimSpace(out), "active") {
		if _, err := s.runner.Systemctl("restart", unit); err != nil {
			writeErr(w, http.StatusConflict, "cannot bring up %s: %v", unit, err)
			return
		}
	}

	peer := strings.SplitN(t.RemotePrivateIP, "/", 2)[0]

	// 1) GRE tunnel ping: 10 fast probes give an exact loss% over the link.
	greOut, greErr := s.runner.Exec("ping", "-c", "10", "-i", "0.2", "-W", "1", "-I", t.Iface, peer)
	greLoss, greAvg := parsePing(greOut)
	greReachable := greErr == nil && greLoss < 100

	// 2) DF MTU probe: a full-size packet with don't-fragment proves the
	// configured MTU (minus 28 bytes of IP+ICMP headers) survives the path.
	mtuSize := t.MTU - 28
	if mtuSize < 576 {
		mtuSize = 576
	}
	mtuOut, mtuErr := s.runner.Exec("ping", "-M", "do", "-s", strconv.Itoa(mtuSize),
		"-c", "3", "-W", "2", "-I", t.Iface, peer)
	mtuLoss, _ := parsePing(mtuOut)
	mtuOK := mtuErr == nil && mtuLoss == 0

	// 3) Public baseline: loss here but not over GRE points at the underlying
	// datacenter route rather than protocol 47 / the tunnel.
	pubOut, pubErr := s.runner.Exec("ping", "-c", "5", "-W", "2", t.RemotePublicIP)
	pubLoss, pubAvg := parsePing(pubOut)
	pubReachable := pubErr == nil && pubLoss < 100

	checks := map[string]any{
		"gre": map[string]any{
			"label": "GRE tunnel ping", "target": peer,
			"output":    strings.TrimSpace(greOut),
			"reachable": greReachable, "loss_pct": greLoss, "rtt_ms": greAvg,
		},
		"mtu": map[string]any{
			"label": "DF MTU probe", "target": peer, "size": mtuSize,
			"output": strings.TrimSpace(mtuOut), "ok": mtuOK, "loss_pct": mtuLoss,
		},
		"public": map[string]any{
			"label": "Public IP baseline", "target": t.RemotePublicIP,
			"output":    strings.TrimSpace(pubOut),
			"reachable": pubReachable, "loss_pct": pubLoss, "rtt_ms": pubAvg,
		},
	}

	resp := map[string]any{
		"name": name, "iface": t.Iface, "peer": peer,
		"output":    strings.TrimSpace(greOut),
		"reachable": greReachable, "loss_pct": greLoss,
		"mtu_probe_ok": mtuOK, "mtu_probe_size": mtuSize,
		"public_loss_pct": pubLoss, "checks": checks,
	}
	if greAvg > 0 {
		resp["rtt_ms"] = greAvg
	}
	if pubAvg > 0 {
		resp["public_rtt_ms"] = pubAvg
	}
	resp["rx_bytes"] = readNetStat(s.paths.SysNetDir, t.Iface, "rx_bytes")
	resp["tx_bytes"] = readNetStat(s.paths.SysNetDir, t.Iface, "tx_bytes")
	writeJSON(w, http.StatusOK, resp)
}

// parsePing extracts loss% and avg rtt from iputils ping output:
//
//	3 packets transmitted, 3 received, 0% packet loss, time 2003ms
//	rtt min/avg/max/mdev = 11.7/12.4/13.9/0.9 ms
func parsePing(out string) (loss float64, avgMs float64) {
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, "packet loss"); i > 0 {
			before := line[:i]
			if p := strings.LastIndex(before, ","); p >= 0 {
				f := strings.Fields(before[p+1:])
				if len(f) >= 1 {
					if v, err := strconv.ParseFloat(strings.TrimSuffix(f[0], "%"), 64); err == nil {
						loss = v
					}
				}
			}
		}
		if i := strings.Index(line, "rtt min/avg/max"); i >= 0 {
			rest := strings.SplitN(line[i:], "=", 2)
			if len(rest) == 2 {
				// "11.700/12.433/13.500/0.900 ms" → avg is the 2nd number.
				if fields := strings.Fields(rest[1]); len(fields) > 0 {
					if nums := strings.SplitN(fields[0], "/", 4); len(nums) >= 2 {
						if v, err := strconv.ParseFloat(nums[1], 64); err == nil {
							avgMs = v
						}
					}
				}
			}
		}
	}
	return loss, avgMs
}

// ---- delete ------------------------------------------------------------------------

func (s *Server) handleGREDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	t, err := gre.Read(s.paths.GREDir, name)
	if err != nil {
		writeGREErr(w, err)
		return
	}
	unit := "gre-tunnel@" + t.Name
	if out, err := s.disableUnitNow(unit); err != nil {
		audit("disable %s failed during delete: %s", unit, strings.TrimSpace(out))
	}
	// Teardown is best-effort (interface may already be gone), like the CLI's
	// `frp-gre down "$name" 2>/dev/null || true`.
	if _, err := s.runner.Exec("frp-gre", "down", t.Name); err != nil {
		audit("frp-gre down %s: %v", t.Name, err)
	}
	if err := gre.Delete(s.paths.GREDir, name); err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	audit("deleted GRE tunnel %s", name)
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "status": "removed (interface, rules and env deleted)"})
}

// writeGREErr maps gre package errors onto HTTP statuses.
func writeGREErr(w http.ResponseWriter, err error) {
	if os.IsNotExist(err) || strings.Contains(err.Error(), "missing") || strings.Contains(err.Error(), "no tunnel") {
		writeErr(w, http.StatusNotFound, "%v", err)
		return
	}
	if strings.Contains(err.Error(), "invalid tunnel name") {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	writeErr(w, http.StatusBadRequest, "%v", err)
}

// listEnvNames returns .env file stems in a dir.
func listEnvNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".env") {
			continue
		}
		names = append(names, strings.TrimSuffix(e.Name(), ".env"))
	}
	return names, nil
}
