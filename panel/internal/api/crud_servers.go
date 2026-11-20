// frps instance CRUD. Everything here writes the same
// /root/frp/server/*.toml files the bash CLI edits, through the shared
// write gate (frps verify + .bak), then drives frps@<name> via systemctl.
package api

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/frp-suite/panel/internal/frpconf"
)

// instanceNamePattern is the shared charset for config/systemd instance
// names (frps@<name>, file <name>.toml).
var instanceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// ---- DTOs ------------------------------------------------------------------

type serverCreateReq struct {
	Name        string `json:"name"`
	BindPort    int    `json:"bindPort"`
	BindAddr    string `json:"bindAddr"`
	Protocol    string `json:"protocol"` // quic | kcp | none (default quic)
	TCPMux      *bool  `json:"tcpMux"`
	Token       string `json:"token"`
	WebEnabled  *bool  `json:"webEnabled"` // default true (metrics dashboard)
	WebPort     int    `json:"webPort"`
	WebUser     string `json:"webUser"`
	WebPassword string `json:"webPassword"`
}

type serverUpdateReq struct {
	BindPort                *int    `json:"bindPort"`
	BindAddr                *string `json:"bindAddr"`
	Protocol                *string `json:"protocol"`
	TCPMux                  *bool   `json:"tcpMux"`
	TCPMuxKeepaliveInterval *int    `json:"tcpMuxKeepaliveInterval"`
	HeartbeatTimeout        *int    `json:"heartbeatTimeout"`
	TCPKeepalive            *int    `json:"tcpKeepalive"`
	MaxPoolCount            *int    `json:"maxPoolCount"`
	QUICKeepalivePeriod     *int    `json:"quicKeepalivePeriod"`
	QUICMaxIdleTimeout      *int    `json:"quicMaxIdleTimeout"`
	QUICMaxIncomingStreams  *int    `json:"quicMaxIncomingStreams"`
	Token                   *string `json:"token"`
	Restart                 *bool   `json:"restart"`
}

type unitState struct {
	Active  string `json:"active"`  // active | inactive | failed | …
	Enabled string `json:"enabled"` // enabled | disabled | static | …
	Error   string `json:"error,omitempty"`
}

type serverSummary struct {
	Name                    string    `json:"name"`
	File                    string    `json:"file"`
	BindAddr                string    `json:"bindAddr"`
	BindPort                int       `json:"bindPort"`
	Protocol                string    `json:"protocol"`
	WebPort                 int       `json:"webPort"`
	WebUser                 string    `json:"webUser,omitempty"`
	TokenSet                bool      `json:"tokenSet"`
	TCPMux                  bool      `json:"tcpMux"`
	TCPMuxKeepaliveInterval int       `json:"tcpMuxKeepaliveInterval"`
	HeartbeatTimeout        int       `json:"heartbeatTimeout"`
	TCPKeepalive            int       `json:"tcpKeepalive"`
	MaxPoolCount            int       `json:"maxPoolCount"`
	QUICKeepalivePeriod     int       `json:"quicKeepalivePeriod"`
	QUICMaxIdleTimeout      int       `json:"quicMaxIdleTimeout"`
	QUICMaxIncomingStreams  int       `json:"quicMaxIncomingStreams"`
	Style                   string    `json:"style"`
	Unit                    unitState `json:"unit"`
	ParseError              string    `json:"parseError,omitempty"`
}

// ---- list / detail ---------------------------------------------------------

func (s *Server) handleServersList(w http.ResponseWriter, r *http.Request) {
	names, err := frpconf.ListConfigs(s.paths.ServerDir)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot list server configs: %v", err)
		return
	}
	out := []serverSummary{}
	for _, name := range names {
		sum := s.serverSummary(name)
		out = append(out, sum)
	}
	writeJSON(w, http.StatusOK, map[string]any{"servers": out})
}

func (s *Server) serverSummary(name string) serverSummary {
	sum := serverSummary{
		Name: name,
		File: filepath.Join(s.paths.ServerDir, name+".toml"),
	}
	raw, err := os.ReadFile(sum.File)
	if err != nil {
		sum.ParseError = err.Error()
		sum.Style = frpconf.StyleAdvanced.String()
		return sum
	}
	style, _, _ := frpconf.Classify(raw, frpconf.KindServer)
	sum.Style = style.String()
	cfg, err := frpconf.ParseServer(raw)
	if err != nil {
		sum.ParseError = err.Error()
	} else {
		sum.BindAddr = cfg.BindAddr
		sum.BindPort = cfg.BindPort
		sum.Protocol = serverProtocol(cfg)
		sum.WebPort = cfg.WebServer.Port
		sum.WebUser = cfg.WebServer.User
		sum.TokenSet = cfg.Auth.Token != ""
		sum.TCPMux = cfg.Transport.TCPMux
		sum.TCPMuxKeepaliveInterval = cfg.Transport.TCPMuxKeepaliveInterval
		sum.HeartbeatTimeout = cfg.Transport.HeartbeatTimeout
		sum.TCPKeepalive = cfg.Transport.TCPKeepalive
		sum.MaxPoolCount = cfg.Transport.MaxPoolCount
		sum.QUICKeepalivePeriod = cfg.Transport.QUIC.KeepalivePeriod
		sum.QUICMaxIdleTimeout = cfg.Transport.QUIC.MaxIdleTimeout
		sum.QUICMaxIncomingStreams = cfg.Transport.QUIC.MaxIncomingStreams
	}
	sum.Unit = s.unitState("frps@" + name)
	return sum
}

func (s *Server) unitState(unit string) unitState {
	st := unitState{}
	if out, err := s.runner.Systemctl("is-active", unit); err == nil {
		st.Active = normalizeActive(out, nil)
	} else {
		st.Active = normalizeActive("", err)
		st.Error = strings.TrimSpace(out)
	}
	if out, err := s.runner.Systemctl("is-enabled", unit); err == nil {
		st.Enabled = normalizeEnabled(out, nil)
	} else {
		st.Enabled = normalizeEnabled("", err)
	}
	return st
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

// protocolFromWire maps the wizard's protocol name onto the builder enum.
func protocolFromWire(p string) (frpconf.Protocol, bool) {
	switch strings.ToLower(p) {
	case "", "quic":
		return frpconf.ProtoQUIC, true
	case "kcp":
		return frpconf.ProtoKCP, true
	case "none", "tcp":
		return frpconf.ProtoNone, true
	}
	return "", false
}

// checkRange guards numeric transport tunables before they reach the TOML
// renderer (a zero/negative value would make frp reject the config).
func checkRange(label string, v, lo, hi int) error {
	if v < lo || v > hi {
		return fmt.Errorf("%s must be %d..%d", label, lo, hi)
	}
	return nil
}

// ---- create ----------------------------------------------------------------

func (s *Server) handleServersCreate(w http.ResponseWriter, r *http.Request) {
	var req serverCreateReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.BindPort < 1 || req.BindPort > 65535 {
		writeErr(w, http.StatusBadRequest, "bindPort is required (1..65535)")
		return
	}
	if req.Name == "" {
		req.Name = "server-" + itoa(req.BindPort)
	}
	if !instanceNamePattern.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, "invalid instance name %q (want [A-Za-z0-9_.-], up to 64 chars)", req.Name)
		return
	}
	if req.BindAddr == "" {
		req.BindAddr = "::" // dual-stack, like the CLI default
	}
	if ip := net.ParseIP(req.BindAddr); ip == nil {
		writeErr(w, http.StatusBadRequest, "invalid bindAddr %q (want 0.0.0.0, :: or a tunnel IP)", req.BindAddr)
		return
	}
	proto, ok := protocolFromWire(req.Protocol)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid protocol %q (want quic|kcp|none)", req.Protocol)
		return
	}

	path := filepath.Join(s.paths.ServerDir, req.Name+".toml")
	if _, err := os.Stat(path); err == nil {
		writeErr(w, http.StatusConflict, "instance %q already exists (%s)", req.Name, path)
		return
	}
	used, err := frpconf.UsedServerPorts(s.paths.ServerDir)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot scan server ports: %v", err)
		return
	}
	if used[req.BindPort] {
		writeErr(w, http.StatusConflict, "port %d is already used by another frps instance", req.BindPort)
		return
	}

	// webServer allocation (metrics endpoint — loopback only).
	webEnabled := true
	if req.WebEnabled != nil {
		webEnabled = *req.WebEnabled
	}
	opts := frpconf.ServerOptions{
		BindAddr:    req.BindAddr,
		BindPort:    req.BindPort,
		Protocol:    proto,
		Token:       req.Token,
		WebUser:     req.WebUser,
		WebPassword: req.WebPassword,
	}
	if req.TCPMux != nil {
		opts.TCPMux = *req.TCPMux
	}
	if webEnabled {
		webUsed, err := frpconf.UsedWebServerPorts(s.paths.ServerDir)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "cannot scan webServer ports: %v", err)
			return
		}
		if req.WebPort > 0 {
			if webUsed[req.WebPort] {
				writeErr(w, http.StatusConflict, "webServer port %d is already used by another instance", req.WebPort)
				return
			}
			opts.WebPort = req.WebPort
		} else {
			p, ok := frpconf.AllocatePort(webUsed, frpconf.ServerWebPortLo, frpconf.ServerWebPortHi)
			if !ok {
				writeErr(w, http.StatusConflict, "no free webServer port in %d..%d", frpconf.ServerWebPortLo, frpconf.ServerWebPortHi)
				return
			}
			opts.WebPort = p
		}
	}

	cfgSrv, err := frpconf.NewServerConfig(opts)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	content := frpconf.RenderServer(cfgSrv)

	gate, err := s.writeGate(frpconf.KindServer, path, content)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "%v", err)
		return
	}

	unit := "frps@" + req.Name
	if out, err := s.runner.Systemctl("enable", "--now", unit); err != nil {
		audit("created frps instance %s but enable failed: %s", req.Name, strings.TrimSpace(out))
		writeJSON(w, http.StatusCreated, map[string]any{
			"name": req.Name, "file": path, "bindPort": cfgSrv.BindPort,
			"token": cfgSrv.Auth.Token, "webPort": cfgSrv.WebServer.Port,
			"webPassword": cfgSrv.WebServer.Password, "webUser": cfgSrv.WebServer.User,
			"verify": gate.VerifyMode, "backup": gate.Backup,
			"unit_error": strings.TrimSpace(strings.TrimSpace(out) + " " + err.Error()),
		})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"name": req.Name, "file": path, "bindPort": cfgSrv.BindPort,
		"token": cfgSrv.Auth.Token, "webPort": cfgSrv.WebServer.Port,
		"webPassword": cfgSrv.WebServer.Password, "webUser": cfgSrv.WebServer.User,
		"verify": gate.VerifyMode, "backup": gate.Backup,
		"unit": s.unitState(unit),
	})
}

// ---- get -------------------------------------------------------------------

type serverDetail struct {
	serverSummary
	Token       string `json:"token,omitempty"`
	WebPassword string `json:"webPassword,omitempty"`
}

func (s *Server) handleServerGet(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !instanceNamePattern.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid instance name")
		return
	}
	path := filepath.Join(s.paths.ServerDir, name+".toml")
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			writeErr(w, http.StatusNotFound, "no server instance named %q", name)
			return
		}
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	detail := serverDetail{serverSummary: s.serverSummary(name)}
	if cfg, err := frpconf.ParseServer(raw); err == nil {
		detail.Token = cfg.Auth.Token
		detail.WebPassword = cfg.WebServer.Password
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name": name, "file": path, "style": detail.Style,
		"config": detail.serverSummary, "unit": detail.Unit,
		"token": detail.Token, "webPassword": detail.WebPassword,
	})
}

// ---- update (structured, managed style only) ---------------------------------

func (s *Server) handleServerUpdate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !instanceNamePattern.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid instance name")
		return
	}
	path := filepath.Join(s.paths.ServerDir, name+".toml")
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			writeErr(w, http.StatusNotFound, "no server instance named %q", name)
			return
		}
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	style, _, _ := frpconf.Classify(raw, frpconf.KindServer)
	if style != frpconf.StyleManaged {
		writeErr(w, http.StatusConflict,
			"instance %q is %s-managed — open the raw TOML editor instead",
			name, style.String())
		return
	}
	cfg, err := frpconf.ParseServer(raw)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "existing config does not parse: %v", err)
		return
	}

	var req serverUpdateReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Port collision check excludes the file being edited.
	used, err := frpconf.UsedServerPorts(s.paths.ServerDir)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot scan server ports: %v", err)
		return
	}
	delete(used, cfg.BindPort)

	if req.BindPort != nil {
		if *req.BindPort < 1 || *req.BindPort > 65535 {
			writeErr(w, http.StatusBadRequest, "bindPort out of range")
			return
		}
		if used[*req.BindPort] {
			writeErr(w, http.StatusConflict, "port %d is already used by another frps instance", *req.BindPort)
			return
		}
		cfg.BindPort = *req.BindPort
		switch serverProtocol(cfg) {
		case "quic":
			cfg.QUICBindPort = *req.BindPort
		case "kcp":
			cfg.KCPBindPort = *req.BindPort
		}
	}
	if req.BindAddr != nil {
		if ip := net.ParseIP(*req.BindAddr); ip == nil {
			writeErr(w, http.StatusBadRequest, "invalid bindAddr %q", *req.BindAddr)
			return
		}
		cfg.BindAddr = *req.BindAddr
	}
	if req.Protocol != nil {
		proto, ok := protocolFromWire(*req.Protocol)
		if !ok {
			writeErr(w, http.StatusBadRequest, "invalid protocol %q (want quic|kcp|none)", *req.Protocol)
			return
		}
		cfg.QUICBindPort, cfg.KCPBindPort = 0, 0
		switch proto {
		case frpconf.ProtoQUIC:
			cfg.QUICBindPort = cfg.BindPort
		case frpconf.ProtoKCP:
			cfg.KCPBindPort = cfg.BindPort
		}
	}
	if req.TCPMux != nil {
		cfg.Transport.TCPMux = *req.TCPMux
	}
	if req.TCPMuxKeepaliveInterval != nil {
		if err := checkRange("tcpMuxKeepaliveInterval", *req.TCPMuxKeepaliveInterval, 0, 3600); err != nil {
			writeErr(w, http.StatusBadRequest, "%v", err)
			return
		}
		cfg.Transport.TCPMuxKeepaliveInterval = *req.TCPMuxKeepaliveInterval
	}
	if req.HeartbeatTimeout != nil {
		if err := checkRange("heartbeatTimeout", *req.HeartbeatTimeout, 1, 3600); err != nil {
			writeErr(w, http.StatusBadRequest, "%v", err)
			return
		}
		cfg.Transport.HeartbeatTimeout = *req.HeartbeatTimeout
	}
	if req.TCPKeepalive != nil {
		if err := checkRange("tcpKeepalive", *req.TCPKeepalive, 1, 3600); err != nil {
			writeErr(w, http.StatusBadRequest, "%v", err)
			return
		}
		cfg.Transport.TCPKeepalive = *req.TCPKeepalive
	}
	if req.MaxPoolCount != nil {
		if err := checkRange("maxPoolCount", *req.MaxPoolCount, 1, 1000000); err != nil {
			writeErr(w, http.StatusBadRequest, "%v", err)
			return
		}
		cfg.Transport.MaxPoolCount = *req.MaxPoolCount
	}
	if req.QUICKeepalivePeriod != nil {
		if err := checkRange("quic.keepalivePeriod", *req.QUICKeepalivePeriod, 1, 3600); err != nil {
			writeErr(w, http.StatusBadRequest, "%v", err)
			return
		}
		cfg.Transport.QUIC.KeepalivePeriod = *req.QUICKeepalivePeriod
	}
	if req.QUICMaxIdleTimeout != nil {
		if err := checkRange("quic.maxIdleTimeout", *req.QUICMaxIdleTimeout, 1, 3600); err != nil {
			writeErr(w, http.StatusBadRequest, "%v", err)
			return
		}
		cfg.Transport.QUIC.MaxIdleTimeout = *req.QUICMaxIdleTimeout
	}
	if req.QUICMaxIncomingStreams != nil {
		if err := checkRange("quic.maxIncomingStreams", *req.QUICMaxIncomingStreams, 1, 100000000); err != nil {
			writeErr(w, http.StatusBadRequest, "%v", err)
			return
		}
		cfg.Transport.QUIC.MaxIncomingStreams = *req.QUICMaxIncomingStreams
	}
	if req.Token != nil {
		if *req.Token == "" {
			writeErr(w, http.StatusBadRequest, "token may not be empty")
			return
		}
		cfg.Auth.Token = *req.Token
	}

	content, err := frpconf.ComposeServer(raw, cfg)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "%v", err)
		return
	}
	gate, err := s.writeGate(frpconf.KindServer, path, string(content))
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "%v", err)
		return
	}
	unit := "frps@" + name
	switch {
	case req.Restart == nil:
		s.restartIfActive(unit) // legacy default: apply immediately when running
	case *req.Restart:
		if out, rerr := s.runner.Systemctl("restart", unit); rerr != nil {
			audit("restart %s after edit failed: %s", unit, strings.TrimSpace(out))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name": name, "verify": gate.VerifyMode, "backup": gate.Backup,
		"unit": s.unitState(unit),
	})
}

// ---- delete -----------------------------------------------------------------

func (s *Server) handleServerDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !instanceNamePattern.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid instance name")
		return
	}
	path := filepath.Join(s.paths.ServerDir, name+".toml")
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			writeErr(w, http.StatusNotFound, "no server instance named %q", name)
			return
		}
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	unit := "frps@" + name
	if out, err := s.runner.Systemctl("disable", "--now", unit); err != nil {
		audit("disable %s failed during delete: %s", unit, strings.TrimSpace(out))
	}
	bak, err := s.backupAndRemove(path)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "delete failed: %v", err)
		return
	}
	audit("deleted frps instance %s (backup %s)", name, bak)
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "backup": bak})
}

// ---- token regeneration -------------------------------------------------------

type tokenRegenReq struct {
	Propagate *bool `json:"propagate"` // also update local client TOMLs using the old token
}

func (s *Server) handleServerTokenRegenerate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !instanceNamePattern.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid instance name")
		return
	}
	path := filepath.Join(s.paths.ServerDir, name+".toml")
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			writeErr(w, http.StatusNotFound, "no server instance named %q", name)
			return
		}
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	old, _ := frpconf.ParseServer(raw)
	if old == nil || old.Auth.Token == "" {
		writeErr(w, http.StatusUnprocessableEntity, "cannot determine the current token of %q", name)
		return
	}

	newTok, err := frpconf.RandomToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	updated, n := replaceTokenLine(string(raw), newTok)
	if n == 0 {
		writeErr(w, http.StatusConflict, "no auth.token line found in %s — edit it manually", path)
		return
	}
	gate, err := s.writeGate(frpconf.KindServer, path, updated)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "%v", err)
		return
	}
	s.restartIfActive("frps@" + name)

	resp := map[string]any{
		"name": name, "token": newTok, "verify": gate.VerifyMode, "backup": gate.Backup,
		"propagated": []string{},
	}

	propagate := reqBool(r, true)
	if propagate {
		propagated := []string{}
		clientNames, _ := frpconf.ListConfigs(s.paths.ClientDir)
		for _, cn := range clientNames {
			cpath := filepath.Join(s.paths.ClientDir, cn+".toml")
			craw, err := os.ReadFile(cpath)
			if err != nil {
				continue
			}
			ccfg, err := frpconf.ParseClient(craw)
			if err != nil || ccfg.Auth.Token != old.Auth.Token {
				continue
			}
			cupdated, n := replaceTokenLine(string(craw), newTok)
			if n == 0 {
				continue
			}
			if _, err := s.writeGate(frpconf.KindClient, cpath, cupdated); err != nil {
				audit("token propagation to %s failed: %v", cn, err)
				continue
			}
			s.restartIfActive("frpc@" + cn)
			propagated = append(propagated, cn)
		}
		resp["propagated"] = propagated
	}
	audit("regenerated token for frps@%s (propagated to %d clients)", name, len(resp["propagated"].([]string)))
	writeJSON(w, http.StatusOK, resp)
}

// ---- raw editor ----------------------------------------------------------------

func (s *Server) handleServerRawGet(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	raw, ok := s.readConfigRaw(w, s.paths.ServerDir, name)
	if !ok {
		return
	}
	style, _, _ := frpconf.Classify(raw, frpconf.KindServer)
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "style": style.String(), "content": string(raw)})
}

func (s *Server) handleServerRawPut(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !instanceNamePattern.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid instance name")
		return
	}
	var req struct {
		Content string `json:"content"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	path := filepath.Join(s.paths.ServerDir, name+".toml")
	gate, err := s.writeGate(frpconf.KindServer, path, req.Content)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "%v", err)
		return
	}
	s.restartIfActive("frps@" + name)
	style, _, _ := frpconf.Classify([]byte(req.Content), frpconf.KindServer)
	writeJSON(w, http.StatusOK, map[string]any{
		"name": name, "style": style.String(), "verify": gate.VerifyMode, "backup": gate.Backup,
	})
}

// ---- shared helpers -------------------------------------------------------------

// readConfigRaw reads dir/<name>.toml, writing the HTTP error on failure.
func (s *Server) readConfigRaw(w http.ResponseWriter, dir, name string) ([]byte, bool) {
	if !instanceNamePattern.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid instance name")
		return nil, false
	}
	raw, err := os.ReadFile(filepath.Join(dir, name+".toml"))
	if err != nil {
		if os.IsNotExist(err) {
			writeErr(w, http.StatusNotFound, "no instance named %q", name)
		} else {
			writeErr(w, http.StatusInternalServerError, "%v", err)
		}
		return nil, false
	}
	return raw, true
}

// restartIfActive restarts a unit only when it is currently active, so
// editing a stopped instance does not start it.
func (s *Server) restartIfActive(unit string) {
	if s.unitIsActive(unit) {
		_, _ = s.runner.Systemctl("restart", unit)
	}
}

// replaceTokenLine swaps the auth.token value in raw text — works for
// managed and advanced styles alike (token lines are always dotted keys).
func replaceTokenLine(raw, newToken string) (string, int) {
	lines := strings.Split(raw, "\n")
	n := 0
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "auth.token") && strings.Contains(t, "=") && !strings.HasPrefix(t, "#") {
			lines[i] = "auth.token = \"" + newToken + "\""
			n++
		}
	}
	if n == 0 {
		return raw, 0
	}
	return strings.Join(lines, "\n"), n
}

// reqBool returns the request's ?param= default value when absent.
func reqBool(r *http.Request, def bool) bool {
	v := r.URL.Query().Get("propagate")
	if v == "" {
		return def
	}
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

func itoa(n int) string { return strconv.Itoa(n) }
