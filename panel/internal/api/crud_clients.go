// frpc instance CRUD — mirrors the servers API, plus the per-instance
// proxy rules endpoint with the single TCP+UDP toggle (each port emits a
// paired tcp-<p> / udp-<p> block, exactly like the CLI's setup_client).
package api

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/frp-suite/panel/internal/frpconf"
)

// ---- DTOs ---------------------------------------------------------------------

type clientCreateReq struct {
	Name           string  `json:"name"`
	ServerAddr     string  `json:"serverAddr"`
	ServerPort     int     `json:"serverPort"`
	Token          string  `json:"token"` // empty → reuse the single local server token
	Protocol       string  `json:"protocol"` // tcp | websocket | quic | kcp
	TCPMux         *bool   `json:"tcpMux"`
	UseTLS         *bool   `json:"useTls"`     // default true
	UseCompression *bool   `json:"useCompression"` // default false
	Ports          string  `json:"ports"`  // "22,6000-6006"
	Proto          string  `json:"proto"`  // both | tcp | udp (default both)
	LocalIP        string  `json:"localIp"`
	WebEnabled     *bool   `json:"webEnabled"` // default true
	WebPort        int     `json:"webPort"`
	WebUser        string  `json:"webUser"`
	WebPassword    string  `json:"webPassword"`
}

type clientUpdateReq struct {
	ServerAddr     *string `json:"serverAddr"`
	ServerPort     *int    `json:"serverPort"`
	Token          *string `json:"token"`
	Protocol       *string `json:"protocol"`
	TCPMux         *bool   `json:"tcpMux"`
	UseTLS         *bool   `json:"useTls"`
	UseCompression *bool   `json:"useCompression"`
}

type proxyDTO struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	LocalIP    string `json:"localIp"`
	LocalPort  int    `json:"localPort"`
	RemotePort int    `json:"remotePort"`
}

type clientSummary struct {
	Name        string     `json:"name"`
	File        string     `json:"file"`
	ServerAddr  string     `json:"serverAddr"`
	ServerPort  int        `json:"serverPort"`
	Protocol    string     `json:"protocol"`
	TLS         bool       `json:"tls"`
	TCPMux      bool       `json:"tcpMux"`
	WebPort     int        `json:"webPort"`
	TokenSet    bool       `json:"tokenSet"`
	Proxies     []proxyDTO `json:"proxies"`
	Style       string     `json:"style"`
	Unit        unitState  `json:"unit"`
	ParseError  string     `json:"parseError,omitempty"`
}

// ---- list / detail ------------------------------------------------------------

func (s *Server) handleClientsList(w http.ResponseWriter, r *http.Request) {
	names, err := frpconf.ListConfigs(s.paths.ClientDir)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot list client configs: %v", err)
		return
	}
	out := []clientSummary{}
	for _, name := range names {
		out = append(out, s.clientSummary(name))
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": out})
}

func (s *Server) clientSummary(name string) clientSummary {
	sum := clientSummary{
		Name: name,
		File: filepath.Join(s.paths.ClientDir, name+".toml"),
		Proxies: []proxyDTO{},
	}
	raw, err := os.ReadFile(sum.File)
	if err != nil {
		sum.ParseError = err.Error()
		sum.Style = frpconf.StyleAdvanced.String()
		return sum
	}
	style, _, _ := frpconf.Classify(raw, frpconf.KindClient)
	sum.Style = style.String()
	cfg, err := frpconf.ParseClient(raw)
	if err != nil {
		sum.ParseError = err.Error()
	} else {
		sum.ServerAddr = cfg.ServerAddr
		sum.ServerPort = cfg.ServerPort
		sum.Protocol = cfg.Transport.Protocol
		sum.TLS = cfg.Transport.TLS.Enable
		sum.TCPMux = cfg.Transport.TCPMux
		sum.WebPort = cfg.WebServer.Port
		sum.TokenSet = cfg.Auth.Token != ""
		for _, p := range cfg.Proxies {
			sum.Proxies = append(sum.Proxies, proxyDTO{
				Name: p.Name, Type: p.Type, LocalIP: p.LocalIP,
				LocalPort: p.LocalPort, RemotePort: p.RemotePort,
			})
		}
	}
	sum.Unit = s.unitState("frpc@" + name)
	return sum
}

func (s *Server) handleClientGet(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !instanceNamePattern.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid instance name")
		return
	}
	raw, ok := s.readConfigRaw(w, s.paths.ClientDir, name)
	if !ok {
		return
	}
	sum := s.clientSummary(name)
	token := ""
	if cfg, err := frpconf.ParseClient(raw); err == nil {
		token = cfg.Auth.Token
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name": name, "file": sum.File, "style": sum.Style, "token": token,
		"config": sum, "unit": sum.Unit,
	})
}

// ---- create --------------------------------------------------------------------

func protoFromWire(p string) (frpconf.ProtoToggle, bool) {
	switch strings.ToLower(p) {
	case "", "both", "tcp+udp":
		return frpconf.ProtoTCPAndUDP, true
	case "tcp":
		return frpconf.ProtoTCPOnly, true
	case "udp":
		return frpconf.ProtoUDPOnly, true
	}
	return 0, false
}

// pickToken resolves the wizard's token: explicit wins; otherwise reuse the
// token of the single local frps config (CLI parity — setup_client does the
// same); ambiguous → the caller must choose.
func (s *Server) pickToken(explicit string) (string, error) {
	if strings.TrimSpace(explicit) != "" {
		return explicit, nil
	}
	names, err := frpconf.ListConfigs(s.paths.ServerDir)
	if err != nil {
		return "", err
	}
	if len(names) == 0 {
		return "", errNoLocalToken
	}
	if len(names) > 1 {
		return "", errAmbiguousToken
	}
	cfg, err := frpconf.ReadServer(filepath.Join(s.paths.ServerDir, names[0]+".toml"))
	if err != nil || cfg.Auth.Token == "" {
		return "", errNoLocalToken
	}
	return cfg.Auth.Token, nil
}

var (
	errNoLocalToken   = errStr("no token given and no local frps config to reuse it from")
	errAmbiguousToken = errStr("multiple local frps configs — pass an explicit token")
)

type errStr string

func (e errStr) Error() string { return string(e) }

func (s *Server) handleClientsCreate(w http.ResponseWriter, r *http.Request) {
	var req clientCreateReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if ip := net.ParseIP(req.ServerAddr); ip == nil || req.ServerAddr == "" {
		writeErr(w, http.StatusBadRequest, "serverAddr is required (IP or tunnel IP)")
		return
	}
	if req.ServerPort <= 0 {
		req.ServerPort = 7000
	}
	if req.Name == "" {
		req.Name = "client-" + itoa(req.ServerPort)
	}
	if !instanceNamePattern.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, "invalid instance name %q", req.Name)
		return
	}
	switch strings.ToLower(req.Protocol) {
	case "", "tcp", "websocket", "quic", "kcp":
	default:
		writeErr(w, http.StatusBadRequest, "invalid protocol %q (want tcp|websocket|quic|kcp)", req.Protocol)
		return
	}
	proto, ok := protoFromWire(req.Proto)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid proto %q (want both|tcp|udp)", req.Proto)
		return
	}

	token, err := s.pickToken(req.Token)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}

	specs, err := frpconf.ParsePortSpecs(req.Ports)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	if len(specs) == 0 {
		writeErr(w, http.StatusBadRequest, "ports is required (e.g. \"22,6000-6006\")")
		return
	}

	// Remote-port collisions across every config the CLI would scan too.
	used, err := s.allUsedPorts()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot scan used ports: %v", err)
		return
	}
	if collides := collide(specs, used); collides != "" {
		writeErr(w, http.StatusConflict, "remote port(s) already in use: %s", collides)
		return
	}

	path := filepath.Join(s.paths.ClientDir, req.Name+".toml")
	if _, err := os.Stat(path); err == nil {
		writeErr(w, http.StatusConflict, "instance %q already exists (%s)", req.Name, path)
		return
	}

	webEnabled := true
	if req.WebEnabled != nil {
		webEnabled = *req.WebEnabled
	}
	// Secure transport default: TLS on unless the wizard says otherwise.
	opts := frpconf.ClientOptions{
		ServerAddr: req.ServerAddr,
		ServerPort: req.ServerPort,
		Token:      token,
		Protocol:   strings.ToLower(req.Protocol),
		Ports:      specs,
		Proto:      proto,
		LocalIP:    req.LocalIP,
		UseTLS:     true,
		WebUser:    req.WebUser,
		WebPassword: req.WebPassword,
	}
	if req.TCPMux != nil {
		opts.TCPMux = *req.TCPMux
	}
	if req.UseTLS != nil {
		opts.UseTLS = *req.UseTLS
	}
	if req.UseCompression != nil {
		opts.UseCompression = *req.UseCompression
	}
	if webEnabled {
		webUsed, err := frpconf.UsedWebServerPorts(s.paths.ClientDir)
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
			p, ok := frpconf.AllocatePort(webUsed, frpconf.ClientWebPortLo, frpconf.ClientWebPortHi)
			if !ok {
				writeErr(w, http.StatusConflict, "no free webServer port in %d..%d", frpconf.ClientWebPortLo, frpconf.ClientWebPortHi)
				return
			}
			opts.WebPort = p
		}
	}

	cfg, err := frpconf.NewClientConfig(opts)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	gate, err := s.writeGate(frpconf.KindClient, path, frpconf.RenderClient(cfg))
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "%v", err)
		return
	}

	unit := "frpc@" + req.Name
	resp := map[string]any{
		"name": req.Name, "file": path, "token": token,
		"verify": gate.VerifyMode, "backup": gate.Backup,
		"proxies": len(cfg.Proxies),
	}
	if out, err := s.runner.Systemctl("enable", "--now", unit); err != nil {
		audit("created frpc instance %s but enable failed: %s", req.Name, strings.TrimSpace(out))
		resp["unit_error"] = strings.TrimSpace(strings.TrimSpace(out) + " " + err.Error())
		writeJSON(w, http.StatusCreated, resp)
		return
	}
	resp["unit"] = s.unitState(unit)
	writeJSON(w, http.StatusCreated, resp)
}

// allUsedPorts merges every port the CLI's is_port_free would consider busy:
// frps bind ports and every client's remote ports.
func (s *Server) allUsedPorts() (map[int]bool, error) {
	used := map[int]bool{}
	srv, err := frpconf.UsedServerPorts(s.paths.ServerDir)
	if err != nil {
		return nil, err
	}
	cli, err := frpconf.UsedClientRemotePorts(s.paths.ClientDir)
	if err != nil {
		return nil, err
	}
	for p := range srv {
		used[p] = true
	}
	for p := range cli {
		used[p] = true
	}
	return used, nil
}

// collide returns the sorted list of ports in specs already present in used.
func collide(specs []frpconf.PortSpec, used map[int]bool) string {
	var hits []int
	for _, sp := range specs {
		for p := sp.Start; p <= sp.End; p++ {
			if used[p] {
				hits = append(hits, p)
			}
		}
	}
	if hits == nil {
		return ""
	}
	sort.Ints(hits)
	parts := make([]string, len(hits))
	for i, p := range hits {
		parts[i] = itoa(p)
	}
	return strings.Join(parts, ",")
}

// ---- update ------------------------------------------------------------------

func (s *Server) handleClientUpdate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !instanceNamePattern.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid instance name")
		return
	}
	path := filepath.Join(s.paths.ClientDir, name+".toml")
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			writeErr(w, http.StatusNotFound, "no client instance named %q", name)
			return
		}
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	style, _, _ := frpconf.Classify(raw, frpconf.KindClient)
	if style != frpconf.StyleManaged {
		writeErr(w, http.StatusConflict,
			"instance %q is %s-managed — structured edits would drop unknown keys; use the raw editor instead",
			name, style.String())
		return
	}
	cfg, err := frpconf.ParseClient(raw)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "existing config does not parse: %v", err)
		return
	}

	var req clientUpdateReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.ServerAddr != nil {
		if net.ParseIP(*req.ServerAddr) == nil {
			writeErr(w, http.StatusBadRequest, "invalid serverAddr %q", *req.ServerAddr)
			return
		}
		cfg.ServerAddr = *req.ServerAddr
	}
	if req.ServerPort != nil {
		if *req.ServerPort < 1 || *req.ServerPort > 65535 {
			writeErr(w, http.StatusBadRequest, "serverPort out of range")
			return
		}
		cfg.ServerPort = *req.ServerPort
	}
	if req.Token != nil {
		if *req.Token == "" {
			writeErr(w, http.StatusBadRequest, "token may not be empty")
			return
		}
		cfg.Auth.Token = *req.Token
	}
	if req.Protocol != nil {
		switch strings.ToLower(*req.Protocol) {
		case "tcp", "websocket", "quic", "kcp":
			cfg.Transport.Protocol = strings.ToLower(*req.Protocol)
		default:
			writeErr(w, http.StatusBadRequest, "invalid protocol %q", *req.Protocol)
			return
		}
	}
	if req.TCPMux != nil {
		cfg.Transport.TCPMux = *req.TCPMux
	}
	if req.UseTLS != nil {
		cfg.Transport.TLS.Enable = *req.UseTLS
	}
	if req.UseCompression != nil {
		for i := range cfg.Proxies {
			cfg.Proxies[i].Transport.UseCompression = *req.UseCompression
		}
	}

	gate, err := s.writeGate(frpconf.KindClient, path, frpconf.RenderClient(cfg))
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "%v", err)
		return
	}
	s.restartIfActive("frpc@" + name)
	writeJSON(w, http.StatusOK, map[string]any{
		"name": name, "verify": gate.VerifyMode, "backup": gate.Backup,
		"unit": s.unitState("frpc@" + name),
	})
}

// ---- delete ---------------------------------------------------------------------

func (s *Server) handleClientDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !instanceNamePattern.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid instance name")
		return
	}
	path := filepath.Join(s.paths.ClientDir, name+".toml")
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			writeErr(w, http.StatusNotFound, "no client instance named %q", name)
			return
		}
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	unit := "frpc@" + name
	if out, err := s.runner.Systemctl("disable", "--now", unit); err != nil {
		audit("disable %s failed during delete: %s", unit, strings.TrimSpace(out))
	}
	bak, err := s.backupAndRemove(path)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "delete failed: %v", err)
		return
	}
	audit("deleted frpc instance %s (backup %s)", name, bak)
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "backup": bak})
}

// ---- proxies ----------------------------------------------------------------------

type proxiesAddReq struct {
	Ports   string `json:"ports"`
	Proto   string `json:"proto"`   // both | tcp | udp (default both)
	LocalIP string `json:"localIp"`
}

func (s *Server) handleClientProxiesAdd(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	cfg, _, path, ok := s.loadManagedClient(w, name)
	if !ok {
		return
	}
	var req proxiesAddReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	specs, err := frpconf.ParsePortSpecs(req.Ports)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	if len(specs) == 0 {
		writeErr(w, http.StatusBadRequest, "ports is required")
		return
	}
	proto, ok := protoFromWire(req.Proto)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid proto %q (want both|tcp|udp)", req.Proto)
		return
	}
	if req.LocalIP != "" && net.ParseIP(req.LocalIP) == nil {
		writeErr(w, http.StatusBadRequest, "invalid localIp %q", req.LocalIP)
		return
	}

	// Collisions: everything busy host-wide, plus this client's own ports.
	used, err := s.allUsedPorts()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot scan used ports: %v", err)
		return
	}
	if collides := collide(specs, used); collides != "" {
		writeErr(w, http.StatusConflict, "remote port(s) already in use: %s", collides)
		return
	}

	localIP := req.LocalIP
	if localIP == "" {
		if len(cfg.Proxies) > 0 {
			localIP = cfg.Proxies[0].LocalIP
		} else {
			localIP = "127.0.0.1"
		}
	}
	added := frpconf.BuildProxies(specs, proto, localIP, true, proxyCompression(cfg))
	cfg.Proxies = append(cfg.Proxies, added...)

	gate, err := s.writeGate(frpconf.KindClient, path, frpconf.RenderClient(cfg))
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "%v", err)
		return
	}
	s.restartIfActive("frpc@" + name)
	writeJSON(w, http.StatusCreated, map[string]any{
		"name": name, "added": len(added), "total": len(cfg.Proxies),
		"verify": gate.VerifyMode, "backup": gate.Backup,
	})
}

func proxyCompression(cfg *frpconf.ClientConfig) bool {
	for _, p := range cfg.Proxies {
		return p.Transport.UseCompression
	}
	return false
}

type proxiesReplaceReq struct {
	Proxies []proxyDTO `json:"proxies"`
}

func (s *Server) handleClientProxiesReplace(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	cfg, _, path, ok := s.loadManagedClient(w, name)
	if !ok {
		return
	}
	var req proxiesReplaceReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	names := map[string]bool{}
	var proxies []frpconf.Proxy
	for i, p := range req.Proxies {
		if !instanceNamePattern.MatchString(p.Name) {
			writeErr(w, http.StatusBadRequest, "proxy[%d]: invalid name %q", i, p.Name)
			return
		}
		if names[p.Name] {
			writeErr(w, http.StatusBadRequest, "proxy name %q used more than once", p.Name)
			return
		}
		names[p.Name] = true
		if p.Type != "tcp" && p.Type != "udp" {
			writeErr(w, http.StatusBadRequest, "proxy[%d]: type must be tcp or udp", i)
			return
		}
		if net.ParseIP(p.LocalIP) == nil {
			writeErr(w, http.StatusBadRequest, "proxy[%d]: invalid localIp", i)
			return
		}
		if p.LocalPort < 1 || p.LocalPort > 65535 || p.RemotePort < 1 || p.RemotePort > 65535 {
			writeErr(w, http.StatusBadRequest, "proxy[%d]: ports out of range", i)
			return
		}
		var px frpconf.Proxy
		px.Name, px.Type, px.LocalIP = p.Name, p.Type, p.LocalIP
		px.LocalPort, px.RemotePort = p.LocalPort, p.RemotePort
		px.Transport.UseEncryption = true
		px.Transport.UseCompression = proxyCompression(cfg)
		proxies = append(proxies, px)
	}
	cfg.Proxies = proxies

	gate, err := s.writeGate(frpconf.KindClient, path, frpconf.RenderClient(cfg))
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "%v", err)
		return
	}
	s.restartIfActive("frpc@" + name)
	writeJSON(w, http.StatusOK, map[string]any{
		"name": name, "total": len(proxies), "verify": gate.VerifyMode, "backup": gate.Backup,
	})
}

func (s *Server) handleClientProxiesDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	cfg, _, path, ok := s.loadManagedClient(w, name)
	if !ok {
		return
	}
	portsParam := r.URL.Query().Get("ports")
	if portsParam == "" {
		var req struct {
			Ports string `json:"ports"`
		}
		if err := decodeJSON(r, &req); err == nil {
			portsParam = req.Ports
		}
	}
	specs, err := frpconf.ParsePortSpecs(portsParam)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	doomed := map[int]bool{}
	for _, sp := range specs {
		for p := sp.Start; p <= sp.End; p++ {
			doomed[p] = true
		}
	}

	var kept []frpconf.Proxy
	var removed []string
	for _, p := range cfg.Proxies {
		if doomed[p.LocalPort] || doomed[p.RemotePort] {
			removed = append(removed, p.Name)
			continue
		}
		kept = append(kept, p)
	}
	if len(removed) == 0 {
		writeErr(w, http.StatusNotFound, "no proxy matches ports %q in %q", portsParam, name)
		return
	}
	cfg.Proxies = kept

	gate, err := s.writeGate(frpconf.KindClient, path, frpconf.RenderClient(cfg))
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "%v", err)
		return
	}
	s.restartIfActive("frpc@" + name)
	writeJSON(w, http.StatusOK, map[string]any{
		"name": name, "removed": removed, "total": len(kept),
		"verify": gate.VerifyMode, "backup": gate.Backup,
	})
}

// loadManagedClient loads a client config that must exist and be managed
// style (structured proxy edits need the full model). Raw edits go through
// the raw editor instead.
func (s *Server) loadManagedClient(w http.ResponseWriter, name string) (*frpconf.ClientConfig, []byte, string, bool) {
	if !instanceNamePattern.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid instance name")
		return nil, nil, "", false
	}
	path := filepath.Join(s.paths.ClientDir, name+".toml")
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			writeErr(w, http.StatusNotFound, "no client instance named %q", name)
		} else {
			writeErr(w, http.StatusInternalServerError, "%v", err)
		}
		return nil, nil, "", false
	}
	style, _, _ := frpconf.Classify(raw, frpconf.KindClient)
	if style != frpconf.StyleManaged {
		writeErr(w, http.StatusConflict,
			"instance %q is %s-managed — proxy edits need the managed model; use the raw editor", name, style.String())
		return nil, nil, "", false
	}
	cfg, err := frpconf.ParseClient(raw)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "existing config does not parse: %v", err)
		return nil, nil, "", false
	}
	return cfg, raw, path, true
}

// ---- raw editor --------------------------------------------------------------------

func (s *Server) handleClientRawGet(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	raw, ok := s.readConfigRaw(w, s.paths.ClientDir, name)
	if !ok {
		return
	}
	style, _, _ := frpconf.Classify(raw, frpconf.KindClient)
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "style": style.String(), "content": string(raw)})
}

func (s *Server) handleClientRawPut(w http.ResponseWriter, r *http.Request) {
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
	path := filepath.Join(s.paths.ClientDir, name+".toml")
	gate, err := s.writeGate(frpconf.KindClient, path, req.Content)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "%v", err)
		return
	}
	s.restartIfActive("frpc@" + name)
	style, _, _ := frpconf.Classify([]byte(req.Content), frpconf.KindClient)
	writeJSON(w, http.StatusOK, map[string]any{
		"name": name, "style": style.String(), "verify": gate.VerifyMode, "backup": gate.Backup,
	})
}
