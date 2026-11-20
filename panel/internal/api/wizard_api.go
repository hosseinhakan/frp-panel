// FRP over GRE Reverse quick-setup wizard.
//
// One endpoint creates both halves of the recommended Iran ↔ Foreign topology
// in a single step, so users never have to configure GRE and FRP separately:
//
//	Iran (entry/bridge)    : gt11 10.100.111.2/30, frps bound to 10.100.111.2:7025
//	Foreign (exit/backend) : gt11 10.100.111.1/30, frpc dialing 10.100.111.2:7025
//
// End users connect to Iran Public IP:<forwarded port>; the Foreign node dials
// back through GRE and exposes its 127.0.0.1:<port> services on that port.
//
// The Iran call returns a mirror payload/command the Foreign node pastes into
// its own wizard (same endpoint, role=foreign), keeping the GRE pair, control
// port and generated 32-char token in sync.
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
	"github.com/frp-suite/panel/internal/gre"
	"github.com/frp-suite/panel/internal/watchdog"
)

const (
	wizardIface          = "gt11"
	wizardIranPrivate    = "10.100.111.2/30" // frps side (entry)
	wizardForeignPrivate = "10.100.111.1/30" // frpc side (exit)
	wizardServerAddr     = "10.100.111.2"
	wizardDefaultPort    = 7025
	wizardMTU            = 1400
	wizardMSS            = "1220" // safe TCPMSS clamp for GRE (1240 is the other recommended value)
)

// wizardTokenPattern bounds pasted tokens before they reach the TOML renderer
// (auth.token is written as a quoted string; keep it to a shell-safe charset).
var wizardTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{8,128}$`)

// ---- DTOs ------------------------------------------------------------------

type wizardGREFRPReq struct {
	Role string `json:"role"` // iran|entry|frps | foreign|exit|frpc

	// Shared / Iran (entry) inputs.
	IranPublicIP    string `json:"iranPublicIp"`
	ForeignPublicIP string `json:"foreignPublicIp"`
	Iface           string `json:"iface"`
	Subnet          string `json:"subnet"` // optional 10.100.<n>.0/30; defaults to 10.100.111.0/30
	ControlPort     int    `json:"controlPort"`
	Protocol        string `json:"protocol"` // tcp | quic | kcp
	MSSMode         string `json:"mssMode"`  // optional; default 1220
	ServerName      string `json:"serverName"`

	// Foreign (exit) inputs.
	MirrorPayload  string `json:"mirrorPayload"`
	LocalPorts     string `json:"localPorts"`
	Proto          string `json:"proto"`      // both | tcp | udp (default both)
	LocalIP        string `json:"localIp"`    // proxy localIP, default 127.0.0.1
	Token          string `json:"token"`      // explicit when not using a payload
	ServerAddr     string `json:"serverAddr"` // explicit override, default 10.100.111.2
	ClientName     string `json:"clientName"`
	EnableWatchdog *bool  `json:"enableWatchdog"` // default true (dual-layer auto-heal)
}

func (r *wizardGREFRPReq) watchdogEnabled() bool {
	return r.EnableWatchdog == nil || *r.EnableWatchdog
}

// mirrorParams is the parsed foreign-side view of the tunnel + FRP control link.
type mirrorParams struct {
	Iface           string
	LocalPublicIP   string
	RemotePublicIP  string
	LocalPrivateIP  string
	RemotePrivateIP string
	MTU             int
	MSSMode         string
	ServerAddr      string
	ControlPort     int
	Protocol        string
	Token           string
}

// ---- entry handler ---------------------------------------------------------

func (s *Server) handleWizardGREFRP(w http.ResponseWriter, r *http.Request) {
	var req wizardGREFRPReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	switch strings.ToLower(strings.TrimSpace(req.Role)) {
	case "iran", "entry", "frps":
		s.wizardIran(w, &req)
	case "foreign", "exit", "frpc":
		s.wizardForeign(w, &req)
	default:
		writeErr(w, http.StatusBadRequest, `role must be "iran" (entry/frps) or "foreign" (exit/frpc)`)
	}
}

// wizardIran creates the entry node: a GRE tunnel (next free gtNN / 10.100.<n>.0/30
// by default) and an frps instance bound strictly to that tunnel IP. It
// returns the mirror material for the Foreign node.
func (s *Server) wizardIran(w http.ResponseWriter, req *wizardGREFRPReq) {
	iface, octet, autoWarnings, err := s.allocateWizardGRE(req.Iface, req.Subnet,
		req.IranPublicIP, req.ForeignPublicIP)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot allocate GRE tunnel: %v", err)
		return
	}
	localPriv := fmt.Sprintf("10.100.%d.2/30", octet)
	remotePriv := fmt.Sprintf("10.100.%d.1/30", octet)
	serverAddr := fmt.Sprintf("10.100.%d.2", octet)

	t, err := s.wizardTunnel(req.IranPublicIP, req.ForeignPublicIP, iface,
		localPriv, remotePriv, req.MSSMode)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	if req.ControlPort != 0 && (req.ControlPort < 1 || req.ControlPort > 65535) {
		writeErr(w, http.StatusBadRequest, "controlPort must be 1..65535")
		return
	}

	// Re-running the wizard for the same pair refreshes the existing frps
	// instance (same tunnel IP + port) instead of allocating a second one.
	existingName, existingPort, reuseServer := s.serverForBindAddr(serverAddr)
	var port int
	var portWarnings []string
	if reuseServer {
		port = existingPort
	} else {
		port, portWarnings, err = s.allocateControlPort(req.ControlPort)
		if err != nil {
			writeErr(w, http.StatusConflict, "%v", err)
			return
		}
	}
	autoWarnings = append(autoWarnings, portWarnings...)

	proto, protoName, ok := wizardServerProtocol(req.Protocol)
	if !ok {
		writeErr(w, http.StatusBadRequest, "protocol must be tcp|quic|kcp")
		return
	}

	name := strings.TrimSpace(req.ServerName)
	if name == "" {
		name = "server-" + itoa(port)
	}
	if !instanceNamePattern.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid serverName %q", name)
		return
	}
	if reuseServer && name != existingName {
		writeErr(w, http.StatusConflict,
			"a frps instance for this tunnel IP already exists as %q; use that name or delete it first", existingName)
		return
	}
	path := filepath.Join(s.paths.ServerDir, name+".toml")
	if _, err := os.Stat(path); err == nil && !reuseServer {
		writeErr(w, http.StatusConflict, "frps instance %q already exists (%s)", name, path)
		return
	}

	cfg, err := frpconf.NewServerConfig(frpconf.ServerOptions{
		BindAddr: serverAddr,
		BindPort: port,
		Protocol: proto,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot build frps config: %v", err)
		return
	}

	gres, gerr := s.upsertWizardTunnel(t)
	if gerr != nil {
		writeErr(w, http.StatusInternalServerError, "cannot create GRE tunnel: %v", gerr)
		return
	}

	gate, err := s.writeGate(frpconf.KindServer, path, frpconf.RenderServer(cfg))
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "%v", err)
		return
	}
	unit := "frps@" + name
	unitErr := ""
	if out, err := s.runner.Systemctl("enable", "--now", unit); err != nil {
		unitErr = strings.TrimSpace(strings.TrimSpace(out) + " " + err.Error())
		audit("wizard created frps@%s but enable failed: %s", name, unitErr)
	}
	audit("wizard (iran/entry) created %s + %s (%s %d)", t.Name, unit, cfg.BindAddr, port)

	mp := mirrorParams{
		Iface:           t.Iface,
		LocalPublicIP:   t.RemotePublicIP, // foreign
		RemotePublicIP:  t.LocalPublicIP,  // iran
		LocalPrivateIP:  t.RemotePrivateIP,
		RemotePrivateIP: t.LocalPrivateIP,
		MTU:             t.MTU,
		MSSMode:         t.MSSMode,
		ServerAddr:      cfg.BindAddr,
		ControlPort:     port,
		Protocol:        protoName,
		Token:           cfg.Auth.Token,
	}

	wd := map[string]any{"enabled": false, "skipped": true}
	if req.watchdogEnabled() {
		wd = s.wizardEnableWatchdog()
	}

	resp := map[string]any{
		"role":     "iran",
		"topology": wizardTopologyFor(t.Iface, cfg.BindAddr),
		"tunnel":   gres.Tunnel,
		"warnings": append(append([]string{}, gres.Warnings...), autoWarnings...),
		"backup":   gres.Backup,
		"server": map[string]any{
			"name": name, "file": path, "bindAddr": cfg.BindAddr, "bindPort": port,
			"protocol": protoName, "token": cfg.Auth.Token, "unit": unit,
		},
		"watchdog":       wd,
		"verify":         gate.VerifyMode,
		"mirror_payload": renderMirrorPayload(mp),
		"mirror_command": renderMirrorCommand(mp, "8443,2053,443"),
		"next_step":      "Paste the mirror payload (or run the mirror command) on the Foreign/exit node, add the local ports it should expose, and run the wizard there.",
	}
	if unitErr != "" {
		resp["unit_error"] = unitErr
	}
	if gres.UnitError != "" {
		resp["tunnel_unit_error"] = gres.UnitError
	}
	writeJSON(w, http.StatusCreated, resp)
}

// wizardForeign creates the exit node: the mirrored GRE pair and an frpc
// instance dialing the Iran tunnel IP. It then runs the GRE ping + frpc
// status link test.
func (s *Server) wizardForeign(w http.ResponseWriter, req *wizardGREFRPReq) {
	mp, err := resolveMirror(req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	if mp.ControlPort < 1 || mp.ControlPort > 65535 {
		writeErr(w, http.StatusBadRequest, "controlPort must be 1..65535")
		return
	}
	clientProto, ok := wizardClientProtocol(mp.Protocol)
	if !ok {
		writeErr(w, http.StatusBadRequest, "protocol must be tcp|quic|kcp")
		return
	}
	mp.Protocol = clientProto
	if !wizardTokenPattern.MatchString(mp.Token) {
		writeErr(w, http.StatusBadRequest, "token is required (paste the mirror payload or pass an 8..128 char token)")
		return
	}
	if ip := net.ParseIP(mp.ServerAddr); ip == nil || ip.To4() == nil {
		writeErr(w, http.StatusBadRequest, "serverAddr must be an IPv4 address (the Iran tunnel IP)")
		return
	}

	if err := s.foreignSubnetConflict(mp.LocalPrivateIP, mp.LocalPublicIP, mp.RemotePublicIP); err != nil {
		writeErr(w, http.StatusConflict, "%v", err)
		return
	}
	iface, ifaceWarnings, err := s.allocateForeignIface(mp.Iface, mp.LocalPublicIP, mp.RemotePublicIP)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot allocate GRE interface: %v", err)
		return
	}
	t, err := s.wizardTunnel(mp.LocalPublicIP, mp.RemotePublicIP, iface,
		mp.LocalPrivateIP, mp.RemotePrivateIP, mp.MSSMode)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}

	specs, err := frpconf.ParsePortSpecs(req.LocalPorts)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	if len(specs) == 0 {
		writeErr(w, http.StatusBadRequest, "localPorts is required (e.g. \"8443,2053,443\")")
		return
	}
	proto, ok := protoFromWire(req.Proto)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid proto %q (want both|tcp|udp)", req.Proto)
		return
	}
	localIP := strings.TrimSpace(req.LocalIP)
	if localIP == "" {
		localIP = "127.0.0.1"
	}
	if net.ParseIP(localIP) == nil {
		writeErr(w, http.StatusBadRequest, "invalid localIp %q", localIP)
		return
	}

	name := strings.TrimSpace(req.ClientName)
	if name == "" {
		name = "client-" + itoa(mp.ControlPort)
	}
	if !instanceNamePattern.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid clientName %q", name)
		return
	}
	path := filepath.Join(s.paths.ClientDir, name+".toml")
	reuseClient := false
	var oldClient *frpconf.ClientConfig
	if old, rerr := frpconf.ReadClient(path); rerr == nil {
		if old.ServerAddr == mp.ServerAddr && old.ServerPort == mp.ControlPort {
			reuseClient = true
			oldClient = old
		}
	}
	if _, err := os.Stat(path); err == nil && !reuseClient {
		writeErr(w, http.StatusConflict, "frpc instance %q already exists (%s)", name, path)
		return
	}
	used, err := s.allUsedPorts()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot scan used ports: %v", err)
		return
	}
	// Re-running for the same control link refreshes this client: its own
	// remote ports must not count as a collision with itself.
	if reuseClient && oldClient != nil {
		for _, p := range oldClient.Proxies {
			delete(used, p.RemotePort)
		}
	}
	if collides := collide(specs, used); collides != "" {
		writeErr(w, http.StatusConflict, "remote port(s) already in use on this node: %s", collides)
		return
	}

	var webPort int
	var webOK bool
	if reuseClient && oldClient != nil && oldClient.WebServer.Port > 0 {
		webPort, webOK = oldClient.WebServer.Port, true
	} else {
		webUsed, werr := frpconf.UsedWebServerPorts(s.paths.ClientDir)
		if werr != nil {
			writeErr(w, http.StatusInternalServerError, "cannot scan webServer ports: %v", werr)
			return
		}
		webPort, webOK = frpconf.AllocatePort(webUsed, frpconf.ClientWebPortLo, frpconf.ClientWebPortHi)
	}
	if !webOK {
		writeErr(w, http.StatusConflict, "no free webServer port in %d..%d",
			frpconf.ClientWebPortLo, frpconf.ClientWebPortHi)
		return
	}

	cfg, err := frpconf.NewClientConfig(frpconf.ClientOptions{
		ServerAddr:     mp.ServerAddr,
		ServerPort:     mp.ControlPort,
		Token:          mp.Token,
		Protocol:       mp.Protocol,
		Ports:          specs,
		Proto:          proto,
		LocalIP:        localIP,
		UseTLS:         true,
		UseCompression: false,
		WebPort:        webPort,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}

	gres, gerr := s.upsertWizardTunnel(t)
	if gerr != nil {
		writeErr(w, http.StatusInternalServerError, "cannot create GRE tunnel: %v", gerr)
		return
	}

	gate, err := s.writeGate(frpconf.KindClient, path, frpconf.RenderClient(cfg))
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "%v", err)
		return
	}
	unit := "frpc@" + name
	unitErr := ""
	if out, err := s.runner.Systemctl("enable", "--now", unit); err != nil {
		unitErr = strings.TrimSpace(strings.TrimSpace(out) + " " + err.Error())
		audit("wizard created frpc@%s but enable failed: %s", name, unitErr)
	}
	audit("wizard (foreign/exit) created %s + %s (dialing %s:%d, %d proxies)",
		t.Name, unit, mp.ServerAddr, mp.ControlPort, len(cfg.Proxies))

	link := s.wizardLinkTest(t, name)
	wd := map[string]any{"enabled": false, "skipped": true}
	if req.watchdogEnabled() {
		wd = s.wizardEnableWatchdog()
	}
	resp := map[string]any{
		"role":     "foreign",
		"topology": wizardTopologyFor(t.Iface, mp.ServerAddr),
		"tunnel":   gres.Tunnel,
		"warnings": append(append([]string{}, gres.Warnings...), ifaceWarnings...),
		"backup":   gres.Backup,
		"client": map[string]any{
			"name": name, "file": path, "serverAddr": cfg.ServerAddr,
			"serverPort": cfg.ServerPort, "protocol": cfg.Transport.Protocol,
			"tls": cfg.Transport.TLS.Enable, "proxies": len(cfg.Proxies),
			"webPort": cfg.WebServer.Port, "tokenSet": cfg.Auth.Token != "", "unit": unit,
		},
		"watchdog":  wd,
		"verify":    gate.VerifyMode,
		"link_test": link,
	}
	if unitErr != "" {
		resp["unit_error"] = unitErr
	}
	if gres.UnitError != "" {
		resp["tunnel_unit_error"] = gres.UnitError
	}
	writeJSON(w, http.StatusCreated, resp)
}

func wizardTopologyFor(iface, serverAddr string) string {
	return fmt.Sprintf("User -> Iran Public IP:<port> -> frps (Iran, %s) -> GRE %s -> frpc (Foreign) -> Foreign 127.0.0.1:<port>", serverAddr, iface)
}

// ---- shared helpers --------------------------------------------------------

// wizardTunnel validates and normalises a GT11 definition for one role.
func (s *Server) wizardTunnel(localPub, remotePub, iface, localPriv, remotePriv, mss string) (gre.Tunnel, error) {
	iface = strings.TrimSpace(iface)
	if iface == "" {
		iface = wizardIface
	}
	if strings.TrimSpace(localPub) == "" || strings.TrimSpace(remotePub) == "" {
		return gre.Tunnel{}, fmt.Errorf("both the Iran and Foreign public IPs are required")
	}
	if mss == "" {
		mss = wizardMSS
	}
	switch mss {
	case "clamp", "1360", "1240", "1220", "off":
	default:
		return gre.Tunnel{}, fmt.Errorf("invalid mssMode %q (want clamp|1360|1240|1220|off)", mss)
	}
	t := gre.Tunnel{
		Name:            iface,
		LocalPublicIP:   strings.TrimSpace(localPub),
		RemotePublicIP:  strings.TrimSpace(remotePub),
		Iface:           iface,
		LocalPrivateIP:  localPriv,
		RemotePrivateIP: remotePriv,
		MTU:             wizardMTU,
		MSSMode:         mss,
	}
	if _, err := t.Validate(); err != nil {
		return gre.Tunnel{}, err
	}
	return t, nil
}

type wizardTunnelResult struct {
	Tunnel    greTunnelResp
	Warnings  []string
	Backup    string
	UnitError string
}

// upsertWizardTunnel writes the env (with a .bak when replacing), installs the
// canonical helper/unit and enables gre-tunnel@<name>.
func (s *Server) upsertWizardTunnel(t gre.Tunnel) (wizardTunnelResult, error) {
	warnings, err := t.Validate()
	if err != nil {
		return wizardTunnelResult{}, err
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
		return wizardTunnelResult{}, fmt.Errorf("install GRE assets: %w", err)
	}
	if err := gre.Write(s.paths.GREDir, t); err != nil {
		return wizardTunnelResult{}, err
	}
	res := wizardTunnelResult{Warnings: warnings, Backup: backup}
	unit := "gre-tunnel@" + t.Name
	if out, err := s.runner.Systemctl("enable", "--now", unit); err != nil {
		res.UnitError = strings.TrimSpace(strings.TrimSpace(out) + " " + err.Error())
		audit("wizard wrote %s but enable failed: %s", unit, res.UnitError)
	}
	res.Tunnel = s.greResp(t)
	return res, nil
}

// wizardEnableWatchdog installs the canonical dual-layer watchdog, seeds the
// fast defaults when no env exists (15s / 3 / 60s), and enables the unit.
// A user-customised watchdog.env is never overwritten.
func (s *Server) wizardEnableWatchdog() map[string]any {
	res := map[string]any{"enabled": false}
	if err := s.ensureWatchdogAssets(); err != nil {
		res["error"] = err.Error()
		return res
	}
	envPath := s.watchdogEnvPath()
	env, ok := watchdog.Read(envPath)
	if !ok {
		env = watchdog.Default()
		if err := os.MkdirAll(s.paths.EtcPanelDir, 0o755); err == nil {
			if werr := os.WriteFile(envPath, []byte(watchdog.Render(env)), 0o600); werr != nil {
				res["error"] = werr.Error()
			}
		}
	}
	res["config"] = env

	unitErr := ""
	if out, err := s.runner.Systemctl("enable", "--now", "frp-watchdog"); err != nil {
		unitErr = strings.TrimSpace(strings.TrimSpace(out) + " " + err.Error())
		audit("wizard could not enable frp-watchdog: %s", unitErr)
	}
	// Pick up a changed env even when the unit was already running.
	s.restartIfActive("frp-watchdog")
	res["unit"] = s.unitState("frp-watchdog")
	if unitErr != "" {
		res["unit_error"] = unitErr
	} else {
		res["enabled"] = true
	}
	return res
}

// wizardLinkTest pings the Iran tunnel IP through gt11 and reports whether the
// frpc unit is active. Network failure is a result, never an API error.
func (s *Server) wizardLinkTest(t gre.Tunnel, clientName string) map[string]any {
	peer := strings.SplitN(t.RemotePrivateIP, "/", 2)[0]
	out, err := s.runner.Exec("ping", "-c", "3", "-W", "2", "-I", t.Iface, peer)
	frpcActive := s.unitIsActive("frpc@" + clientName)
	res := map[string]any{
		"iface":       t.Iface,
		"peer":        peer,
		"output":      strings.TrimSpace(out),
		"reachable":   false,
		"frpc_unit":   "frpc@" + clientName,
		"frpc_active": frpcActive,
		"ok":          false,
	}
	if err != nil {
		res["error"] = err.Error()
		return res
	}
	loss, avg := parsePing(out)
	reachable := avg > 0 || loss < 100
	res["reachable"] = reachable
	res["loss_pct"] = loss
	if avg > 0 {
		res["rtt_ms"] = avg
	}
	res["ok"] = reachable && frpcActive
	return res
}

func resolveMirror(req *wizardGREFRPReq) (mirrorParams, error) {
	mp := mirrorParams{}
	if strings.TrimSpace(req.MirrorPayload) != "" {
		parsed, err := parseMirrorPayload(req.MirrorPayload)
		if err != nil {
			return mp, err
		}
		mp = parsed
	}
	// Explicit fields override the payload (handy when a user edits one value).
	if v := strings.TrimSpace(req.Iface); v != "" {
		mp.Iface = v
	}
	if v := strings.TrimSpace(req.ForeignPublicIP); v != "" {
		mp.LocalPublicIP = v
	}
	if v := strings.TrimSpace(req.IranPublicIP); v != "" {
		mp.RemotePublicIP = v
	}
	if v := strings.TrimSpace(req.ServerAddr); v != "" {
		mp.ServerAddr = v
	}
	if req.ControlPort > 0 {
		mp.ControlPort = req.ControlPort
	}
	if v := strings.TrimSpace(req.Token); v != "" {
		mp.Token = v
	}
	if v := strings.TrimSpace(req.Protocol); v != "" {
		mp.Protocol = v
	}
	if v := strings.TrimSpace(req.MSSMode); v != "" {
		mp.MSSMode = v
	}

	if mp.Iface == "" {
		mp.Iface = wizardIface
	}
	if mp.LocalPrivateIP == "" {
		mp.LocalPrivateIP = wizardForeignPrivate
	}
	if mp.RemotePrivateIP == "" {
		mp.RemotePrivateIP = wizardIranPrivate
	}
	if mp.MTU == 0 {
		mp.MTU = wizardMTU
	}
	if mp.MSSMode == "" {
		mp.MSSMode = wizardMSS
	}
	if mp.ServerAddr == "" {
		mp.ServerAddr = wizardServerAddr
	}
	if mp.ControlPort == 0 {
		mp.ControlPort = wizardDefaultPort
	}
	if mp.Protocol == "" {
		mp.Protocol = "tcp"
	}
	return mp, nil
}

// parseMirrorPayload reads the KEY=VALUE block the Iran wizard prints.
func parseMirrorPayload(payload string) (mirrorParams, error) {
	mp := mirrorParams{}
	for _, line := range strings.Split(payload, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return mp, fmt.Errorf("invalid mirror payload line %q (want KEY=VALUE)", line)
		}
		key = strings.ToUpper(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		switch key {
		case "IFACE":
			mp.Iface = val
		case "LOCAL_PUBLIC_IP":
			mp.LocalPublicIP = val
		case "REMOTE_PUBLIC_IP":
			mp.RemotePublicIP = val
		case "LOCAL_PRIVATE_IP":
			mp.LocalPrivateIP = val
		case "REMOTE_PRIVATE_IP":
			mp.RemotePrivateIP = val
		case "MTU":
			n, err := strconv.Atoi(val)
			if err != nil {
				return mp, fmt.Errorf("invalid MTU %q in mirror payload", val)
			}
			mp.MTU = n
		case "MSS_MODE":
			mp.MSSMode = val
		case "SERVER_ADDR":
			mp.ServerAddr = val
		case "CONTROL_PORT":
			n, err := strconv.Atoi(val)
			if err != nil {
				return mp, fmt.Errorf("invalid CONTROL_PORT %q in mirror payload", val)
			}
			mp.ControlPort = n
		case "PROTOCOL":
			mp.Protocol = strings.ToLower(val)
		case "TOKEN":
			mp.Token = val
		default:
			// tolerate unknown keys like the GRE env parser does
		}
	}
	if mp.LocalPublicIP == "" || mp.RemotePublicIP == "" {
		return mp, fmt.Errorf("mirror payload is missing LOCAL_PUBLIC_IP / REMOTE_PUBLIC_IP")
	}
	return mp, nil
}

func renderMirrorPayload(m mirrorParams) string {
	var b strings.Builder
	b.WriteString("# FRP Tunnel Suite — FRP over GRE Reverse mirror (paste on the FOREIGN / exit node)\n")
	fmt.Fprintf(&b, "# Flow: User -> Iran Public IP:<port> -> frps (Iran) -> GRE %s -> frpc (Foreign) -> 127.0.0.1:<port>\n", m.Iface)
	fmt.Fprintf(&b, "IFACE=%s\n", m.Iface)
	fmt.Fprintf(&b, "LOCAL_PUBLIC_IP=%s\n", m.LocalPublicIP)   // foreign
	fmt.Fprintf(&b, "REMOTE_PUBLIC_IP=%s\n", m.RemotePublicIP) // iran
	fmt.Fprintf(&b, "LOCAL_PRIVATE_IP=%s\n", m.LocalPrivateIP)
	fmt.Fprintf(&b, "REMOTE_PRIVATE_IP=%s\n", m.RemotePrivateIP)
	fmt.Fprintf(&b, "MTU=%d\n", m.MTU)
	fmt.Fprintf(&b, "MSS_MODE=%s\n", m.MSSMode)
	fmt.Fprintf(&b, "SERVER_ADDR=%s\n", m.ServerAddr)
	fmt.Fprintf(&b, "CONTROL_PORT=%d\n", m.ControlPort)
	fmt.Fprintf(&b, "PROTOCOL=%s\n", m.Protocol)
	fmt.Fprintf(&b, "TOKEN=%s\n", m.Token)
	return b.String()
}

func renderMirrorCommand(m mirrorParams, ports string) string {
	return fmt.Sprintf(`frp-manager reverse foreign \
  --local-public %s \
  --remote-public %s \
  --iface %s \
  --local-private %s \
  --remote-private %s \
  --mtu %d \
  --mss %s \
  --control-port %d \
  --protocol %s \
  --token %s \
  --ports %s`,
		m.LocalPublicIP, m.RemotePublicIP, m.Iface,
		m.LocalPrivateIP, m.RemotePrivateIP, m.MTU, m.MSSMode,
		m.ControlPort, m.Protocol, m.Token, ports)
}

func wizardServerProtocol(p string) (frpconf.Protocol, string, bool) {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "", "tcp", "none":
		return frpconf.ProtoNone, "tcp", true
	case "quic":
		return frpconf.ProtoQUIC, "quic", true
	case "kcp":
		return frpconf.ProtoKCP, "kcp", true
	}
	return "", "", false
}

func wizardClientProtocol(p string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "", "tcp":
		return "tcp", true
	case "quic":
		return "quic", true
	case "kcp":
		return "kcp", true
	}
	return "", false
}
