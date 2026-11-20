// Multi-tunnel allocation for the FRP over GRE Reverse wizard.
//
// The first tunnel uses gt11 / 10.100.111.0/30 / control port 7025. When the
// host already runs one or more tunnels, the wizard must keep working: this
// file scans GRE envs, live interfaces, frps configs and /proc/net/tcp, then
// suggests the next free iface/subnet/port and auto-falls-back on POST.
package api

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/frp-suite/panel/internal/frpconf"
	"github.com/frp-suite/panel/internal/gre"
)

const (
	wizardIfaceStart  = 11
	wizardSubnetStart = 111
	wizardSubnetLo    = 1
	wizardSubnetHi    = 254
)

var (
	liveIfacePattern = regexp.MustCompile(`^\s*\d+:\s+([^:@\s]+)`)
	serverNamePort   = regexp.MustCompile(`^server-([0-9]{1,5})$`)
)

// handleWizardDefaults returns the next free iface, /30 subnet and control
// port so the Web UI can pre-fill the Iran form on a busy host.
func (s *Server) handleWizardDefaults(w http.ResponseWriter, r *http.Request) {
	ifaces, octets, tunnels, err := s.wizardGREState()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot scan GRE tunnels: %v", err)
		return
	}
	iface := nextFreeIface(ifaces)
	octet := nextFreeSubnet(octets)
	port, _, err := s.allocateControlPort(wizardDefaultPort)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot scan control ports: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"iface":           iface,
		"subnet":          subnetCIDR(octet),
		"localPrivateIp":  fmt.Sprintf("10.100.%d.2/30", octet),
		"remotePrivateIp": fmt.Sprintf("10.100.%d.1/30", octet),
		"controlPort":     port,
		"serverAddr":      fmt.Sprintf("10.100.%d.2", octet),
		"existingTunnels": len(tunnels),
	})
}

// wizardGREState collects every GRE interface and /30 third octet in use,
// from env files, live links and /sys/class/net.
func (s *Server) wizardGREState() (usedIfaces *ifaceSet, usedOctets map[int]bool, tunnels []gre.Tunnel, err error) {
	ifaces := newIfaceSet()
	octets := map[int]bool{}

	tunnels, _, err = gre.List(s.paths.GREDir)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, t := range tunnels {
		ifaces.add(t.Iface)
		ifaces.add(t.Name)
		for _, cidr := range []string{t.LocalPrivateIP, t.RemotePrivateIP} {
			if n, ok := subnetOctet(cidr); ok {
				octets[n] = true
			}
		}
	}

	// Live interfaces via `ip -o link show` (best effort: a container or a
	// test host may not have iproute2).
	if out, ierr := s.runner.Exec("ip", "-o", "link", "show"); ierr == nil {
		for _, line := range strings.Split(out, "\n") {
			if m := liveIfacePattern.FindStringSubmatch(line); m != nil {
				ifaces.add(m[1])
			}
		}
	}
	// /sys/class/net is authoritative even without iproute2.
	if entries, derr := os.ReadDir(s.paths.SysNetDir); derr == nil {
		for _, e := range entries {
			ifaces.add(e.Name())
		}
	}
	return ifaces, octets, tunnels, nil
}

// ownTunnel reports whether an existing env is this same GRE pair (matching
// both public IPs in either orientation), so re-running the wizard refreshes
// rather than clones. The mirrored orientation also covers a host that runs
// both wizard roles (e.g. a lab or a single-box demo).
func ownTunnel(t gre.Tunnel, localPub, remotePub string) bool {
	localPub, remotePub = strings.TrimSpace(localPub), strings.TrimSpace(remotePub)
	if localPub == "" || remotePub == "" {
		return false
	}
	return (t.LocalPublicIP == localPub && t.RemotePublicIP == remotePub) ||
		(t.LocalPublicIP == remotePub && t.RemotePublicIP == localPub)
}

// allocateWizardGRE resolves the requested iface/subnet into a free pair.
// Only the conflicting component moves; the returned warnings explain both.
func (s *Server) allocateWizardGRE(reqIface, reqSubnet, localPub, remotePub string) (iface string, octet int, warnings []string, err error) {
	usedIfaces, usedOctets, tunnels, err := s.wizardGREState()
	if err != nil {
		return "", 0, nil, err
	}

	reqIface = strings.TrimSpace(reqIface)
	if reqIface == "" {
		reqIface = wizardIface
	}
	reqOctet := wizardSubnetStart
	if v, ok := subnetOctet(strings.TrimSpace(reqSubnet)); ok {
		reqOctet = v
	}

	// The same public pair already exists: refresh that tunnel rather than
	// cloning it (the UI pre-fills globally free values, not pair-aware ones).
	for _, t := range tunnels {
		if !ownTunnel(t, localPub, remotePub) {
			continue
		}
		oct := wizardSubnetStart
		if n, ok := subnetOctet(t.LocalPrivateIP); ok {
			oct = n
		} else if n, ok := subnetOctet(t.RemotePrivateIP); ok {
			oct = n
		}
		return t.Iface, oct, nil, nil
	}

	ifaceBusy := usedIfaces.has(reqIface)
	subnetBusy := usedOctets[reqOctet]

	if !ifaceBusy && !subnetBusy {
		return reqIface, reqOctet, nil, nil
	}

	iface = reqIface
	octet = reqOctet
	if ifaceBusy {
		iface = nextFreeIface(usedIfaces)
	}
	if subnetBusy {
		octet = nextFreeSubnet(usedOctets)
	}

	switch {
	case ifaceBusy && subnetBusy:
		warnings = append(warnings, fmt.Sprintf(
			"%s was busy; allocated %s (%s)", reqIface, iface, subnetCIDR(octet)))
	case ifaceBusy:
		warnings = append(warnings, fmt.Sprintf(
			"%s was busy; allocated %s (kept %s)", reqIface, iface, subnetCIDR(octet)))
	default:
		warnings = append(warnings, fmt.Sprintf(
			"%s was in use; allocated %s (%s)", subnetCIDR(reqOctet), iface, subnetCIDR(octet)))
	}
	return iface, octet, warnings, nil
}

// allocateForeignIface keeps the mirrored /30 but moves the local interface
// name when it is already taken by another tunnel on this host.
func (s *Server) allocateForeignIface(reqIface, localPub, remotePub string) (string, []string, error) {
	usedIfaces, _, tunnels, err := s.wizardGREState()
	if err != nil {
		return "", nil, err
	}
	reqIface = strings.TrimSpace(reqIface)
	if reqIface == "" {
		reqIface = wizardIface
	}
	own := false
	for _, t := range tunnels {
		if (t.Iface == reqIface || t.Name == reqIface) && ownTunnel(t, localPub, remotePub) {
			own = true
			break
		}
	}
	if !usedIfaces.has(reqIface) || own {
		return reqIface, nil, nil
	}
	next := nextFreeIface(usedIfaces)
	return next, []string{fmt.Sprintf(
		"%s was busy locally; using %s with the same mirrored /30", reqIface, next)}, nil
}

// foreignSubnetConflict refuses to reuse a mirrored /30 that already belongs
// to a different local tunnel (renaming the local iface is safe; sharing the
// private subnet is not).
func (s *Server) foreignSubnetConflict(localPriv, localPub, remotePub string) error {
	_, usedOctets, tunnels, err := s.wizardGREState()
	if err != nil {
		return err
	}
	octet, ok := subnetOctet(localPriv)
	if !ok {
		return fmt.Errorf("invalid local private CIDR %q", localPriv)
	}
	if !usedOctets[octet] {
		return nil
	}
	for _, t := range tunnels {
		if !ownTunnel(t, localPub, remotePub) {
			continue
		}
		for _, cidr := range []string{t.LocalPrivateIP, t.RemotePrivateIP} {
			if n, ok := subnetOctet(cidr); ok && n == octet {
				return nil
			}
		}
	}
	return fmt.Errorf("the mirrored %s subnet is already used by another local tunnel; re-run the Iran wizard to allocate a fresh pair", subnetCIDR(octet))
}

// serverForBindAddr finds an existing frps config already bound to the given
// tunnel IP, so re-running the wizard refreshes that instance instead of
// allocating a second port/listener for the same pair.
func (s *Server) serverForBindAddr(addr string) (name string, port int, ok bool) {
	names, err := frpconf.ListConfigs(s.paths.ServerDir)
	if err != nil {
		return "", 0, false
	}
	for _, n := range names {
		cfg, err := frpconf.ReadServer(filepath.Join(s.paths.ServerDir, n+".toml"))
		if err != nil {
			continue
		}
		if cfg.BindAddr == addr && cfg.BindPort > 0 {
			return n, cfg.BindPort, true
		}
	}
	return "", 0, false
}

// allocateControlPort returns a free frps control port, moving to the next
// free port when the requested one is already configured or listening.
func (s *Server) allocateControlPort(req int) (port int, warnings []string, err error) {
	used, err := frpconf.UsedServerPorts(s.paths.ServerDir)
	if err != nil {
		return 0, nil, err
	}
	// A config named server-<port>.toml reserves that name even when its
	// bindPort was edited by hand.
	if names, nerr := frpconf.ListConfigs(s.paths.ServerDir); nerr == nil {
		for _, n := range names {
			if m := serverNamePort.FindStringSubmatch(n); m != nil {
				if p, perr := strconv.Atoi(m[1]); perr == nil && p > 0 && p <= 65535 {
					used[p] = true
				}
			}
		}
	}
	for p := range listeningTCPPorts("/proc/net/tcp") {
		used[p] = true
	}
	for p := range listeningTCPPorts("/proc/net/tcp6") {
		used[p] = true
	}

	if req == 0 {
		req = wizardDefaultPort
	}
	if req < 1 || req > 65535 {
		return 0, nil, fmt.Errorf("controlPort must be 1..65535")
	}
	if !used[req] {
		return req, nil, nil
	}
	for p := req + 1; p <= 65535; p++ {
		if !used[p] {
			return p, []string{fmt.Sprintf("port %d was in use; switched to %d", req, p)}, nil
		}
	}
	for p := 1; p < req; p++ {
		if !used[p] {
			return p, []string{fmt.Sprintf("port %d was in use; switched to %d", req, p)}, nil
		}
	}
	return 0, nil, fmt.Errorf("no free control port available")
}

// ---- small helpers ---------------------------------------------------------

type ifaceSet struct {
	names   map[string]bool
	gtNames map[int]bool
}

func newIfaceSet() *ifaceSet {
	return &ifaceSet{names: map[string]bool{}, gtNames: map[int]bool{}}
}

func (s *ifaceSet) add(name string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	s.names[name] = true
	if n, ok := gtNumber(name); ok {
		s.gtNames[n] = true
	}
}

func (s *ifaceSet) has(name string) bool { return s.names[name] }

func gtNumber(name string) (int, bool) {
	if !strings.HasPrefix(name, "gt") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(name, "gt"))
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

func nextFreeIface(used *ifaceSet) string {
	for n := wizardIfaceStart; n < 1000; n++ {
		if !used.gtNames[n] {
			return fmt.Sprintf("gt%d", n)
		}
	}
	return "gt1000"
}

func nextFreeSubnet(used map[int]bool) int {
	for n := wizardSubnetStart; n <= wizardSubnetHi; n++ {
		if !used[n] {
			return n
		}
	}
	for n := wizardSubnetLo; n < wizardSubnetStart; n++ {
		if !used[n] {
			return n
		}
	}
	return wizardSubnetStart
}

func subnetCIDR(octet int) string { return fmt.Sprintf("10.100.%d.0/30", octet) }

// subnetOctet extracts the third octet from a 10.100.<n>.x/y CIDR (or a bare
// 10.100.<n>.0/30 subnet).
func subnetOctet(raw string) (int, bool) {
	if raw == "" {
		return 0, false
	}
	ipPart := strings.SplitN(raw, "/", 2)[0]
	parts := strings.Split(ipPart, ".")
	if len(parts) != 4 || parts[0] != "10" || parts[1] != "100" {
		return 0, false
	}
	n, err := strconv.Atoi(parts[2])
	if err != nil || n < 0 || n > 255 {
		return 0, false
	}
	return n, true
}

// listeningTCPPorts parses /proc/net/tcp{,6} for sockets in LISTEN (0A).
// Missing files (non-Linux or a test host) simply yield an empty set.
func listeningTCPPorts(path string) map[int]bool {
	out := map[int]bool{}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for i, line := range strings.Split(string(raw), "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[3] != "0A" {
			continue
		}
		_, hexPort, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue
		}
		p, err := strconv.ParseInt(hexPort, 16, 32)
		if err == nil && p > 0 && p <= 65535 {
			out[int(p)] = true
		}
	}
	return out
}
