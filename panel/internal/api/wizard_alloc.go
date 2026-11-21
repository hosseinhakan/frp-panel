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
	// `ip -d tunnel show` prints one line per tunnel, e.g.
	//   gt11: gre remote 206.1.100.7 local 5.6.7.8 dev eth0 ...
	liveGRETunnelLine = regexp.MustCompile(`^\s*([^:\s]+):\s+gre\b(.*)$`)
	liveGREEndpoint   = regexp.MustCompile(`\b(remote|local)\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)`)
	inetCIDRPattern   = regexp.MustCompile(`\binet\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+)`)
)

// greInventory is the snapshot of every GRE tunnel known to this host: the
// /root/frp/gre/*.env definitions plus interfaces the kernel currently has
// (`ip -d tunnel show`). The live view matters because a manually-created or
// half-provisioned tunnel has no env file, and adding a second keyless GRE to
// the same endpoint fails in the kernel with `File exists`.
type greInventory struct {
	ifaces  *ifaceSet
	octets  map[int]bool
	tunnels []gre.Tunnel
	// liveKeys marks tunnels discovered via `ip -d tunnel show`, so callers
	// can tell a plain env rerun from a reused kernel-only interface.
	liveKeys map[string]bool
}

// handleWizardDefaults returns the next free iface, /30 subnet and control
// port so the Web UI can pre-fill the Iran form on a busy host.
func (s *Server) handleWizardDefaults(w http.ResponseWriter, r *http.Request) {
	inv, err := s.wizardGREState()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot scan GRE tunnels: %v", err)
		return
	}
	iface := nextFreeIface(inv.ifaces)
	octet := nextFreeSubnet(inv.octets)
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
		"existingTunnels": len(inv.tunnels),
	})
}

// wizardGREState collects every GRE interface and /30 third octet in use,
// from env files, live GRE tunnels (`ip -d tunnel show`), live links and
// /sys/class/net.
func (s *Server) wizardGREState() (*greInventory, error) {
	inv := &greInventory{
		ifaces:   newIfaceSet(),
		octets:   map[int]bool{},
		liveKeys: map[string]bool{},
	}

	tunnels, _, err := gre.List(s.paths.GREDir)
	if err != nil {
		return nil, err
	}
	for _, t := range tunnels {
		inv.ifaces.add(t.Iface)
		inv.ifaces.add(t.Name)
		for _, cidr := range []string{t.LocalPrivateIP, t.RemotePrivateIP} {
			if n, ok := subnetOctet(cidr); ok {
				inv.octets[n] = true
			}
		}
		inv.tunnels = append(inv.tunnels, t)
	}

	// Live GRE tunnels. An interface the kernel already owns is authoritative
	// even without an env file: reusing it avoids the kernel's EEXIST failure
	// when a second keyless tunnel targets the same public endpoint.
	for _, lt := range s.liveGRETunnels() {
		inv.ifaces.add(lt.Iface)
		lp, rp := s.ifacePrivatePair(lt.Iface, tunnels)
		lt.LocalPrivateIP, lt.RemotePrivateIP = lp, rp
		if n, ok := subnetOctet(lp); ok {
			inv.octets[n] = true
		}
		duplicate := false
		for _, et := range tunnels {
			if et.Iface == lt.Iface && et.LocalPublicIP == lt.LocalPublicIP &&
				et.RemotePublicIP == lt.RemotePublicIP {
				duplicate = true
				break
			}
		}
		if !duplicate {
			inv.liveKeys[tunnelKey(lt)] = true
			inv.tunnels = append(inv.tunnels, lt)
		}
	}

	// Live interfaces via `ip -o link show` (best effort: a container or a
	// test host may not have iproute2).
	if out, ierr := s.runner.Exec("ip", "-o", "link", "show"); ierr == nil {
		for _, line := range strings.Split(out, "\n") {
			if m := liveIfacePattern.FindStringSubmatch(line); m != nil {
				inv.ifaces.add(m[1])
			}
		}
	}
	// /sys/class/net is authoritative even without iproute2.
	if entries, derr := os.ReadDir(s.paths.SysNetDir); derr == nil {
		for _, e := range entries {
			inv.ifaces.add(e.Name())
		}
	}
	return inv, nil
}

// liveGRETunnels parses `ip -d tunnel show` into tunnel definitions. The
// kernel output carries the public endpoints but not the private /30; that is
// filled in by ifacePrivatePair.
func (s *Server) liveGRETunnels() []gre.Tunnel {
	out, err := s.runner.Exec("ip", "-d", "tunnel", "show")
	if err != nil {
		return nil
	}
	return parseLiveGRETunnels(out)
}

func parseLiveGRETunnels(out string) []gre.Tunnel {
	var tunnels []gre.Tunnel
	for _, line := range strings.Split(out, "\n") {
		m := liveGRETunnelLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		t := gre.Tunnel{Name: m[1], Iface: m[1]}
		for _, em := range liveGREEndpoint.FindAllStringSubmatch(m[2], -1) {
			switch em[1] {
			case "local":
				t.LocalPublicIP = em[2]
			case "remote":
				t.RemotePublicIP = em[2]
			}
		}
		if t.LocalPublicIP == "" || t.RemotePublicIP == "" {
			continue
		}
		tunnels = append(tunnels, t)
	}
	return tunnels
}

// ifacePrivatePair resolves the /30 pair for an interface, preferring the env
// definition (authoritative, already oriented) and falling back to the live
// IPv4 address from `ip -o -4 addr show dev <iface>`.
func (s *Server) ifacePrivatePair(iface string, env []gre.Tunnel) (local, remote string) {
	for _, t := range env {
		if t.Iface == iface || t.Name == iface {
			if t.LocalPrivateIP != "" {
				return t.LocalPrivateIP, t.RemotePrivateIP
			}
		}
	}
	out, err := s.runner.Exec("ip", "-o", "-4", "addr", "show", "dev", iface)
	if err != nil {
		return "", ""
	}
	m := inetCIDRPattern.FindStringSubmatch(out)
	if m == nil {
		return "", ""
	}
	local = m[1]
	remote, _ = peerPrivateCIDR(local)
	return local, remote
}

// peerPrivateCIDR returns the other usable host of a point-to-point /30.
func peerPrivateCIDR(cidr string) (string, bool) {
	ipPart, mask, ok := strings.Cut(cidr, "/")
	if !ok || mask != "30" {
		return "", false
	}
	parts := strings.Split(ipPart, ".")
	if len(parts) != 4 {
		return "", false
	}
	host, err := strconv.Atoi(parts[3])
	if err != nil {
		return "", false
	}
	var peer int
	switch host {
	case 1:
		peer = 2
	case 2:
		peer = 1
	default:
		return "", false
	}
	return fmt.Sprintf("%s.%s.%s.%d/30", parts[0], parts[1], parts[2], peer), true
}

// findReusableTunnel returns an existing GRE tunnel that already terminates
// at remotePub. An exact public pair (in either orientation) is a plain
// refresh; a matching remote endpoint alone means the local public IP changed.
// Both are reused so the kernel never sees a duplicate keyless tunnel. live
// reports that the match came from `ip -d tunnel show` rather than an env
// definition, so callers can surface a reuse notice.
func findReusableTunnel(inv *greInventory, localPub, remotePub string) (t gre.Tunnel, exact, live, ok bool) {
	localPub, remotePub = strings.TrimSpace(localPub), strings.TrimSpace(remotePub)
	if localPub == "" || remotePub == "" {
		return gre.Tunnel{}, false, false, false
	}
	// Prefer a match that knows its /30, and among those an exact pair.
	for _, candidate := range inv.tunnels {
		if ownTunnel(candidate, localPub, remotePub) && tunnelHasPrivate(candidate) {
			return candidate, true, inv.liveKeys[tunnelKey(candidate)], true
		}
	}
	for _, candidate := range inv.tunnels {
		if ownTunnel(candidate, localPub, remotePub) {
			return candidate, true, inv.liveKeys[tunnelKey(candidate)], true
		}
	}
	for _, candidate := range inv.tunnels {
		if candidate.RemotePublicIP == remotePub && tunnelHasPrivate(candidate) {
			return candidate, false, inv.liveKeys[tunnelKey(candidate)], true
		}
	}
	for _, candidate := range inv.tunnels {
		if candidate.RemotePublicIP == remotePub {
			return candidate, false, inv.liveKeys[tunnelKey(candidate)], true
		}
	}
	return gre.Tunnel{}, false, false, false
}

func tunnelKey(t gre.Tunnel) string {
	return t.Iface + "|" + t.LocalPublicIP + "|" + t.RemotePublicIP
}

func tunnelHasPrivate(t gre.Tunnel) bool {
	return t.LocalPrivateIP != "" || t.RemotePrivateIP != ""
}

func tunnelOctet(t gre.Tunnel) (int, bool) {
	if n, ok := subnetOctet(t.LocalPrivateIP); ok {
		return n, true
	}
	return subnetOctet(t.RemotePrivateIP)
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
// Before allocating anything, an existing GRE tunnel to the same public peer
// (env file or live kernel tunnel) is reused with its original /30.
func (s *Server) allocateWizardGRE(reqIface, reqSubnet, localPub, remotePub string) (iface string, octet int, warnings []string, err error) {
	inv, err := s.wizardGREState()
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

	// The same public pair (or the same remote endpoint after a local IP
	// change) already has a tunnel: reuse its interface and /30 rather than
	// letting the kernel reject a duplicate keyless GRE with `File exists`.
	if t, exact, live, ok := findReusableTunnel(inv, localPub, remotePub); ok {
		reuseOctet, oerr := tunnelOctet(t)
		if !oerr {
			return "", 0, nil, fmt.Errorf(
				"existing GRE tunnel %s for %s has no IPv4 /30; delete it or assign one first",
				t.Iface, strings.TrimSpace(remotePub))
		}
		if !exact || live {
			warnings = append(warnings, fmt.Sprintf(
				"reused existing GRE tunnel %s for %s (%s)", t.Iface, strings.TrimSpace(remotePub), subnetCIDR(reuseOctet)))
		}
		return t.Iface, reuseOctet, warnings, nil
	}

	ifaceBusy := inv.ifaces.has(reqIface)
	subnetBusy := inv.octets[reqOctet]

	if !ifaceBusy && !subnetBusy {
		return reqIface, reqOctet, nil, nil
	}

	iface = reqIface
	octet = reqOctet
	if ifaceBusy {
		iface = nextFreeIface(inv.ifaces)
	}
	if subnetBusy {
		octet = nextFreeSubnet(inv.octets)
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

// allocateForeignIface reuses an existing tunnel to the same Iran peer (env or
// live), returning that tunnel's own private pair so the caller never rewrites
// an established /30. Only when no such tunnel exists does it move the local
// interface name while keeping the mirrored /30.
func (s *Server) allocateForeignIface(reqIface, localPub, remotePub, localPriv, remotePriv string) (iface, localPrivate, remotePrivate string, warnings []string, err error) {
	inv, err := s.wizardGREState()
	if err != nil {
		return "", "", "", nil, err
	}
	reqIface = strings.TrimSpace(reqIface)
	if reqIface == "" {
		reqIface = wizardIface
	}

	if t, exact, live, ok := findReusableTunnel(inv, localPub, remotePub); ok {
		localPrivate, remotePrivate = t.LocalPrivateIP, t.RemotePrivateIP
		// A single-box lab can hold the mirrored orientation; keep this
		// role's address family local-first so the Foreign side gets `.1`
		// and the Iran side `.2`.
		if t.LocalPublicIP == strings.TrimSpace(remotePub) && t.RemotePublicIP == strings.TrimSpace(localPub) &&
			localPrivate != "" && remotePrivate != "" {
			localPrivate, remotePrivate = remotePrivate, localPrivate
		}
		if localPrivate == "" {
			localPrivate = localPriv
		}
		if remotePrivate == "" {
			remotePrivate = remotePriv
		}
		if !exact || live {
			oct, _ := subnetOctet(localPrivate)
			if oct > 0 {
				warnings = append(warnings, fmt.Sprintf(
					"reused existing GRE tunnel %s for %s (%s)", t.Iface, strings.TrimSpace(remotePub), subnetCIDR(oct)))
			} else {
				warnings = append(warnings, fmt.Sprintf(
					"reused existing GRE tunnel %s for %s", t.Iface, strings.TrimSpace(remotePub)))
			}
		}
		return t.Iface, localPrivate, remotePrivate, warnings, nil
	}

	if !inv.ifaces.has(reqIface) {
		return reqIface, localPriv, remotePriv, nil, nil
	}
	next := nextFreeIface(inv.ifaces)
	return next, localPriv, remotePriv, []string{fmt.Sprintf(
		"%s was busy locally; using %s with the same mirrored /30", reqIface, next)}, nil
}

// foreignSubnetConflict refuses to reuse a mirrored /30 that already belongs
// to a different local tunnel (renaming the local iface is safe; sharing the
// private subnet is not). iface is the tunnel selected for this request, so
// its own /30 is always allowed.
func (s *Server) foreignSubnetConflict(iface, localPriv, localPub, remotePub string) error {
	inv, err := s.wizardGREState()
	if err != nil {
		return err
	}
	octet, ok := subnetOctet(localPriv)
	if !ok {
		return fmt.Errorf("invalid local private CIDR %q", localPriv)
	}
	if !inv.octets[octet] {
		return nil
	}
	for _, t := range inv.tunnels {
		if t.Iface != iface && !ownTunnel(t, localPub, remotePub) && t.RemotePublicIP != strings.TrimSpace(remotePub) {
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
