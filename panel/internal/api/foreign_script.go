// One-click Foreign (exit) node provisioning from the Iran entry node.
//
// The generated block is a self-contained Bash script: it installs the GRE
// tunnel + helper + systemd units, downloads frpc when missing, writes the
// matching frpc TOML (same token / control port / transport as the Iran frps)
// and verifies the link — without frp-panel on the Foreign server.
package api

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/frp-suite/panel/internal/assets"
	"github.com/frp-suite/panel/internal/frpconf"
	"github.com/frp-suite/panel/internal/gre"
)

type foreignScriptReq struct {
	ForeignPublicIP  string `json:"foreignPublicIp"`
	IranPublicIP     string `json:"iranPublicIp"`
	Iface            string `json:"iface"`
	Subnet           string `json:"subnet"` // 10.100.<n>.0/30 when no tunnel is linked
	IranPrivateIP    string `json:"iranPrivateIp"`
	ForeignPrivateIP string `json:"foreignPrivateIp"`
	MTU              int    `json:"mtu"`
	MSSMode          string `json:"mssMode"`
	Ports            string `json:"ports"`
	Proto            string `json:"proto"` // both | tcp | udp
	LocalIP          string `json:"localIp"`
	RawSpeed         bool   `json:"rawSpeed"`
	ClientName       string `json:"clientName"`
}

type foreignScriptOptions struct {
	Ports      string
	Proto      string
	LocalIP    string
	RawSpeed   bool
	ClientName string
}

// handleServerForeignScript renders the Foreign install command for one frps
// row. All routing details are derived from the linked GRE env; the caller only
// has to supply the Foreign public IP when the frps is not tied to a tunnel.
func (s *Server) handleServerForeignScript(w http.ResponseWriter, r *http.Request) {
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
	cfg, err := frpconf.ParseServer(raw)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "config does not parse: %v", err)
		return
	}
	token := strings.TrimSpace(cfg.Auth.Token)
	if token == "" {
		writeErr(w, http.StatusUnprocessableEntity,
			"frps %q has no auth.token — set a token before generating a Foreign installer", name)
		return
	}

	var req foreignScriptReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	t, linked, err := s.resolveForeignTunnel(&req, cfg.BindAddr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}

	serverAddr := ipOnly(t.RemotePrivateIP) // Iran side of the GRE pair
	if !linked {
		if ip := net.ParseIP(cfg.BindAddr); ip != nil && !ip.IsUnspecified() {
			serverAddr = cfg.BindAddr
		}
	}
	clientProto, ok := wizardClientProtocol(serverProtocol(cfg))
	if !ok {
		clientProto = "tcp"
	}
	clientName := strings.TrimSpace(req.ClientName)
	if clientName == "" {
		clientName = "client-" + strconv.Itoa(cfg.BindPort)
	}

	// Remote ports are allocated on the Iran frps; refuse a collision before
	// the operator pastes a command that frp would reject at runtime.
	checkPorts := strings.TrimSpace(req.Ports)
	if checkPorts == "" {
		checkPorts = "8989"
	}
	specs, perr := frpconf.ParsePortSpecs(checkPorts)
	if perr != nil {
		writeErr(w, http.StatusBadRequest, "%v", perr)
		return
	}
	used, uerr := s.allUsedPorts()
	if uerr != nil {
		writeErr(w, http.StatusInternalServerError, "cannot scan used ports: %v", uerr)
		return
	}
	if collides := collide(specs, used); collides != "" {
		writeErr(w, http.StatusConflict, "remote port(s) already in use on this node: %s", collides)
		return
	}

	_, script, err := buildForeignScript(t, serverAddr, cfg.BindPort, token, clientProto, foreignScriptOptions{
		Ports:      req.Ports,
		Proto:      req.Proto,
		LocalIP:    req.LocalIP,
		RawSpeed:   req.RawSpeed,
		ClientName: clientName,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"serverName":       name,
		"serverAddr":       serverAddr,
		"serverPort":       cfg.BindPort,
		"clientName":       clientName,
		"iface":            t.Iface,
		"iranPublicIp":     t.RemotePublicIP,
		"foreignPublicIp":  t.LocalPublicIP,
		"iranPrivateIp":    t.RemotePrivateIP,
		"foreignPrivateIp": t.LocalPrivateIP,
		"mtu":              t.MTU,
		"mssMode":          t.MSSMode,
		"ports":            req.Ports,
		"proto":            req.Proto,
		"rawSpeed":         req.RawSpeed,
		"linkedTunnel":     linked,
		"script":           script,
	})
}

// resolveForeignTunnel finds the GRE env linked to an frps bind address and
// returns the tunnel from the Foreign node's point of view. When no tunnel is
// linked, the caller-provided public IPs and /30 are used (with warnings folded
// into the validation error).
func (s *Server) resolveForeignTunnel(req *foreignScriptReq, bindAddr string) (gre.Tunnel, bool, error) {
	tunnels, _, err := gre.List(s.paths.GREDir)
	if err != nil {
		return gre.Tunnel{}, false, fmt.Errorf("cannot list GRE tunnels: %w", err)
	}
	linkedTunnel, linked := matchTunnel(tunnels, bindAddr)

	foreignPub := strings.TrimSpace(req.ForeignPublicIP)
	iranPub := strings.TrimSpace(req.IranPublicIP)
	iface := strings.TrimSpace(req.Iface)
	foreignPriv := strings.TrimSpace(req.ForeignPrivateIP)
	iranPriv := strings.TrimSpace(req.IranPrivateIP)
	mtu := req.MTU
	mss := strings.TrimSpace(req.MSSMode)

	if linked {
		if foreignPub == "" {
			foreignPub = linkedTunnel.RemotePublicIP
		}
		if iranPub == "" {
			iranPub = linkedTunnel.LocalPublicIP
		}
		if iface == "" {
			iface = linkedTunnel.Iface
		}
		if foreignPriv == "" {
			foreignPriv = linkedTunnel.RemotePrivateIP
		}
		if iranPriv == "" {
			iranPriv = linkedTunnel.LocalPrivateIP
		}
		if mtu == 0 {
			mtu = linkedTunnel.MTU
		}
		if mss == "" {
			mss = linkedTunnel.MSSMode
		}
	}
	if iface == "" {
		iface = wizardIface
	}
	if mtu == 0 {
		mtu = wizardMTU
	}
	if mss == "" {
		mss = wizardMSS
	}
	if foreignPriv == "" || iranPriv == "" {
		octet := wizardSubnetStart
		if v, ok := subnetOctet(strings.TrimSpace(req.Subnet)); ok {
			octet = v
		}
		if foreignPriv == "" {
			foreignPriv = fmt.Sprintf("10.100.%d.1/30", octet)
		}
		if iranPriv == "" {
			iranPriv = fmt.Sprintf("10.100.%d.2/30", octet)
		}
	}
	if foreignPub == "" {
		return gre.Tunnel{}, linked, fmt.Errorf(
			"foreignPublicIp is required — no GRE tunnel is linked to frps bind address %q", bindAddr)
	}
	if iranPub == "" {
		return gre.Tunnel{}, linked, fmt.Errorf("iranPublicIp is required (the Iran node's public IP)")
	}

	t := gre.Tunnel{
		Name:            iface,
		Iface:           iface,
		LocalPublicIP:   foreignPub,
		RemotePublicIP:  iranPub,
		LocalPrivateIP:  foreignPriv,
		RemotePrivateIP: iranPriv,
		MTU:             mtu,
		MSSMode:         mss,
	}
	if _, err := t.Validate(); err != nil {
		return gre.Tunnel{}, linked, err
	}
	return t, linked, nil
}

func matchTunnel(tunnels []gre.Tunnel, bindAddr string) (gre.Tunnel, bool) {
	bind := ipOnly(bindAddr)
	for _, t := range tunnels {
		if ipOnly(t.LocalPrivateIP) == bind || ipOnly(t.RemotePrivateIP) == bind {
			return t, true
		}
	}
	if len(tunnels) == 1 {
		return tunnels[0], true
	}
	return gre.Tunnel{}, false
}

func ipOnly(cidr string) string {
	cidr = strings.TrimSpace(cidr)
	if ip, _, err := net.ParseCIDR(cidr); err == nil {
		return ip.String()
	}
	return cidr
}

// buildForeignScript constructs the Foreign frpc config and the self-contained
// install block that provisions it.
func buildForeignScript(t gre.Tunnel, serverAddr string, serverPort int, token, clientProto string, o foreignScriptOptions) (*frpconf.ClientConfig, string, error) {
	ports := strings.TrimSpace(o.Ports)
	if ports == "" {
		ports = "8989"
	}
	specs, err := frpconf.ParsePortSpecs(ports)
	if err != nil {
		return nil, "", err
	}
	if len(specs) == 0 {
		return nil, "", fmt.Errorf("ports is required (e.g. \"8989,8443\")")
	}
	proto, ok := protoFromWire(o.Proto)
	if !ok {
		return nil, "", fmt.Errorf("invalid proto %q (want both|tcp|udp)", o.Proto)
	}
	localIP := strings.TrimSpace(o.LocalIP)
	if localIP == "" {
		localIP = "127.0.0.1"
	}
	if net.ParseIP(localIP) == nil {
		return nil, "", fmt.Errorf("invalid localIp %q", localIP)
	}
	if clientProto == "" || clientProto == "none" {
		clientProto = "tcp"
	}
	name := strings.TrimSpace(o.ClientName)
	if name == "" {
		name = "client-" + strconv.Itoa(serverPort)
	}
	if !instanceNamePattern.MatchString(name) {
		return nil, "", fmt.Errorf("invalid clientName %q", name)
	}

	encrypt := !o.RawSpeed
	cfg, err := frpconf.NewClientConfig(frpconf.ClientOptions{
		ServerAddr:     serverAddr,
		ServerPort:     serverPort,
		Token:          token,
		Protocol:       clientProto,
		Ports:          specs,
		Proto:          proto,
		LocalIP:        localIP,
		UseTLS:         !o.RawSpeed,
		UseEncryption:  &encrypt,
		UseCompression: false,
	})
	if err != nil {
		return nil, "", err
	}
	script, err := renderForeignScript(t, serverAddr, cfg, name)
	if err != nil {
		return nil, "", err
	}
	return cfg, script, nil
}

func renderForeignScript(t gre.Tunnel, serverAddr string, cfg *frpconf.ClientConfig, clientName string) (string, error) {
	helper, err := assets.FS.ReadFile("helpers/frp-gre")
	if err != nil {
		return "", err
	}
	greUnit, err := assets.FS.ReadFile("systemd/gre-tunnel@.service")
	if err != nil {
		return "", err
	}
	frpcUnit, err := assets.FS.ReadFile("systemd/frpc@.service")
	if err != nil {
		return "", err
	}
	clientTOML := frpconf.RenderClient(cfg)

	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	writeBlock := func(content []byte) {
		b.Write(content)
		if len(content) == 0 || content[len(content)-1] != '\n' {
			b.WriteString("\n")
		}
	}

	w("sudo bash <<'FRP_FOREIGN_SETUP'")
	w("#!/usr/bin/env bash")
	w("# FRP over GRE Reverse — Foreign (exit) node: %s", clientName)
	w("# Generated by frp-panel on the Iran node. Self-contained: frp-panel is NOT required here.")
	w("# Paste this whole block on the Foreign server as root.")
	w("set -euo pipefail")
	w("")
	w("IFACE=%s", shellSingle(t.Iface))
	w("IRAN_PUBLIC_IP=%s", shellSingle(t.RemotePublicIP))
	w("FOREIGN_PUBLIC_IP=%s", shellSingle(t.LocalPublicIP))
	w("IRAN_PRIVATE_IP=%s", shellSingle(t.RemotePrivateIP))
	w("FOREIGN_PRIVATE_IP=%s", shellSingle(t.LocalPrivateIP))
	w("MTU=%s", shellSingle(strconv.Itoa(t.MTU)))
	w("MSS_MODE=%s", shellSingle(t.MSSMode))
	w("SERVER_ADDR=%s", shellSingle(serverAddr))
	w("SERVER_PORT=%s", shellSingle(strconv.Itoa(cfg.ServerPort)))
	w("CLIENT_NAME=%s", shellSingle(clientName))
	w("")
	w("if [ \"$(id -u)\" -ne 0 ]; then echo 'run as root (sudo)' >&2; exit 1; fi")
	w("")
	w("# ---- required tools -------------------------------------------------------")
	w("MISSING=\"\"")
	w("for bin in ip iptables curl tar; do")
	w("  command -v \"$bin\" >/dev/null 2>&1 || MISSING=\"$MISSING $bin\"")
	w("done")
	w("if [ -n \"$MISSING\" ]; then")
	w("  echo \"installing missing tools:$MISSING\"")
	w("  if command -v apt-get >/dev/null 2>&1; then")
	w("    apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y iproute2 iptables curl ca-certificates tar")
	w("  elif command -v dnf >/dev/null 2>&1; then")
	w("    dnf install -y iproute iptables curl ca-certificates tar")
	w("  elif command -v yum >/dev/null 2>&1; then")
	w("    yum install -y iproute iptables curl ca-certificates tar")
	w("  else")
	w("    echo \"install these tools and re-run:$MISSING\" >&2; exit 1")
	w("  fi")
	w("fi")
	w("modprobe ip_gre 2>/dev/null || true")
	w("mkdir -p /root/frp/gre /root/frp/client /usr/local/bin")
	w("")
	w("# ---- GRE helper (canonical) ----------------------------------------------")
	w("cat > /usr/local/bin/frp-gre <<'FRP_GRE_HELPER'")
	writeBlock(helper)
	w("FRP_GRE_HELPER")
	w("chmod 0755 /usr/local/bin/frp-gre")
	w("")
	w("cat > \"/root/frp/gre/${IFACE}.env\" <<EOF")
	w("# GRE tunnel definition (FRP Tunnel Suite) — generated by frp-panel")
	w("LOCAL_PUBLIC_IP=${FOREIGN_PUBLIC_IP}")
	w("REMOTE_PUBLIC_IP=${IRAN_PUBLIC_IP}")
	w("IFACE=${IFACE}")
	w("LOCAL_PRIVATE_IP=${FOREIGN_PRIVATE_IP}")
	w("REMOTE_PRIVATE_IP=${IRAN_PRIVATE_IP}")
	w("MTU=${MTU}")
	w("MSS_MODE=${MSS_MODE}")
	w("EOF")
	w("chmod 0600 \"/root/frp/gre/${IFACE}.env\"")
	w("")
	w("# Stop a previous run and recreate the interface with the exact endpoints.")
	w("systemctl stop \"gre-tunnel@${IFACE}\" 2>/dev/null || true")
	w("systemctl stop \"frpc@${CLIENT_NAME}\" 2>/dev/null || true")
	w("if ip link show \"$IFACE\" >/dev/null 2>&1; then")
	w("  ip tunnel del \"$IFACE\" 2>/dev/null || ip link del \"$IFACE\" 2>/dev/null || true")
	w("fi")
	w("")
	w("cat > /etc/systemd/system/gre-tunnel@.service <<'FRP_GRE_UNIT'")
	writeBlock(greUnit)
	w("FRP_GRE_UNIT")
	w("")
	w("# ---- frpc binary ----------------------------------------------------------")
	w("if [ ! -x /usr/local/bin/frpc ]; then")
	w("  arch=$(uname -m)")
	w("  case \"$arch\" in")
	w("    x86_64|amd64) arch=amd64 ;;")
	w("    aarch64|arm64) arch=arm64 ;;")
	w("    armv7l|armv6l) arch=arm ;;")
	w("    *) echo \"unsupported architecture: $arch\" >&2; exit 1 ;;")
	w("  esac")
	w("  os=$(uname -s | tr '[:upper:]' '[:lower:]')")
	w("  ver=$(curl -fsSL https://api.github.com/repos/fatedier/frp/releases/latest 2>/dev/null \\")
	w("        | sed -n 's/.*\"tag_name\": *\"v\\([^\"]*\\)\".*/\\1/p' | head -n1 || true)")
	w("  [ -n \"${ver:-}\" ] || ver=\"0.61.0\"")
	w("  tmp=$(mktemp -d)")
	w("  trap 'rm -rf \"$tmp\"' EXIT")
	w("  curl -fL \"https://github.com/fatedier/frp/releases/download/v${ver}/frp_${ver}_${os}_${arch}.tar.gz\" -o \"$tmp/frp.tar.gz\"")
	w("  tar -xzf \"$tmp/frp.tar.gz\" -C \"$tmp\"")
	w("  install -m 0755 \"$tmp\"/frp_*/frpc /usr/local/bin/frpc")
	w("  rm -rf \"$tmp\"")
	w("  trap - EXIT")
	w("fi")
	w("")
	w("cat > /etc/systemd/system/frpc@.service <<'FRP_FRPC_UNIT'")
	writeBlock(frpcUnit)
	w("FRP_FRPC_UNIT")
	w("")
	w("# ---- frpc config (matches the Iran frps exactly) --------------------------")
	w("cat > \"/root/frp/client/${CLIENT_NAME}.toml\" <<'FRP_CLIENT_TOML'")
	writeBlock([]byte(clientTOML))
	w("FRP_CLIENT_TOML")
	w("chmod 0600 \"/root/frp/client/${CLIENT_NAME}.toml\"")
	w("")
	w("# ---- enable + verify ------------------------------------------------------")
	w("systemctl daemon-reload")
	w("systemctl enable \"gre-tunnel@${IFACE}\"")
	w("systemctl restart \"gre-tunnel@${IFACE}\"")
	w("systemctl enable \"frpc@${CLIENT_NAME}\"")
	w("systemctl restart \"frpc@${CLIENT_NAME}\"")
	w("")
	w("sleep 3")
	w("echo")
	w("echo \"=== GRE ${IFACE} ===\"")
	w("ip -brief addr show \"$IFACE\" || true")
	w("echo \"=== ping ${SERVER_ADDR} over ${IFACE} ===\"")
	w("PING_OK=0")
	w("if command -v ping >/dev/null 2>&1; then")
	w("  ping -c 3 -W 2 -I \"$IFACE\" \"$SERVER_ADDR\" && PING_OK=1 || true")
	w("fi")
	w("echo \"=== units ===\"")
	w("systemctl is-active \"gre-tunnel@${IFACE}\" || true")
	w("systemctl is-active \"frpc@${CLIENT_NAME}\" || true")
	w("if systemctl is-active --quiet \"frpc@${CLIENT_NAME}\"; then")
	w("  echo \"OK: frpc@${CLIENT_NAME} is active — forwarded ports are live on the Iran entry node.\"")
	w("else")
	w("  echo \"FAILED: frpc@${CLIENT_NAME} is not active. Recent logs:\" >&2")
	w("  journalctl -u \"frpc@${CLIENT_NAME}\" --no-pager -n 30 || true")
	w("  exit 1")
	w("fi")
	w("if [ \"$PING_OK\" -ne 1 ]; then")
	w("  echo \"WARNING: GRE peer ${SERVER_ADDR} did not answer — check UDP protocol 47 and the Iran GRE unit.\" >&2")
	w("fi")
	w("FRP_FOREIGN_SETUP")
	return b.String(), nil
}

// shellSingle quotes a validated value for a POSIX shell assignment.
func shellSingle(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
