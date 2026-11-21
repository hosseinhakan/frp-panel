// Package gre models the tunnel definitions under /root/frp/gre/*.env.
//
// The .env files are shared with the bash CLI (frp-manager) and the
// frp-gre helper (which `source`s them), so this package renders and parses
// the exact same byte format and enforces the same validation rules as the
// CLI's gre_create_do. Values are strictly charset-checked because frp-gre
// sources these files — a hostile value must never reach a shell.
package gre

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Defaults matching the CLI wizard (frp-setup.sh gre_create_prompt).
const (
	// DefaultMTU is deliberately conservative: 1400 black-holes on some
	// Iran ISP/MPLS/PPPoE paths (GRE adds 24 bytes of overhead), so 1280 is
	// the safe default across the whole route.
	DefaultMTU        = 1280
	DefaultMSSMode    = "1220"
	DefaultTXQueuelen = 1000
	DefaultName       = "gt11"
	defaultSubnet3o   = 111 // 10.100.<n>.0/30 suggestion starts at n=111
)

// NamePattern is the tunnel-name charset shared by frp-gre and the CLI.
var NamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

// safeValue bounds every env value: no shell metacharacters, ever.
var safeValue = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,64}$`)

// Tunnel is one GRE tunnel definition (one .env file).
type Tunnel struct {
	Name            string `json:"name"` // env file stem == systemd instance
	LocalPublicIP   string `json:"local_public_ip"`
	RemotePublicIP  string `json:"remote_public_ip"`
	Iface           string `json:"iface"`
	LocalPrivateIP  string `json:"local_private_ip"`  // CIDR, e.g. 10.100.111.1/30
	RemotePrivateIP string `json:"remote_private_ip"` // CIDR, e.g. 10.100.111.2/30
	MTU             int    `json:"mtu"`
	MSSMode         string `json:"mss_mode"` // clamp|1360|1240|1220|off
	TXQueuelen      int    `json:"txqueuelen"`
}

// MSSModes lists the accepted TCP MSS clamping modes (frp-gre mss_rules).
var MSSModes = []string{"clamp", "1360", "1240", "1220", "off"}

// Validate applies the same rules as the CLI's gre_create_do. It returns the
// joined validation error (nil = ok) and a list of non-fatal warnings
// (e.g. mismatched /24s, remote == local).
func (t Tunnel) Validate() (warnings []string, err error) {
	fail := func(format string, a ...any) {
		err = fmt.Errorf(format, a...)
	}
	switch {
	case !NamePattern.MatchString(t.Name):
		fail("invalid tunnel name %q (want up to 15 chars of [A-Za-z0-9_.-])", t.Name)
	case !isIPv4(t.LocalPublicIP):
		fail("invalid local public IP: %s", t.LocalPublicIP)
	case !isIPv4(t.RemotePublicIP):
		fail("invalid remote public IP: %s", t.RemotePublicIP)
	case !isCIDR4(t.LocalPrivateIP):
		fail("invalid local private CIDR: %s", t.LocalPrivateIP)
	case !isCIDR4(t.RemotePrivateIP):
		fail("invalid remote private CIDR: %s", t.RemotePrivateIP)
	case t.LocalPublicIP == t.RemotePublicIP:
		fail("local and remote public IPs must differ")
	case t.LocalPrivateIP == t.RemotePrivateIP:
		fail("local and remote private IPs must differ")
	case !NamePattern.MatchString(t.Iface):
		fail("invalid interface name: %s", t.Iface)
	case t.MTU < 576 || t.MTU > 1500:
		fail("invalid MTU: %d (want 576..1500)", t.MTU)
	case t.TXQueuelen < 1 || t.TXQueuelen > 100000:
		fail("invalid TXQUEUELEN: %d (want 1..100000)", t.TXQueuelen)
	case !validMSS(t.MSSMode):
		fail("invalid MSS mode: %s (want clamp|1360|1240|1220|off)", t.MSSMode)
	}
	if err != nil {
		return nil, err
	}

	// Same-/24 sanity warning (non-fatal, mirrors the CLI).
	l24, lok := net24(t.LocalPrivateIP)
	r24, rok := net24(t.RemotePrivateIP)
	if lok && rok && l24 != r24 {
		warnings = append(warnings,
			fmt.Sprintf("private IPs are not in the same /24 (%s vs %s) — unusual for a p2p GRE link", l24, r24))
	}
	if t.RemotePublicIP == t.LocalPublicIP {
		warnings = append(warnings, "remote public IP equals the local one")
	}
	return warnings, nil
}

// RenderEnv produces the exact byte format the CLI writes (gre_create_do)
// and frp-gre sources.
func RenderEnv(t Tunnel) string {
	var b strings.Builder
	b.WriteString("# GRE tunnel definition (FRP Tunnel Suite) — managed by frp-manager / frp-panel\n")
	b.WriteString("LOCAL_PUBLIC_IP=" + t.LocalPublicIP + "\n")
	b.WriteString("REMOTE_PUBLIC_IP=" + t.RemotePublicIP + "\n")
	b.WriteString("IFACE=" + t.Iface + "\n")
	b.WriteString("LOCAL_PRIVATE_IP=" + t.LocalPrivateIP + "\n")
	b.WriteString("REMOTE_PRIVATE_IP=" + t.RemotePrivateIP + "\n")
	b.WriteString("MTU=" + strconv.Itoa(t.MTU) + "\n")
	b.WriteString("MSS_MODE=" + t.MSSMode + "\n")
	b.WriteString("TXQUEUELEN=" + strconv.Itoa(t.TXQueuelen) + "\n")
	return b.String()
}

// ParseEnv strictly parses a .env body. Unknown keys are ignored (the CLI
// tolerates them), but every present value must be charset-safe and known
// fields must parse — this file is sourced by a bash helper, so anything
// suspicious is rejected outright.
func ParseEnv(name, raw string) (Tunnel, error) {
	t := Tunnel{Name: name, MTU: DefaultMTU, MSSMode: DefaultMSSMode, TXQueuelen: DefaultTXQueuelen}
	seen := map[string]bool{}
	for i, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return Tunnel{}, fmt.Errorf("gre: %s.env line %d: not a KEY=VALUE assignment", name, i+1)
		}
		if !safeValue.MatchString(value) {
			return Tunnel{}, fmt.Errorf("gre: %s.env line %d: unsafe characters in %s", name, i+1, key)
		}
		switch strings.TrimSpace(key) {
		case "LOCAL_PUBLIC_IP":
			t.LocalPublicIP, seen[key] = value, true
		case "REMOTE_PUBLIC_IP":
			t.RemotePublicIP, seen[key] = value, true
		case "IFACE":
			t.Iface, seen[key] = value, true
		case "LOCAL_PRIVATE_IP":
			t.LocalPrivateIP, seen[key] = value, true
		case "REMOTE_PRIVATE_IP":
			t.RemotePrivateIP, seen[key] = value, true
		case "MTU":
			n, err := strconv.Atoi(value)
			if err != nil {
				return Tunnel{}, fmt.Errorf("gre: %s.env: MTU not numeric: %q", name, value)
			}
			t.MTU, seen[key] = n, true
		case "MSS_MODE":
			t.MSSMode, seen[key] = value, true
		case "TXQUEUELEN":
			n, err := strconv.Atoi(value)
			if err != nil {
				return Tunnel{}, fmt.Errorf("gre: %s.env: TXQUEUELEN not numeric: %q", name, value)
			}
			t.TXQueuelen, seen[key] = n, true
		default:
			// tolerated, like bash `source` would
		}
	}
	for _, k := range []string{"LOCAL_PUBLIC_IP", "REMOTE_PUBLIC_IP", "IFACE", "LOCAL_PRIVATE_IP", "REMOTE_PRIVATE_IP"} {
		if !seen[k] {
			return Tunnel{}, fmt.Errorf("gre: %s.env is missing required field %s", name, k)
		}
	}
	return t, nil
}

// Mirror returns the same tunnel from the remote node's point of view
// (local/remote swapped), for the far side's .env.
func (t Tunnel) Mirror() Tunnel {
	m := t
	m.Name = t.Iface
	m.LocalPublicIP, m.RemotePublicIP = t.RemotePublicIP, t.LocalPublicIP
	m.LocalPrivateIP, m.RemotePrivateIP = t.RemotePrivateIP, t.LocalPrivateIP
	return m
}

// MirrorText renders the copy-paste blob for the remote node — byte-for-byte
// the same layout the CLI prints (gre_mirror_print), so users can move
// between CLI and panel freely.
func (t Tunnel) MirrorText(envDir string) string {
	m := t.Mirror()
	var b strings.Builder
	fmt.Fprintf(&b, "# ---- mirror config for the REMOTE node (%s) ----\n", t.Iface)
	b.WriteString("# Either use the interactive wizard (frp-manager, menu 10) or run:\n")
	b.WriteString("frp-manager gre create \\\n")
	fmt.Fprintf(&b, "  --local-public %s \\\n", m.LocalPublicIP)
	fmt.Fprintf(&b, "  --remote-public %s \\\n", m.RemotePublicIP)
	fmt.Fprintf(&b, "  --iface %s \\\n", m.Iface)
	fmt.Fprintf(&b, "  --local-private %s \\\n", m.LocalPrivateIP)
	fmt.Fprintf(&b, "  --remote-private %s \\\n", m.RemotePrivateIP)
	fmt.Fprintf(&b, "  --mtu %d \\\n", m.MTU)
	fmt.Fprintf(&b, "  --mss %s \\\n", m.MSSMode)
	fmt.Fprintf(&b, "  --txqueuelen %d\n", m.TXQueuelen)
	b.WriteString("\n")
	// This section mirrors the CLI's gre_mirror_print exactly (bare
	// KEY=VALUE lines, no header comment).
	fmt.Fprintf(&b, "# Equivalent env file (%s/%s.env):\n", envDir, m.Name)
	fmt.Fprintf(&b, "LOCAL_PUBLIC_IP=%s\n", m.LocalPublicIP)
	fmt.Fprintf(&b, "REMOTE_PUBLIC_IP=%s\n", m.RemotePublicIP)
	fmt.Fprintf(&b, "IFACE=%s\n", m.Iface)
	fmt.Fprintf(&b, "LOCAL_PRIVATE_IP=%s\n", m.LocalPrivateIP)
	fmt.Fprintf(&b, "REMOTE_PRIVATE_IP=%s\n", m.RemotePrivateIP)
	fmt.Fprintf(&b, "MTU=%d\n", m.MTU)
	fmt.Fprintf(&b, "MSS_MODE=%s\n", m.MSSMode)
	fmt.Fprintf(&b, "TXQUEUELEN=%d\n", m.TXQueuelen)
	return b.String()
}

// SuggestSubnet returns the next free private /30 pair in 10.100.<n>.0/30,
// scanning the third octet of every existing tunnel's private IPs (mirrors
// the architecture's /30 allocator; starts at the CLI default n=111).
func SuggestSubnet(existing []Tunnel) (local, remote string) {
	used := map[int]bool{}
	for _, t := range existing {
		for _, cidr := range []string{t.LocalPrivateIP, t.RemotePrivateIP} {
			if n, ok := subnet3Octet(cidr); ok {
				used[n] = true
			}
		}
	}
	n := defaultSubnet3o
	for used[n] && n < 255 {
		n++
	}
	if n > 254 {
		n = 1
		for used[n] && n < 255 {
			n++
		}
	}
	return fmt.Sprintf("10.100.%d.1/30", n), fmt.Sprintf("10.100.%d.2/30", n)
}

// ---- store operations ----------------------------------------------------

// List reads every *.env in dir (bad files are skipped with a warning entry
// in the returned map so one broken file never hides the rest).
func List(dir string) ([]Tunnel, map[string]error, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	var tunnels []Tunnel
	bad := map[string]error{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".env") {
			continue
		}
		stem := strings.TrimSuffix(name, ".env")
		t, perr := Read(dir, stem)
		if perr != nil {
			bad[stem] = perr
			continue
		}
		tunnels = append(tunnels, t)
	}
	return tunnels, bad, nil
}

// Read loads and parses one tunnel definition.
func Read(dir, name string) (Tunnel, error) {
	if !NamePattern.MatchString(name) {
		return Tunnel{}, fmt.Errorf("gre: invalid tunnel name %q", name)
	}
	raw, err := os.ReadFile(filepath.Join(dir, name+".env"))
	if err != nil {
		return Tunnel{}, err
	}
	return ParseEnv(name, string(raw))
}

// Write renders and stores the tunnel env (0600, parent dir created).
func Write(dir string, t Tunnel) error {
	if !NamePattern.MatchString(t.Name) {
		return fmt.Errorf("gre: invalid tunnel name %q", t.Name)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, t.Name+".env"), []byte(RenderEnv(t)), 0o600)
}

// Delete removes a tunnel env file.
func Delete(dir, name string) error {
	if !NamePattern.MatchString(name) {
		return fmt.Errorf("gre: invalid tunnel name %q", name)
	}
	err := os.Remove(filepath.Join(dir, name+".env"))
	if err != nil && os.IsNotExist(err) {
		return fmt.Errorf("gre: no tunnel named %q (%s missing)", name, filepath.Join(dir, name+".env"))
	}
	return err
}

// ---- small helpers ------------------------------------------------------

func isIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

func isCIDR4(s string) bool {
	ip, _, err := net.ParseCIDR(s)
	return err == nil && ip.To4() != nil
}

func validMSS(m string) bool {
	for _, v := range MSSModes {
		if v == m {
			return true
		}
	}
	return false
}

// net24 returns the /24 prefix text of a CIDR ("10.100.111.1/30" → "10.100.111").
func net24(cidr string) (string, bool) {
	ip := net.ParseIP(strings.Split(cidr, "/")[0])
	if ip == nil || ip.To4() == nil {
		return "", false
	}
	o := ip.To4()
	return fmt.Sprintf("%d.%d.%d", o[0], o[1], o[2]), true
}

// subnet3Octet extracts the third octet from a 10.100.<n>.x/y CIDR.
func subnet3Octet(cidr string) (int, bool) {
	parts := strings.SplitN(cidr, "/", 2)
	o := strings.Split(parts[0], ".")
	if len(o) != 4 || o[0] != "10" || o[1] != "100" {
		return 0, false
	}
	n, err := strconv.Atoi(o[2])
	if err != nil || n < 0 || n > 255 {
		return 0, false
	}
	return n, true
}

// IfacesExist is a helper for status endpoints: names of interfaces present
// on the host (from /sys/class/net/<name> presence via os.Stat).
func IfacesExist(sysNetDir string, names []string) map[string]bool {
	out := map[string]bool{}
	for _, n := range names {
		if _, err := os.Stat(filepath.Join(sysNetDir, n)); err == nil {
			out[n] = true
		}
	}
	return out
}

// RandomIfaceSuffix produces a small random number for suggested iface names.
func RandomIfaceSuffix() (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(90))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()) + 10, nil
}
