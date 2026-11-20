// Package watchdog models /etc/frp-panel/watchdog.env — the tuning file the
// frp-watchdog helper sources on start. Render is byte-identical to the
// CLI's watchdog_enable heredoc, so both faces manage the same file with
// the same bytes.
package watchdog

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Env is the watchdog tuning file's managed subset.
type Env struct {
	Interval    int `json:"interval"`    // probe interval in seconds (CLI default 60)
	Threshold   int `json:"threshold"`   // consecutive failures before a restart (default 3)
	Cooldown    int `json:"cooldown"`    // seconds between restart attempts (default 120)
	PingTimeout int `json:"ping_timeout"` // ICMP probe timeout (default 2)
	TCPTimeout  int `json:"tcp_timeout"` // control-channel probe timeout (default 3)
}

// Default matches the CLI's watchdog_enable defaults.
func Default() Env { return Env{Interval: 60, Threshold: 3, Cooldown: 120, PingTimeout: 2, TCPTimeout: 3} }

// Validate applies the CLI's own rules: interval >= 10, threshold >= 1,
// cooldown and timeouts positive.
func (e Env) Validate() error {
	if e.Interval < 10 {
		return fmt.Errorf("interval must be at least 10 seconds")
	}
	if e.Threshold < 1 {
		return fmt.Errorf("threshold must be at least 1")
	}
	if e.Cooldown < 0 {
		return fmt.Errorf("cooldown must not be negative")
	}
	if e.PingTimeout < 1 {
		return fmt.Errorf("ping timeout must be at least 1 second")
	}
	if e.TCPTimeout < 1 {
		return fmt.Errorf("tcp timeout must be at least 1 second")
	}
	return nil
}

// Render emits the file exactly as the CLI heredoc does (header comment +
// five KEY=VALUE lines, trailing newline).
func Render(e Env) string {
	var b strings.Builder
	b.WriteString("# FRP Tunnel Suite watchdog tuning (used by /usr/local/bin/frp-watchdog)\n")
	fmt.Fprintf(&b, "INTERVAL=%d\n", e.Interval)
	fmt.Fprintf(&b, "THRESHOLD=%d\n", e.Threshold)
	fmt.Fprintf(&b, "COOLDOWN=%d\n", e.Cooldown)
	fmt.Fprintf(&b, "PING_TIMEOUT=%d\n", e.PingTimeout)
	fmt.Fprintf(&b, "TCP_TIMEOUT=%d\n", e.TCPTimeout)
	return b.String()
}

// Read loads watchdog.env; ok is false when the file is missing or invalid
// (the helper falls back to its built-in defaults in that case, and so do we).
func Read(path string) (Env, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Env{}, false
	}
	e, err := Parse(string(raw))
	if err != nil {
		return Env{}, false
	}
	return e, true
}

// Parse reads the KEY=VALUE form (comments ignored, all keys required —
// the helper sources this file, so unknown keys are rejected).
func Parse(raw string) (Env, error) {
	e := Env{}
	seen := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return Env{}, fmt.Errorf("watchdog.env: bad line %q", line)
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		n, err := strconv.Atoi(val)
		if err != nil {
			return Env{}, fmt.Errorf("watchdog.env: %s: %v", key, err)
		}
		switch key {
		case "INTERVAL":
			e.Interval = n
		case "THRESHOLD":
			e.Threshold = n
		case "COOLDOWN":
			e.Cooldown = n
		case "PING_TIMEOUT":
			e.PingTimeout = n
		case "TCP_TIMEOUT":
			e.TCPTimeout = n
		default:
			return Env{}, fmt.Errorf("watchdog.env: unknown key %q", key)
		}
		seen[key] = true
	}
	for _, k := range []string{"INTERVAL", "THRESHOLD", "COOLDOWN", "PING_TIMEOUT", "TCP_TIMEOUT"} {
		if !seen[k] {
			return Env{}, fmt.Errorf("watchdog.env: missing key %s", k)
		}
	}
	return e, nil
}
