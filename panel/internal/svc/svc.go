// Package svc is the panel's only gateway to the host system: systemctl
// calls, the frps/frpc `verify -c` write gate, and small probes (ping, ip).
//
// Security model: every command is exec'd directly (never through a shell),
// unit names are validated against a whitelist, and every argument that
// derives from user input is charset-checked before it reaches argv.
// The Runner interface keeps all of this mockable for tests.
package svc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/frp-suite/panel/internal/frpconf"
)

// ErrBinaryMissing reports that frps/frpc is not installed yet; callers fall
// back to the internal parse gate and flag the result accordingly.
var ErrBinaryMissing = errors.New("svc: frp binary not installed")

// cmdTimeout bounds every external command.
const cmdTimeout = 60 * time.Second

// Paths locates every host location the panel touches. Tests override Root
// (plus the individual dirs) to point at temp dirs.
type Paths struct {
	Root        string // filesystem root; "/" in production
	ServerDir   string // /root/frp/server
	ClientDir   string // /root/frp/client
	GREDir      string // /root/frp/gre
	PanelCfg    string // /etc/frp-panel/panel.toml
	EtcPanelDir string // /etc/frp-panel (watchdog.env, zram.env)
	SysctlDir   string // /etc/sysctl.d (turbo drop-ins)
	ModulesDir  string // /etc/modules-load.d (bbr.conf)
	BinDir      string // /usr/local/bin (frps, frpc, frp-gre, frp-panel)
	UnitDir     string // /etc/systemd/system
	SysNetDir   string // /sys/class/net (interface counters)
	LogDir      string // /var/log/frp-panel
}

// DefaultPaths returns the production layout.
func DefaultPaths() Paths {
	return Paths{
		Root:        "/",
		ServerDir:   "/root/frp/server",
		ClientDir:   "/root/frp/client",
		GREDir:      "/root/frp/gre",
		PanelCfg:    "/etc/frp-panel/panel.toml",
		EtcPanelDir: "/etc/frp-panel",
		SysctlDir:   "/etc/sysctl.d",
		ModulesDir:  "/etc/modules-load.d",
		BinDir:      "/usr/local/bin",
		UnitDir:     "/etc/systemd/system",
		SysNetDir:   "/sys/class/net",
		LogDir:      "/var/log/frp-panel",
	}
}

// FRPSPath / FRPCPath are the installed binary locations (same as the
// frps@.service / frpc@.service ExecStart lines).
func (p Paths) FRPSPath() string { return join(p.Root, "/usr/local/bin/frps") }
func (p Paths) FRPCPath() string { return join(p.Root, "/usr/local/bin/frpc") }

func join(root, abs string) string {
	if root == "" || root == "/" {
		return abs
	}
	return strings.TrimSuffix(root, "/") + abs
}

// Runner is the host-command interface. SystemdRunner is the real
// implementation; tests install a fake.
type Runner interface {
	// Systemctl runs a whitelisted systemctl command.
	Systemctl(args ...string) (string, error)
	// Exec runs an allowed auxiliary binary (ping, ip, frp-gre).
	Exec(name string, args ...string) (string, error)
	// ExecStream starts an allowed binary and returns a live reader of its
	// output (journalctl -f). The process is killed when ctx is canceled
	// or the reader is closed.
	ExecStream(ctx context.Context, name string, args ...string) (io.ReadCloser, error)
	// Verify runs `frps verify -c <file>` (or frpc) — the write gate.
	// Returns the command output and ErrBinaryMissing when the binary
	// is absent so callers can fall back to the internal parser.
	Verify(kind frpconf.Kind, file string) (string, error)
}

// SystemdRunner is the production Runner.
type SystemdRunner struct{}

// systemdVerbs is the closed set of systemctl operations the panel issues.
var systemdVerbs = map[string]bool{
	"start": true, "stop": true, "restart": true, "reload": true,
	"enable": true, "disable": true, "is-active": true, "is-enabled": true,
	"status": true, "daemon-reload": true, "list-units": true,
}

// unitPattern constrains every unit string before it reaches argv.
var unitPattern = regexp.MustCompile(`^[a-zA-Z0-9_.@\\-]{1,80}$`)

// ValidateUnit decomposes and whitelists a unit name.
// family is "frps"/"frpc"/"gre-tunnel" for template units (instance may be
// empty for the bare template), or the plain unit name for singletons.
func ValidateUnit(unit string) (family, instance string, err error) {
	if !unitPattern.MatchString(unit) {
		return "", "", fmt.Errorf("svc: invalid unit name %q", unit)
	}
	switch {
	case strings.HasPrefix(unit, "frps@"):
		return "frps", strings.TrimPrefix(unit, "frps@"), nil
	case strings.HasPrefix(unit, "frpc@"):
		return "frpc", strings.TrimPrefix(unit, "frpc@"), nil
	case strings.HasPrefix(unit, "gre-tunnel@"):
		return "gre-tunnel", strings.TrimPrefix(unit, "gre-tunnel@"), nil
	case unit == "tunnel-turbo" || unit == "frp-zram" ||
		unit == "frp-watchdog" || unit == "frp-panel":
		return unit, "", nil
	}
	return "", "", fmt.Errorf("svc: unit %q is not managed by the suite", unit)
}

// Systemctl validates and runs a systemctl command.
func (SystemdRunner) Systemctl(args ...string) (string, error) {
	if len(args) == 0 {
		return "", errors.New("svc: systemctl requires arguments")
	}
	verb := args[0]
	if !systemdVerbs[verb] {
		return "", fmt.Errorf("svc: systemctl verb %q not allowed", verb)
	}
	for _, a := range args[1:] {
		if verb == "daemon-reload" {
			continue // no unit argument
		}
		if strings.HasPrefix(a, "-") {
			return "", fmt.Errorf("svc: systemctl arguments may not start with '-': %q", a)
		}
		if _, _, err := ValidateUnit(a); err != nil {
			return "", err
		}
	}
	return run("systemctl", args...)
}

// execAllowlist is the closed set of auxiliary binaries the panel execs.
var execAllowlist = map[string]bool{
	"ping": true, "ip": true, "frp-gre": true, "frp-turbo": true, "journalctl": true,
}

// Exec runs an allowlisted binary with charset-checked arguments.
func (SystemdRunner) Exec(name string, args ...string) (string, error) {
	if err := checkExecArgs(name, args); err != nil {
		return "", err
	}
	return run(name, args...)
}

// ExecStream starts an allowlisted binary and streams its combined output.
// The child is killed when ctx is canceled or the stream is closed, so a
// journalctl -f follows its SSE client's lifetime exactly.
func (SystemdRunner) ExecStream(ctx context.Context, name string, args ...string) (io.ReadCloser, error) {
	if err := checkExecArgs(name, args); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, name, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	// Diagnostics (e.g. journalctl's own errors) go to the panel's journal,
	// never into the client-facing stream.
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &streamProc{ReadCloser: stdout, cmd: cmd}, nil
}

// streamProc reaps the child process when the stream ends.
type streamProc struct {
	io.ReadCloser
	cmd  *exec.Cmd
	once sync.Once
}

func (s *streamProc) Close() error {
	s.once.Do(func() {
		if s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
		}
		// Wait reaps the child and closes the stdout pipe; the caller is
		// done reading by the time Close runs (EOF or cancel first).
		_ = s.cmd.Wait()
	})
	return s.ReadCloser.Close()
}

// checkExecArgs is the shared allowlist + charset gate for Exec/ExecStream.
func checkExecArgs(name string, args []string) error {
	if !execAllowlist[name] {
		return fmt.Errorf("svc: binary %q is not allowlisted", name)
	}
	for _, a := range args {
		if strings.ContainsAny(a, " \t\n\r;&|`$<>'\"\\") {
			return fmt.Errorf("svc: unsafe argument %q", a)
		}
	}
	return nil
}

// Verify runs the frps/frpc verify gate against a config file.
func (r SystemdRunner) Verify(kind frpconf.Kind, file string) (string, error) {
	var bin string
	if kind == frpconf.KindClient {
		bin = "/usr/local/bin/frpc"
	} else {
		bin = "/usr/local/bin/frps"
	}
	if _, err := execLookPath(bin); err != nil {
		return "", fmt.Errorf("%w (%s)", ErrBinaryMissing, bin)
	}
	out, err := run(bin, "verify", "-c", file)
	if err != nil {
		return out, fmt.Errorf("verify failed: %v\n%s", err, out)
	}
	return out, nil
}

// execLookPath is swappable for tests.
var execLookPath = func(bin string) (string, error) {
	return exec.LookPath(bin)
}

func run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("svc: %s timed out after %s", name, cmdTimeout)
	}
	return string(out), err
}
