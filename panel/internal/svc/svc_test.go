package svc

import (
	"context"
	"strings"
	"testing"
)

func TestValidateUnitWhitelist(t *testing.T) {
	cases := []struct {
		unit     string
		family   string
		instance string
		ok       bool
	}{
		{"frps@server-7000", "frps", "server-7000", true},
		{"frpc@client-7000", "frpc", "client-7000", true},
		{"gre-tunnel@gt11", "gre-tunnel", "gt11", true},
		{"tunnel-turbo", "tunnel-turbo", "", true},
		{"frp-zram", "frp-zram", "", true},
		{"frp-watchdog", "frp-watchdog", "", true},
		{"frp-panel", "frp-panel", "", true},
		// Rejections: foreign units, injection, junk.
		{"sshd", "", "", false},
		{"nginx.service", "", "", false},
		{"frps@;reboot", "", "", false},
		{"frps@$(reboot)", "", "", false},
		{"../../etc/passwd", "", "", false},
		{"", "", "", false},
		{strings.Repeat("a", 100), "", "", false},
	}
	for _, tc := range cases {
		family, instance, err := ValidateUnit(tc.unit)
		if tc.ok {
			if err != nil || family != tc.family || instance != tc.instance {
				t.Errorf("ValidateUnit(%q) = %q,%q,%v; want %q,%q", tc.unit, family, instance, err, tc.family, tc.instance)
			}
		} else if err == nil {
			t.Errorf("ValidateUnit(%q) must be rejected", tc.unit)
		}
	}
}

func TestSystemctlArgValidation(t *testing.T) {
	r := SystemdRunner{}
	// The validation layer rejects before any exec is attempted (these
	// never reach a real systemctl, so they are safe on any OS).
	if _, err := r.Systemctl("enable", "--now", "frps@bad unit"); err == nil {
		t.Error("unit with space must be rejected")
	}
	if _, err := r.Systemctl("enable", "frps@x", "--root=/other"); err == nil {
		t.Error("flag-like arguments must be rejected")
	}
	if _, err := r.Systemctl("kill", "sshd"); err == nil {
		t.Error("non-whitelisted verb must be rejected")
	}
	if _, err := r.Systemctl("enable", "sshd"); err == nil {
		t.Error("non-whitelisted unit must be rejected")
	}
	if _, err := r.Systemctl(); err == nil {
		t.Error("empty systemctl call must be rejected")
	}
}

func TestExecAllowlist(t *testing.T) {
	r := SystemdRunner{}
	if _, err := r.Exec("bash", "-c", "echo hi"); err == nil {
		t.Error("bash must not be allowlisted")
	}
	if _, err := r.Exec("ping", "-c", "3", "10.0.0.1; rm -rf /"); err == nil {
		t.Error("arguments with shell metacharacters must be rejected")
	}
	if _, err := r.Exec("ip", "-4", "addr"); err != nil {
		// Argument validation passes; the binary is simply absent on this
		// host — the important part is that validation allowed `ip`.
		if _, ok := err.(*execError); !ok && !strings.Contains(err.Error(), "not found") &&
			!strings.Contains(err.Error(), "no such file") {
			t.Errorf("ip call failed for an unexpected reason: %v", err)
		}
	}
}

// ExecStream must enforce the exact same allowlist + charset gate as Exec —
// it is the journal SSE path, so the guard is the attack surface.
func TestExecStreamGuards(t *testing.T) {
	r := SystemdRunner{}
	ctx := context.Background()
	if _, err := r.ExecStream(ctx, "bash", "-c", "echo hi"); err == nil {
		t.Error("bash must not be allowlisted for streaming")
	}
	if _, err := r.ExecStream(ctx, "journalctl", "-f", "-u", "frps; rm"); err == nil {
		t.Error("shell metacharacters must be rejected before any process starts")
	}
	if _, err := r.ExecStream(ctx, "journalctl", "-u", "frp-watchdog", "--since", "10 minutes ago"); err == nil {
		t.Error("spaced arguments must be rejected (free-form journalctl expressions)")
	}
	// journalctl validation passes; the binary is absent on this host.
	if _, err := r.ExecStream(ctx, "journalctl", "-f", "-n", "200", "--output=short-iso", "-u", "frp-watchdog"); err == nil {
		t.Skip("host has journalctl — cannot test the missing-binary path here")
	}
}

type execError struct{ msg string }

func (e *execError) Error() string { return e.msg }

func TestVerifyBinaryMissingDetection(t *testing.T) {
	// On the dev host there is no /usr/local/bin/frps, so the real runner
	// must report ErrBinaryMissing (this is the fallback-gate contract).
	r := SystemdRunner{}
	_, err := r.Verify(0, "/nonexistent.toml") // 0 = KindServer
	if err == nil {
		t.Skip("host has /usr/local/bin/frps — cannot test the missing-binary path here")
	}
	if !strings.Contains(err.Error(), "frp binary not installed") {
		t.Errorf("expected ErrBinaryMissing, got: %v", err)
	}
}

func TestPathsJoins(t *testing.T) {
	p := DefaultPaths()
	if p.FRPSPath() != "/usr/local/bin/frps" || p.FRPCPath() != "/usr/local/bin/frpc" {
		t.Errorf("binary paths = %s / %s", p.FRPSPath(), p.FRPCPath())
	}
	p.Root = "/chroot"
	if p.FRPSPath() != "/chroot/usr/local/bin/frps" {
		t.Errorf("root-joined path = %s", p.FRPSPath())
	}
}
