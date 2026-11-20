package gre

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func fixtureTunnel() Tunnel {
	return Tunnel{
		Name:            "gt11",
		LocalPublicIP:   "1.2.3.4",
		RemotePublicIP:  "5.6.7.8",
		Iface:           "gt11",
		LocalPrivateIP:  "10.100.111.1/30",
		RemotePrivateIP: "10.100.111.2/30",
		MTU:             1400,
		MSSMode:         "clamp",
	}
}

// TestRenderEnvGolden locks the exact bytes the CLI's gre_create_do writes —
// the two faces of the suite must produce identical files.
func TestRenderEnvGolden(t *testing.T) {
	want := `# GRE tunnel definition (FRP Tunnel Suite) — managed by frp-manager / frp-panel
LOCAL_PUBLIC_IP=1.2.3.4
REMOTE_PUBLIC_IP=5.6.7.8
IFACE=gt11
LOCAL_PRIVATE_IP=10.100.111.1/30
REMOTE_PRIVATE_IP=10.100.111.2/30
MTU=1400
MSS_MODE=clamp
`
	if got := RenderEnv(fixtureTunnel()); got != want {
		t.Errorf("RenderEnv mismatch:\n--- want ---\n%s\n--- got ---\n%s", want, got)
	}
}

// TestMirrorTextGolden locks the CLI's gre_mirror_print output byte-for-byte
// (values substituted the way the unquoted bash heredoc expands them).
func TestMirrorTextGolden(t *testing.T) {
	want := `# ---- mirror config for the REMOTE node (gt11) ----
# Either use the interactive wizard (frp-manager, menu 10) or run:
frp-manager gre create \
  --local-public 5.6.7.8 \
  --remote-public 1.2.3.4 \
  --iface gt11 \
  --local-private 10.100.111.2/30 \
  --remote-private 10.100.111.1/30 \
  --mtu 1400 \
  --mss clamp

# Equivalent env file (/root/frp/gre/gt11.env):
LOCAL_PUBLIC_IP=5.6.7.8
REMOTE_PUBLIC_IP=1.2.3.4
IFACE=gt11
LOCAL_PRIVATE_IP=10.100.111.2/30
REMOTE_PRIVATE_IP=10.100.111.1/30
MTU=1400
MSS_MODE=clamp
`
	got := fixtureTunnel().MirrorText("/root/frp/gre")
	if got != want {
		t.Errorf("MirrorText mismatch:\n--- want ---\n%s\n--- got ---\n%s", want, got)
	}
}

func TestParseRoundTrip(t *testing.T) {
	original := fixtureTunnel()
	parsed, err := ParseEnv(original.Name, RenderEnv(original))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed, original) {
		t.Errorf("round trip mismatch:\n original=%+v\n parsed=%+v", original, parsed)
	}
}

func TestParseEnvTolerantAndStrict(t *testing.T) {
	// CLI-written file with the standard header parses fine.
	raw := RenderEnv(fixtureTunnel())
	if _, err := ParseEnv("gt11", raw); err != nil {
		t.Fatalf("CLI-format env failed to parse: %v", err)
	}

	// Defaults for MTU/MSS like frp-gre's load_env.
	minimal := "LOCAL_PUBLIC_IP=1.2.3.4\nREMOTE_PUBLIC_IP=5.6.7.8\nIFACE=g1\n" +
		"LOCAL_PRIVATE_IP=10.0.0.1/30\nREMOTE_PRIVATE_IP=10.0.0.2/30\n"
	tun, err := ParseEnv("g1", minimal)
	if err != nil {
		t.Fatalf("minimal env failed: %v", err)
	}
	if tun.MTU != DefaultMTU || tun.MSSMode != DefaultMSSMode {
		t.Errorf("defaults not applied: mtu=%d mss=%s", tun.MTU, tun.MSSMode)
	}

	// Unknown keys tolerated (bash source would too).
	extended := minimal + "SOME_FUTURE_FLAG=1\n"
	if _, err := ParseEnv("g1", extended); err != nil {
		t.Fatalf("unknown key should be tolerated: %v", err)
	}

	// Missing required field.
	if _, err := ParseEnv("g1", "LOCAL_PUBLIC_IP=1.2.3.4\n"); err == nil {
		t.Error("missing required fields must fail")
	}

	// Unsafe value: this file gets sourced by a bash helper — hostile
	// values must never parse.
	evil := minimal + "IFACE=gt11; rm -rf /\n"
	if _, err := ParseEnv("g1", evil); err == nil {
		t.Error("unsafe value must be rejected")
	}

	// Not KEY=VALUE.
	if _, err := ParseEnv("g1", "garbage line\n"); err == nil {
		t.Error("non-assignment line must be rejected")
	}
}

// TestValidate mirrors every rule in the CLI's gre_create_do.
func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Tunnel)
		wantErr bool
	}{
		{"valid", func(t *Tunnel) {}, false},
		{"bad local ip", func(t *Tunnel) { t.LocalPublicIP = "not-an-ip" }, true},
		{"bad remote ip", func(t *Tunnel) { t.RemotePublicIP = "999.1.1.1" }, true},
		{"same public ip", func(t *Tunnel) { t.RemotePublicIP = t.LocalPublicIP }, true},
		{"bad local cidr", func(t *Tunnel) { t.LocalPrivateIP = "10.100.111.1" }, true},
		{"same private ip", func(t *Tunnel) { t.RemotePrivateIP = t.LocalPrivateIP }, true},
		{"bad iface", func(t *Tunnel) { t.Iface = "bad iface!" }, true},
		{"mtu too small", func(t *Tunnel) { t.MTU = 100 }, true},
		{"mtu too big", func(t *Tunnel) { t.MTU = 9000 }, true},
		{"bad mss mode", func(t *Tunnel) { t.MSSMode = "clampy" }, true},
		{"mss off ok", func(t *Tunnel) { t.MSSMode = "off" }, false},
		{"mss 1240 ok", func(t *Tunnel) { t.MSSMode = "1240" }, false},
		{"bad name", func(t *Tunnel) { t.Name = "way-too-long-tunnel-name!" }, true},
	}
	for _, tc := range cases {
		tun := fixtureTunnel()
		tc.mutate(&tun)
		_, err := tun.Validate()
		if tc.wantErr && err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%s: unexpected error %v", tc.name, err)
		}
	}

	// Mismatched /24 is a warning, not an error (CLI parity).
	tun := fixtureTunnel()
	tun.RemotePrivateIP = "10.101.112.2/30"
	warnings, err := tun.Validate()
	if err != nil {
		t.Fatalf("mismatched /24 must not be fatal: %v", err)
	}
	if len(warnings) == 0 {
		t.Error("expected a /24 mismatch warning")
	}
}

func TestMirror(t *testing.T) {
	m := fixtureTunnel().Mirror()
	if m.LocalPublicIP != "5.6.7.8" || m.RemotePublicIP != "1.2.3.4" {
		t.Errorf("public swap wrong: %+v", m)
	}
	if m.LocalPrivateIP != "10.100.111.2/30" || m.RemotePrivateIP != "10.100.111.1/30" {
		t.Errorf("private swap wrong: %+v", m)
	}
	if m.Iface != "gt11" || m.MTU != 1400 || m.MSSMode != "clamp" {
		t.Errorf("mirror lost invariants: %+v", m)
	}
}

func TestSuggestSubnet(t *testing.T) {
	// Empty set: the CLI default 10.100.111.0/30 pair.
	l, r := SuggestSubnet(nil)
	if l != "10.100.111.1/30" || r != "10.100.111.2/30" {
		t.Errorf("first suggestion = %s %s, want 111 pair", l, r)
	}

	// Existing tunnel on 111 → next free /30.
	used := []Tunnel{fixtureTunnel()}
	l, r = SuggestSubnet(used)
	if l != "10.100.112.1/30" || r != "10.100.112.2/30" {
		t.Errorf("second suggestion = %s %s, want 112 pair", l, r)
	}

	// Two tunnels → third suggests 113.
	second := fixtureTunnel()
	second.LocalPrivateIP, second.RemotePrivateIP = "10.100.112.1/30", "10.100.112.2/30"
	l, r = SuggestSubnet(append(used, second))
	if l != "10.100.113.1/30" {
		t.Errorf("third suggestion = %s, want 113 pair", l)
	}
}

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	original := fixtureTunnel()

	if err := Write(dir, original); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" { // perms are a no-op on Windows
		fi, err := os.Stat(filepath.Join(dir, "gt11.env"))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("env mode = %v, want 0600", fi.Mode().Perm())
		}
	}

	got, err := Read(dir, "gt11")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, original) {
		t.Errorf("store round trip mismatch: %+v", got)
	}

	// List sees it.
	tunnels, bad, err := List(dir)
	if err != nil || len(tunnels) != 1 || len(bad) != 0 {
		t.Fatalf("List = %d tunnels, bad=%v err=%v", len(tunnels), bad, err)
	}

	// Broken file shows up in bad, doesn't kill the listing.
	os.WriteFile(filepath.Join(dir, "broken.env"), []byte("IFACE=x\n"), 0o600)
	tunnels, bad, err = List(dir)
	if err != nil || len(tunnels) != 1 || len(bad) != 1 {
		t.Fatalf("List with broken file: tunnels=%d bad=%v err=%v", len(tunnels), bad, err)
	}

	// Delete.
	if err := Delete(dir, "gt11"); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir, "gt11"); err == nil {
		t.Error("deleted tunnel still readable")
	}
	if err := Delete(dir, "gt11"); err == nil {
		t.Error("deleting a missing tunnel must fail")
	}
}

func TestParseRejectsInvalidName(t *testing.T) {
	if _, err := Read(t.TempDir(), "../escape"); err == nil {
		t.Error("path-traversal name must be rejected")
	}
	if !strings.Contains("gt11 gt9 eth0", "gt11") {
		t.Fatal("sanity")
	}
}
