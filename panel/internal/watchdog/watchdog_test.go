package watchdog

import (
	"os"
	"path/filepath"
	"testing"
)

// The CLI writes watchdog.env via heredoc — Render must match those bytes.
func TestRenderByteIdentity(t *testing.T) {
	want := "# FRP Tunnel Suite watchdog tuning (used by /usr/local/bin/frp-watchdog)\n" +
		"INTERVAL=60\nTHRESHOLD=3\nCOOLDOWN=120\nPING_TIMEOUT=2\nTCP_TIMEOUT=3\n"
	if got := Render(Default()); got != want {
		t.Fatalf("Render =\n%q\nwant\n%q", got, want)
	}
}

func TestParseRoundTrip(t *testing.T) {
	e, err := Parse(Render(Env{Interval: 30, Threshold: 5, Cooldown: 60, PingTimeout: 1, TCPTimeout: 4}))
	if err != nil {
		t.Fatal(err)
	}
	if e != (Env{30, 5, 60, 1, 4}) {
		t.Fatalf("round trip = %+v", e)
	}
}

func TestParseStrictness(t *testing.T) {
	if _, err := Parse("INTERVAL=60\n"); err == nil {
		t.Fatal("partial env must fail")
	}
	if _, err := Parse("INTERVAL=abc\nTHRESHOLD=1\nCOOLDOWN=1\nPING_TIMEOUT=1\nTCP_TIMEOUT=1\n"); err == nil {
		t.Fatal("non-numeric value must fail")
	}
	if _, err := Parse("INTERVAL=60\nTHRESHOLD=1\nCOOLDOWN=1\nPING_TIMEOUT=1\nTCP_TIMEOUT=1\nEVIL=1\n"); err == nil {
		t.Fatal("unknown key must fail (the file is bash-sourced)")
	}
	if _, err := Parse("# only comments\n"); err == nil {
		t.Fatal("empty env must fail")
	}
}

func TestValidate(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}
	bad := []Env{
		{Interval: 9, Threshold: 3, Cooldown: 120, PingTimeout: 2, TCPTimeout: 3},
		{Interval: 60, Threshold: 0, Cooldown: 120, PingTimeout: 2, TCPTimeout: 3},
		{Interval: 60, Threshold: 3, Cooldown: -1, PingTimeout: 2, TCPTimeout: 3},
		{Interval: 60, Threshold: 3, Cooldown: 120, PingTimeout: 0, TCPTimeout: 3},
	}
	for _, e := range bad {
		if err := e.Validate(); err == nil {
			t.Fatalf("Validate(%+v) should fail", e)
		}
	}
}

func TestRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "watchdog.env")
	if _, ok := Read(path); ok {
		t.Fatal("missing file must not read")
	}
	if err := os.WriteFile(path, []byte(Render(Default())), 0o600); err != nil {
		t.Fatal(err)
	}
	if e, ok := Read(path); !ok || e != Default() {
		t.Fatalf("Read = %+v ok=%v", e, ok)
	}
	// Invalid content (not sourced safely) reports absent.
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := Read(path); ok {
		t.Fatal("garbage must not read as valid")
	}
}
