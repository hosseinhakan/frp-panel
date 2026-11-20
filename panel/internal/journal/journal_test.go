package journal

import (
	"strings"
	"testing"
	"time"
)

func TestStripANSI(t *testing.T) {
	in := "\x1b[0m-- Journal begins at \x1b[1;31mboot\x1b[0m --"
	if got := StripANSI(in); got != "-- Journal begins at boot --" {
		t.Fatalf("StripANSI = %q", got)
	}
	if got := StripANSI("plain line"); got != "plain line" {
		t.Fatalf("plain line mangled: %q", got)
	}
}

func TestCanonical(t *testing.T) {
	if got := Canonical("line with trailing spaces  \t\r"); got != "line with trailing spaces" {
		t.Fatalf("Canonical = %q", got)
	}
}

func TestArgs(t *testing.T) {
	args := Args("frps@server-7000", 200, time.Time{}, true)
	want := []string{"-f", "-n", "200", "--output=short-iso", "-u", "frps@server-7000"}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Fatalf("Args = %v, want %v", args, want)
	}

	since := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	args = Args("frp-watchdog", 0, since, false)
	want = []string{"-n", "200", "--output=short-iso", "-u", "frp-watchdog",
		"--since", "2026-11-20T10:00:00Z"}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Fatalf("Args with since = %v, want %v", args, want)
	}

	// Clamp out-of-range line counts.
	args = Args("frp-panel", 5000, time.Time{}, true)
	if args[2] != "1000" {
		t.Fatalf("lines not clamped to MaxLines: %v", args)
	}
	args = Args("frp-panel", -3, time.Time{}, true)
	if args[2] != "200" {
		t.Fatalf("negative lines not defaulted: %v", args)
	}
}

func TestParseSince(t *testing.T) {
	ts, err := ParseSince("2026-11-20T10:00:00Z")
	if err != nil || !ts.Equal(time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("ParseSince = %v, %v", ts, err)
	}
	if ts, err := ParseSince(""); err != nil || !ts.IsZero() {
		t.Fatalf("empty since must be zero, got %v %v", ts, err)
	}
	for _, bad := range []string{"10 minutes ago", "now", "2026-13-99"} {
		if _, err := ParseSince(bad); err == nil {
			t.Fatalf("ParseSince(%q) must fail", bad)
		}
	}
}
