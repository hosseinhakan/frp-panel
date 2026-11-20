// Package journal builds journalctl invocations for the SSE log stream and
// canonicalizes its output. The actual process is exec'd by svc.Runner
// (allowlist: journalctl) — this package owns argv construction, ANSI
// stripping and line hygiene only.
package journal

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Output format and stream limits per docs/ARCHITECTURE.md §5.5.
const (
	DefaultLines = 200
	MaxLines     = 1000
	// RingLimit caps how many lines one SSE connection forwards before the
	// stream is closed (the client reconnects and gets a fresh tail).
	RingLimit = 2000
)

var ansiRe = regexp.MustCompile("\x1b\\[[0-9;]*[A-Za-z]")

// StripANSI removes terminal escapes from a journal line.
func StripANSI(s string) string { return ansiRe.ReplaceAllString(s, "") }

// Canonical trims trailing whitespace/carriage returns so SSE data lines
// are uniform across journald versions.
func Canonical(line string) string { return strings.TrimRight(line, " \t\r") }

// Args builds the journalctl argv for a validated unit:
//
//	journalctl -f -n <lines> --output=short-iso -u <unit> [--since <RFC3339>]
//
// Every argument is charset-safe for svc.ExecStream (no spaces, no shell
// metacharacters — RFC3339 timestamps contain only digits and punctuation).
func Args(unit string, lines int, since time.Time, follow bool) []string {
	if lines < 1 {
		lines = DefaultLines
	}
	if lines > MaxLines {
		lines = MaxLines
	}
	args := []string{}
	if follow {
		args = append(args, "-f")
	}
	args = append(args, "-n", strconv.Itoa(lines), "--output=short-iso", "-u", unit)
	if !since.IsZero() {
		args = append(args, "--since", since.UTC().Format(time.RFC3339))
	}
	return args
}

// ParseSince validates the ?since= query parameter. Only strict RFC3339
// timestamps are accepted — free-form journalctl expressions ("10 minutes
// ago") would need shell-unsafe arguments and are rejected.
func ParseSince(v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	ts, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("since must be an RFC3339 timestamp (got %q)", v)
	}
	return ts, nil
}
