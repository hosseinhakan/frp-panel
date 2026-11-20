package watchdog

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The CLI writes watchdog.env via heredoc — Render must match those bytes.
func TestRenderByteIdentity(t *testing.T) {
	want := "# FRP Tunnel Suite watchdog tuning (used by /usr/local/bin/frp-watchdog)\n" +
		"INTERVAL=15\nTHRESHOLD=3\nCOOLDOWN=60\nPING_TIMEOUT=2\nTCP_TIMEOUT=3\n" +
		"TG_BOT_TOKEN=\nTG_CHAT_ID=\nTG_API_BASE=https://api.telegram.org\n"
	if got := Render(Default()); got != want {
		t.Fatalf("Render =\n%q\nwant\n%q", got, want)
	}
}

func TestParseRoundTrip(t *testing.T) {
	in := Env{
		Interval: 30, Threshold: 5, Cooldown: 60, PingTimeout: 1, TCPTimeout: 4,
		TGBotToken: "123456:ABC_def-ghijklmnop", TGChatID: "-1001234567890",
		TGAPIBase: "https://tg.example.workers.dev/",
	}
	e, err := Parse(Render(in))
	if err != nil {
		t.Fatal(err)
	}
	in.TGAPIBase = "https://tg.example.workers.dev" // Render trims the slash
	if e != in {
		t.Fatalf("round trip = %+v want %+v", e, in)
	}
}

// Env files written before Telegram support have only the five numeric keys.
func TestParseLegacyEnv(t *testing.T) {
	raw := "INTERVAL=20\nTHRESHOLD=3\nCOOLDOWN=60\nPING_TIMEOUT=2\nTCP_TIMEOUT=3\n"
	e, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if e.TGBotToken != "" || e.TGChatID != "" {
		t.Fatalf("legacy env invented telegram credentials: %+v", e)
	}
	if e.TGAPIBase != DefaultAPIBase {
		t.Fatalf("legacy env api base = %q", e.TGAPIBase)
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
	if _, err := Parse("INTERVAL=60\nTHRESHOLD=1\nCOOLDOWN=1\nPING_TIMEOUT=1\nTCP_TIMEOUT=1\nTG_BOT_TOKEN=$(id)\n"); err == nil {
		t.Fatal("shell-injection in telegram token must fail")
	}
	if _, err := Parse("INTERVAL=60\nTHRESHOLD=1\nCOOLDOWN=1\nPING_TIMEOUT=1\nTCP_TIMEOUT=1\nTG_API_BASE=file:///etc/passwd\n"); err == nil {
		t.Fatal("non-http telegram API base must fail")
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
		{Interval: 60, Threshold: 3, Cooldown: 120, PingTimeout: 2, TCPTimeout: 3, TGBotToken: "bad token with spaces"},
		{Interval: 60, Threshold: 3, Cooldown: 120, PingTimeout: 2, TCPTimeout: 3, TGAPIBase: "ftp://example.com"},
	}
	for _, e := range bad {
		if err := e.Validate(); err == nil {
			t.Fatalf("Validate(%+v) should fail", e)
		}
	}
}

func TestTelegramRedaction(t *testing.T) {
	e := Env{TGBotToken: "123456:ABC_def-ghijklmnop", TGChatID: "-1001234567890", TGAPIBase: "https://api.telegram.org"}
	red := e.Redacted()
	if red.TGBotToken == e.TGBotToken {
		t.Fatal("token was not masked")
	}
	if !strings.HasSuffix(red.TGBotToken, "mnop") || strings.Contains(red.TGBotToken, "ABC") {
		t.Fatalf("mask = %q", red.TGBotToken)
	}
	if red.TGChatID != e.TGChatID || red.TGAPIBase != e.TGAPIBase {
		t.Fatalf("redaction touched non-secret fields: %+v", red)
	}
	if got := MaskToken("short"); got != "••••" {
		t.Fatalf("short mask = %q", got)
	}
	if got := MaskToken(""); got != "" {
		t.Fatalf("empty mask = %q", got)
	}
}

func TestSendTelegram(t *testing.T) {
	var gotPath, gotChat, gotText string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = r.ParseForm()
		gotChat = r.Form.Get("chat_id")
		gotText = r.Form.Get("text")
		_, _ = io.WriteString(w, `{"ok":true,"result":{}}`)
	}))
	defer srv.Close()

	cfg := Env{
		TGBotToken: "123456:ABC_def-ghijklmnop",
		TGChatID:   "-1001234567890",
		TGAPIBase:  srv.URL,
	}
	if err := SendTelegram(context.Background(), srv.Client(), cfg, "hello"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/bot123456:ABC_def-ghijklmnop/sendMessage" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotChat != "-1001234567890" || gotText != "hello" {
		t.Fatalf("form = chat %q text %q", gotChat, gotText)
	}

	// Telegram errors are surfaced, never swallowed.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"ok":false,"description":"Unauthorized"}`)
	}))
	defer srv2.Close()
	cfg.TGAPIBase = srv2.URL
	if err := SendTelegram(context.Background(), srv2.Client(), cfg, "hello"); err == nil ||
		!strings.Contains(err.Error(), "Unauthorized") {
		t.Fatalf("error = %v", err)
	}
}

func TestHealMessage(t *testing.T) {
	msg := HealMessage("iran-1", "GRE", "gre-tunnel@gt11.service", "3 probes failed", 3, "ok")
	for _, want := range []string{
		"Host: iran-1", "Layer: GRE", "Unit: gre-tunnel@gt11.service",
		"Reason: 3 probes failed", "Consecutive failures: 3", "Result: ok",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q:\n%s", want, msg)
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
