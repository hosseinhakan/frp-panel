package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/frp-suite/panel/internal/watchdog"
)

func seedWatchdogState(t *testing.T, e *testEnv) {
	t.Helper()
	if err := os.MkdirAll(e.srv.paths.EtcPanelDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(e.srv.paths.LogDir, 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestWatchdogGet(t *testing.T) {
	e := newTestEnv(t)
	seedWatchdogState(t, e)
	e.runner.active["frp-watchdog"] = "active"

	if err := os.WriteFile(filepath.Join(e.srv.paths.EtcPanelDir, "watchdog.env"),
		[]byte(watchdog.Render(watchdog.Env{Interval: 45, Threshold: 2, Cooldown: 90, PingTimeout: 2, TCPTimeout: 3})), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.srv.paths.LogDir, "watchdog.log"),
		[]byte("2026-11-20T10:00:00+00:00 frp-watchdog: watchdog started\n2026-11-20T10:01:00+00:00 frp-watchdog: RESTARTED gre-tunnel@gt11.service\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := e.authorized(http.MethodGet, "/api/watchdog", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d: %s", rec.Code, rec.Body.String())
	}
	resp := jsonMap(t, rec)
	unit, _ := resp["unit"].(map[string]any)
	if unit == nil || unit["active"] != "active" {
		t.Errorf("unit = %v", unit)
	}
	cfg, _ := resp["config"].(map[string]any)
	if cfg == nil || cfg["interval"] != float64(45) || cfg["threshold"] != float64(2) {
		t.Errorf("config = %v", resp["config"])
	}
	events, _ := resp["events"].([]any)
	if len(events) != 2 || !strings.Contains(events[1].(string), "RESTARTED") {
		t.Errorf("events = %v", events)
	}
}

func TestWatchdogEnableWritesCLIBytes(t *testing.T) {
	e := newTestEnv(t)
	seedWatchdogState(t, e)
	e.runner.active["frp-watchdog"] = "active" // restart-if-active applies new tuning

	rec := e.authorized(http.MethodPost, "/api/watchdog", `{"enabled":true,"interval":30,"threshold":5,"cooldown":60}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST = %d: %s", rec.Code, rec.Body.String())
	}
	raw, err := os.ReadFile(filepath.Join(e.srv.paths.EtcPanelDir, "watchdog.env"))
	if err != nil {
		t.Fatal(err)
	}
	// Byte-identical to the CLI's watchdog_enable heredoc (defaults fill
	// ping/tcp timeouts).
	want := watchdog.Render(watchdog.Env{Interval: 30, Threshold: 5, Cooldown: 60, PingTimeout: 2, TCPTimeout: 3})
	if string(raw) != want {
		t.Fatalf("watchdog.env drift:\n--- want ---\n%s\n--- got ---\n%s", want, raw)
	}

	// Assets installed + unit enabled + restarted (was active).
	if _, err := os.Stat(filepath.Join(e.srv.paths.BinDir, "frp-watchdog")); err != nil {
		t.Errorf("frp-watchdog helper not installed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.srv.paths.UnitDir, "frp-watchdog.service")); err != nil {
		t.Errorf("frp-watchdog.service not installed: %v", err)
	}
	if !e.runner.called("systemctl:enable frp-watchdog") {
		t.Error("enable frp-watchdog missing")
	}
	if !e.runner.called("systemctl:restart frp-watchdog") {
		t.Error("active unit not restarted to pick up new tuning")
	}
}

func TestWatchdogEnablePartialUpdate(t *testing.T) {
	e := newTestEnv(t)
	seedWatchdogState(t, e)
	// Existing env: only the interval is changed by this request.
	if err := os.WriteFile(filepath.Join(e.srv.paths.EtcPanelDir, "watchdog.env"),
		[]byte(watchdog.Render(watchdog.Env{Interval: 45, Threshold: 2, Cooldown: 90, PingTimeout: 1, TCPTimeout: 4})), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := e.authorized(http.MethodPost, "/api/watchdog", `{"enabled":true,"interval":20}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST = %d: %s", rec.Code, rec.Body.String())
	}
	raw, err := os.ReadFile(filepath.Join(e.srv.paths.EtcPanelDir, "watchdog.env"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := watchdog.Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if env.Interval != 20 || env.Threshold != 2 || env.Cooldown != 90 || env.PingTimeout != 1 || env.TCPTimeout != 4 {
		t.Fatalf("partial update lost values: %+v", env)
	}
	// Old file preserved as .bak (the suite's write rule).
	if _, err := os.Stat(filepath.Join(e.srv.paths.EtcPanelDir, "watchdog.env.bak-"+backupTimestamp(e.clock.now))); err != nil {
		t.Fatalf("no .bak of the previous env: %v", err)
	}
}

func TestWatchdogDisable(t *testing.T) {
	e := newTestEnv(t)
	seedWatchdogState(t, e)
	rec := e.authorized(http.MethodPost, "/api/watchdog", `{"enabled":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST = %d: %s", rec.Code, rec.Body.String())
	}
	if !e.runner.called("systemctl:disable frp-watchdog") {
		t.Error("disable frp-watchdog missing")
	}
	// No env file materializes from a disable.
	if _, err := os.Stat(filepath.Join(e.srv.paths.EtcPanelDir, "watchdog.env")); err == nil {
		t.Error("disable wrote an env file")
	}
}

func TestWatchdogTelegramGetMasksAndPostPreserves(t *testing.T) {
	e := newTestEnv(t)
	seedWatchdogState(t, e)

	env := watchdog.Default()
	env.TGBotToken = "123456:ABC_def-ghijklmnop"
	env.TGChatID = "-1001234567890"
	env.TGAPIBase = "https://tg.example.workers.dev"
	if err := os.WriteFile(filepath.Join(e.srv.paths.EtcPanelDir, "watchdog.env"),
		[]byte(watchdog.Render(env)), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := e.authorized(http.MethodGet, "/api/watchdog", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d: %s", rec.Code, rec.Body.String())
	}
	resp := jsonMap(t, rec)
	if resp["telegram_enabled"] != true {
		t.Errorf("telegram_enabled = %v, want true", resp["telegram_enabled"])
	}
	cfg, _ := resp["config"].(map[string]any)
	tok, _ := cfg["tg_bot_token"].(string)
	if tok == env.TGBotToken || !strings.Contains(tok, "••••") {
		t.Fatalf("token not masked: %q", tok)
	}
	if cfg["tg_chat_id"] != env.TGChatID {
		t.Errorf("chat id = %v", cfg["tg_chat_id"])
	}

	// A blank token keeps the stored one; chat and API base may change.
	rec = e.authorized(http.MethodPost, "/api/watchdog",
		`{"enabled":true,"tgBotToken":"","tgChatId":"-100999","tgApiBase":"https://api.telegram.org"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST = %d: %s", rec.Code, rec.Body.String())
	}
	raw, err := os.ReadFile(filepath.Join(e.srv.paths.EtcPanelDir, "watchdog.env"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := watchdog.Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got.TGBotToken != env.TGBotToken {
		t.Errorf("blank POST wiped the token: %q", got.TGBotToken)
	}
	if got.TGChatID != "-100999" || got.TGAPIBase != "https://api.telegram.org" {
		t.Errorf("telegram update = %+v", got)
	}

	// The masked placeholder echoed by the UI must never overwrite the token.
	rec = e.authorized(http.MethodPost, "/api/watchdog",
		`{"enabled":true,"tgBotToken":"`+tok+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("masked POST = %d: %s", rec.Code, rec.Body.String())
	}
	raw, _ = os.ReadFile(filepath.Join(e.srv.paths.EtcPanelDir, "watchdog.env"))
	if got, err = watchdog.Parse(string(raw)); err != nil || got.TGBotToken != env.TGBotToken {
		t.Fatalf("masked token overwrote the secret: %+v err=%v", got, err)
	}

	// Explicit clear wipes all telegram fields.
	rec = e.authorized(http.MethodPost, "/api/watchdog", `{"enabled":true,"clearTelegram":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("clear POST = %d: %s", rec.Code, rec.Body.String())
	}
	raw, _ = os.ReadFile(filepath.Join(e.srv.paths.EtcPanelDir, "watchdog.env"))
	if got, err = watchdog.Parse(string(raw)); err != nil || got.TelegramEnabled() {
		t.Fatalf("clearTelegram left credentials: %+v err=%v", got, err)
	}
}

func TestWatchdogTestTelegram(t *testing.T) {
	var gotPath, gotChat, gotText string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = r.ParseForm()
		gotChat = r.Form.Get("chat_id")
		gotText = r.Form.Get("text")
		_, _ = io.WriteString(w, `{"ok":true,"result":{}}`)
	}))
	defer srv.Close()

	e := newTestEnv(t)
	seedWatchdogState(t, e)
	env := watchdog.Default()
	env.TGBotToken = "123456:ABC_def-ghijklmnop"
	env.TGChatID = "-1001234567890"
	env.TGAPIBase = srv.URL
	if err := os.WriteFile(filepath.Join(e.srv.paths.EtcPanelDir, "watchdog.env"),
		[]byte(watchdog.Render(env)), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := e.authorized(http.MethodPost, "/api/watchdog/test-telegram", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("test-telegram = %d: %s", rec.Code, rec.Body.String())
	}
	if gotPath != "/bot123456:ABC_def-ghijklmnop/sendMessage" {
		t.Errorf("path = %q", gotPath)
	}
	if gotChat != "-1001234567890" || !strings.Contains(gotText, "test alert") {
		t.Errorf("form = chat %q text %q", gotChat, gotText)
	}

	// Missing credentials: 400, not a network call.
	e2 := newTestEnv(t)
	seedWatchdogState(t, e2)
	if rec := e2.authorized(http.MethodPost, "/api/watchdog/test-telegram", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("missing creds = %d, want 400", rec.Code)
	}

	// Telegram rejecting the token surfaces as 502.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"ok":false,"description":"Unauthorized"}`)
	}))
	defer bad.Close()
	env.TGAPIBase = bad.URL
	if err := os.WriteFile(filepath.Join(e.srv.paths.EtcPanelDir, "watchdog.env"),
		[]byte(watchdog.Render(env)), 0o600); err != nil {
		t.Fatal(err)
	}
	if rec := e.authorized(http.MethodPost, "/api/watchdog/test-telegram", ""); rec.Code != http.StatusBadGateway {
		t.Errorf("upstream failure = %d, want 502: %s", rec.Code, rec.Body.String())
	}
}

func TestWatchdogValidation(t *testing.T) {
	e := newTestEnv(t)
	seedWatchdogState(t, e)
	for _, body := range []string{
		`{"enabled":true,"interval":5}`,  // below the CLI's >= 10 rule
		`{"enabled":true,"threshold":0}`, // threshold >= 1
		`{"enabled":true,"cooldown":-1}`,
		`{}`, // missing enabled switch
	} {
		rec := e.authorized(http.MethodPost, "/api/watchdog", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("POST %s = %d, want 400", body, rec.Code)
		}
	}
	// A rejected request must not write the env.
	if _, err := os.Stat(filepath.Join(e.srv.paths.EtcPanelDir, "watchdog.env")); err == nil {
		t.Error("invalid request wrote watchdog.env")
	}
}
