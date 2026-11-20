// Package watchdog models /etc/frp-panel/watchdog.env — the tuning file the
// frp-watchdog helper sources on start. Render is byte-identical to the
// CLI's watchdog_enable heredoc, so both faces manage the same file with
// the same bytes.
package watchdog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// DefaultAPIBase is Telegram's public Bot API. Iran servers where Telegram is
// blocked can point this at a Cloudflare Worker reverse proxy instead.
const DefaultAPIBase = "https://api.telegram.org"

// Env is the watchdog tuning file's managed subset.
type Env struct {
	Interval    int `json:"interval"`     // probe interval in seconds (default 15)
	Threshold   int `json:"threshold"`    // consecutive failures before a restart (default 3)
	Cooldown    int `json:"cooldown"`     // seconds between restart attempts (default 60)
	PingTimeout int `json:"ping_timeout"` // ICMP probe timeout (default 2)
	TCPTimeout  int `json:"tcp_timeout"`  // control-channel probe timeout (default 3)

	// Optional Telegram alerts. Both TGBotToken and TGChatID must be set for
	// delivery; TGAPIBase defaults to Telegram's public API.
	TGBotToken string `json:"tg_bot_token"`
	TGChatID   string `json:"tg_chat_id"`
	TGAPIBase  string `json:"tg_api_base"`
}

// Default matches the CLI's watchdog_enable defaults: fast detection on
// high-jitter routes without turning a flapping link into a restart storm.
func Default() Env {
	return Env{
		Interval: 15, Threshold: 3, Cooldown: 60, PingTimeout: 2, TCPTimeout: 3,
		TGAPIBase: DefaultAPIBase,
	}
}

// Validate applies the CLI's own rules: interval >= 10, threshold >= 1,
// cooldown and timeouts positive, plus Telegram value safety (the file is
// sourced by bash, so values must never carry shell metacharacters).
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
	if err := ValidateTelegram(e); err != nil {
		return err
	}
	return nil
}

// ValidateTelegram checks the optional alert fields without requiring them.
func ValidateTelegram(e Env) error {
	if len(e.TGBotToken) > 200 {
		return fmt.Errorf("telegram bot token is too long")
	}
	for _, r := range e.TGBotToken {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == ':' || r == '_' || r == '-') {
			return fmt.Errorf("telegram bot token contains unsafe characters")
		}
	}
	if len(e.TGChatID) > 64 {
		return fmt.Errorf("telegram chat id is too long")
	}
	for _, r := range e.TGChatID {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '@') {
			return fmt.Errorf("telegram chat id contains unsafe characters")
		}
	}
	if e.TGAPIBase != "" {
		if _, err := NormalizeAPIBase(e.TGAPIBase); err != nil {
			return err
		}
	}
	return nil
}

// TelegramEnabled reports whether both credentials are configured.
func (e Env) TelegramEnabled() bool {
	return strings.TrimSpace(e.TGBotToken) != "" && strings.TrimSpace(e.TGChatID) != ""
}

// NormalizeAPIBase trims a base URL, applies the default when empty and
// rejects anything that is not a plain http(s) origin+path.
func NormalizeAPIBase(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultAPIBase, nil
	}
	raw = strings.TrimRight(raw, "/")
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid telegram API base: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("telegram API base must be http(s)")
	}
	if u.Host == "" {
		return "", fmt.Errorf("telegram API base is missing a host")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("telegram API base must not contain credentials, a query or a fragment")
	}
	return raw, nil
}

// Redacted returns a copy safe for GET responses and non-secret exports: the
// bot token is masked but everything else stays inspectable.
func (e Env) Redacted() Env {
	out := e
	out.TGBotToken = MaskToken(e.TGBotToken)
	if out.TGAPIBase == "" {
		out.TGAPIBase = DefaultAPIBase
	}
	return out
}

// MaskToken keeps a short suffix so an operator can recognise which token is
// configured without exposing it.
func MaskToken(token string) string {
	if token == "" {
		return ""
	}
	if len(token) <= 8 {
		return "••••"
	}
	return "••••" + token[len(token)-4:]
}

// Render emits the file exactly as the CLI heredoc does (header comment +
// KEY=VALUE lines, trailing newline).
func Render(e Env) string {
	base := e.TGAPIBase
	if b, err := NormalizeAPIBase(base); err == nil {
		base = b
	} else {
		base = DefaultAPIBase
	}
	var b strings.Builder
	b.WriteString("# FRP Tunnel Suite watchdog tuning (used by /usr/local/bin/frp-watchdog)\n")
	fmt.Fprintf(&b, "INTERVAL=%d\n", e.Interval)
	fmt.Fprintf(&b, "THRESHOLD=%d\n", e.Threshold)
	fmt.Fprintf(&b, "COOLDOWN=%d\n", e.Cooldown)
	fmt.Fprintf(&b, "PING_TIMEOUT=%d\n", e.PingTimeout)
	fmt.Fprintf(&b, "TCP_TIMEOUT=%d\n", e.TCPTimeout)
	fmt.Fprintf(&b, "TG_BOT_TOKEN=%s\n", e.TGBotToken)
	fmt.Fprintf(&b, "TG_CHAT_ID=%s\n", e.TGChatID)
	fmt.Fprintf(&b, "TG_API_BASE=%s\n", base)
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

// Parse reads the KEY=VALUE form (comments ignored, the five numeric keys are
// required, the three TG_* keys are optional for env files written before
// Telegram support landed).
func Parse(raw string) (Env, error) {
	e := Env{TGAPIBase: DefaultAPIBase}
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
		switch key {
		case "TG_BOT_TOKEN":
			e.TGBotToken = val
		case "TG_CHAT_ID":
			e.TGChatID = val
		case "TG_API_BASE":
			e.TGAPIBase = val
		case "INTERVAL", "THRESHOLD", "COOLDOWN", "PING_TIMEOUT", "TCP_TIMEOUT":
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
			}
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
	base, err := NormalizeAPIBase(e.TGAPIBase)
	if err != nil {
		return Env{}, fmt.Errorf("watchdog.env: %v", err)
	}
	e.TGAPIBase = base
	if err := ValidateTelegram(e); err != nil {
		return Env{}, fmt.Errorf("watchdog.env: %v", err)
	}
	return e, nil
}

// telegramResponse is the subset of Telegram's reply we care about.
type telegramResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description"`
}

// SendTelegram posts a plain-text alert. Delivery is best-effort: callers
// treat any error as non-fatal.
func SendTelegram(ctx context.Context, client *http.Client, cfg Env, text string) error {
	if !cfg.TelegramEnabled() {
		return fmt.Errorf("telegram bot token and chat id are required")
	}
	if err := ValidateTelegram(cfg); err != nil {
		return err
	}
	base, err := NormalizeAPIBase(cfg.TGAPIBase)
	if err != nil {
		return err
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	form := url.Values{}
	form.Set("chat_id", cfg.TGChatID)
	form.Set("text", text)
	form.Set("disable_web_page_preview", "true")
	endpoint := base + "/bot" + cfg.TGBotToken + "/sendMessage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	var tr telegramResponse
	if json.Unmarshal(body, &tr) == nil {
		if tr.OK {
			return nil
		}
		if tr.Description != "" {
			return fmt.Errorf("telegram: %s", tr.Description)
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("telegram HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// TestMessage is the human-readable body of the "Send Test Alert" button.
func TestMessage(host string) string {
	if strings.TrimSpace(host) == "" {
		host = "this server"
	}
	return fmt.Sprintf("FRP Tunnel Suite test alert\nHost: %s\nStatus: Telegram connectivity OK — watchdog alerts are wired up.", host)
}

// HealMessage renders the concise plain-text notification for one heal event.
func HealMessage(host, layer, unit, reason string, consecutive int, result string) string {
	if strings.TrimSpace(host) == "" {
		host = "unknown-host"
	}
	if result == "" {
		result = "unknown"
	}
	return fmt.Sprintf("FRP Tunnel Suite heal event\nHost: %s\nLayer: %s\nUnit: %s\nReason: %s\nConsecutive failures: %d\nResult: %s",
		host, layer, unit, reason, consecutive, result)
}
