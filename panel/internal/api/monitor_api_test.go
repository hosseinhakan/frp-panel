package api

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/frp-suite/panel/internal/gre"
	"github.com/frp-suite/panel/internal/prober"
)

// seedProbeState creates a GRE tunnel env and a client config so the
// prober derives its three canonical target kinds.
func seedProbeState(t *testing.T, e *testEnv) {
	t.Helper()
	tunnel := gre.Tunnel{
		Name: "gt11", LocalPublicIP: "1.2.3.4", RemotePublicIP: "5.6.7.8", Iface: "gt11",
		LocalPrivateIP: "10.100.111.1/30", RemotePrivateIP: "10.100.111.2/30",
		MTU: 1320, MSSMode: "clamp",
	}
	if err := gre.Write(e.srv.paths.GREDir, tunnel); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(e.srv.paths.ClientDir, 0o755); err != nil {
		t.Fatal(err)
	}
	client := "serverAddr = \"10.100.111.2\"\nserverPort = 7000\n"
	if err := os.WriteFile(filepath.Join(e.srv.paths.ClientDir, "c1.toml"), []byte(client), 0o600); err != nil {
		t.Fatal(err)
	}

	// Canned ping answers through the fake runner (the real adapter runs).
	e.runner.execOut["ping -c 1 -W 2 5.6.7.8"] = "64 bytes from 5.6.7.8: icmp_seq=1 ttl=63 time=12.4 ms\n"
	e.runner.execOut["ping -c 1 -W 2 -I gt11 10.100.111.2"] = "64 bytes from 10.100.111.2: icmp_seq=1 ttl=64 time=2.1 ms\n"
}

// replaceDial swaps only the TCP probe mechanic for deterministic tests
// (no real sockets); the ICMP path keeps exercising runnerPing.
func replaceDial(e *testEnv, rtt float64) {
	e.srv.prober = prober.New(prober.DefaultInterval, e.srv.runnerPing,
		func(t prober.Target) (float64, error) { return rtt, nil },
		e.clock.Now, e.srv.probeTargets)
}

func TestProbeTargetDerivation(t *testing.T) {
	e := newTestEnv(t)
	seedProbeState(t, e)

	targets := e.srv.probeTargets()
	byID := map[string]prober.Target{}
	for _, tg := range targets {
		byID[tg.ID] = tg
	}
	if len(byID) != 3 {
		t.Fatalf("targets = %v", byID)
	}
	pub := byID["gre-gt11-public"]
	if pub.Kind != prober.KindICMP || pub.Host != "5.6.7.8" {
		t.Errorf("public target = %+v", pub)
	}
	priv := byID["gre-gt11-private"]
	if priv.Kind != prober.KindICMPTunnel || priv.Iface != "gt11" || priv.Host != "10.100.111.2" {
		t.Errorf("private target = %+v", priv)
	}
	ctrl := byID["frpc-c1-ctrl"]
	if ctrl.Kind != prober.KindTCP || ctrl.Host != "10.100.111.2:7000" {
		t.Errorf("tcp target = %+v", ctrl)
	}
}

func TestLatencySnapshot(t *testing.T) {
	e := newTestEnv(t)
	seedProbeState(t, e)
	replaceDial(e, 3.5)

	e.srv.prober.Tick()

	rec := e.authorized(http.MethodGet, "/api/monitor/latency", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d: %s", rec.Code, rec.Body.String())
	}
	resp := jsonMap(t, rec)
	if resp["interval_seconds"] != float64(5) {
		t.Errorf("interval = %v", resp["interval_seconds"])
	}
	targets, _ := resp["targets"].(map[string]any)
	pub, _ := targets["gre-gt11-public"].(map[string]any)
	if pub == nil || !pub["ok"].(bool) || pub["rtt_ms"] != 12.4 {
		t.Errorf("public = %v", pub)
	}
	priv, _ := targets["gre-gt11-private"].(map[string]any)
	if priv == nil || priv["rtt_ms"] != 2.1 {
		t.Errorf("private = %v", priv)
	}
	ctrl, _ := targets["frpc-c1-ctrl"].(map[string]any)
	if ctrl == nil || ctrl["rtt_ms"] != 3.5 {
		t.Errorf("tcp = %v", ctrl)
	}
}

// TestLatencyStream drives the SSE handler over a real HTTP connection:
// initial snapshot event, then a live sample after a manual probe tick.
func TestLatencyStreamSSE(t *testing.T) {
	e := newTestEnv(t)
	seedProbeState(t, e)
	replaceDial(e, 3.5)

	ts := httptest.NewServer(e.handler)
	defer ts.Close()

	cookie, code := e.login("admin", e.password)
	if code != http.StatusOK {
		t.Fatalf("login = %d", code)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/monitor/latency/stream", nil)
	req.Header.Set("Cookie", "frp_session="+cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content type = %q", ct)
	}

	events := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		var cur strings.Builder
		for sc.Scan() {
			line := sc.Text()
			if line == "" {
				events <- cur.String()
				cur.Reset()
				continue
			}
			if cur.Len() > 0 || strings.HasPrefix(line, "event:") || strings.HasPrefix(line, "data:") {
				if cur.Len() > 0 {
					cur.WriteByte('\n')
				}
				cur.WriteString(line)
			}
		}
		close(events)
	}()

	readEvent := func() string {
		select {
		case ev, ok := <-events:
			if !ok {
				t.Fatal("stream ended early")
			}
			return ev
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for an SSE event")
			return ""
		}
	}

	// 1) immediate snapshot event.
	if ev := readEvent(); !strings.Contains(ev, "event: snapshot") {
		t.Fatalf("first event = %q", ev)
	}
	// 2) a probe tick pushes a live sample event.
	e.srv.prober.Tick()
	ev := readEvent()
	if !strings.Contains(ev, "event: sample") || !strings.Contains(ev, "12.4") {
		t.Fatalf("sample event = %q", ev)
	}
	// 3) failure propagation: kill the private peer, one more tick.
	e.runner.execErr["ping -c 1 -W 2 -I gt11 10.100.111.2"] = "timeout"
	e.srv.prober.Tick()
	ev = readEvent()
	if !strings.Contains(ev, "event: sample") || !strings.Contains(ev, `"gre-gt11-private"`) {
		t.Fatalf("second sample event = %q", ev)
	}

	cancel()
	// Handler exits on disconnect; the scanner goroutine drains to EOF.
	deadline := time.After(5 * time.Second)
	for done := false; !done; {
		select {
		case _, ok := <-events:
			done = !ok
		case <-deadline:
			t.Fatal("stream did not close on disconnect")
		}
	}
}

func TestLogUnitsList(t *testing.T) {
	e := newTestEnv(t)
	seedProbeState(t, e)
	if err := os.MkdirAll(e.srv.paths.ServerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.srv.paths.ServerDir, "server-7000.toml"),
		[]byte("bindAddr = \"0.0.0.0\"\nbindPort = 7000\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := e.authorized(http.MethodGet, "/api/logs/units", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d", rec.Code)
	}
	resp := jsonMap(t, rec)
	units, _ := resp["units"].([]any)
	joined := ""
	for _, u := range units {
		joined += u.(string) + " "
	}
	for _, want := range []string{"frps@server-7000", "frpc@c1", "gre-tunnel@gt11", "frp-watchdog", "frp-panel", "tunnel-turbo"} {
		if !strings.Contains(joined, want) {
			t.Errorf("units list missing %q: %v", want, units)
		}
	}
}

func TestLogStreamSSE(t *testing.T) {
	e := newTestEnv(t)
	e.runner.execStreamOut["journalctl -f -n 200 --output=short-iso -u frp-watchdog"] =
		"\x1b[0m2026-11-20T12:00:00+00:00 host frp-watchdog[99]: watchdog started\x1b[0m\n" +
			"2026-11-20T12:01:00+00:00 host frp-watchdog[99]: GRE gt11: probe failed (1/3)\n"

	ts := httptest.NewServer(e.handler)
	defer ts.Close()

	cookie, _ := e.login("admin", e.password)
	url := ts.URL + "/api/logs/stream?unit=frp-watchdog&lines=200"
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Cookie", "frp_session="+cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	if !strings.Contains(s, "event: open") {
		t.Fatalf("no open event:\n%s", s)
	}
	if !strings.Contains(s, "data: 2026-11-20T12:00:00+00:00 host frp-watchdog[99]: watchdog started") {
		t.Fatalf("first log line missing or ANSI not stripped:\n%s", s)
	}
	if !strings.Contains(s, "data: 2026-11-20T12:01:00+00:00 host frp-watchdog[99]: GRE gt11: probe failed (1/3)") {
		t.Fatalf("second log line missing:\n%s", s)
	}
	if !strings.Contains(s, "event: eof") {
		t.Fatalf("no eof event:\n%s", s)
	}
	if strings.Contains(s, "\x1b[") {
		t.Fatalf("ANSI escapes leaked into the stream:\n%q", s)
	}
}

func TestLogStreamValidation(t *testing.T) {
	e := newTestEnv(t)
	seedProbeState(t, e) // gre-tunnel@gt11 exists; frps@ghost does not

	cases := []struct {
		url  string
		code int
	}{
		{"/api/logs/stream", http.StatusBadRequest},                                   // no unit
		{"/api/logs/stream?unit=sshd", http.StatusBadRequest},                          // not a suite unit
		{"/api/logs/stream?unit=frps@ghost", http.StatusNotFound},                     // no config file
		{"/api/logs/stream?unit=gre-tunnel@gt11&lines=0", http.StatusBadRequest},      // bad lines
		{"/api/logs/stream?unit=gre-tunnel@gt11&lines=99999", http.StatusBadRequest},  // over cap
		{"/api/logs/stream?unit=gre-tunnel@gt11&since=10+minutes+ago", http.StatusBadRequest}, // free-form journalctl expression
		{"/api/logs/stream?unit=gre-tunnel@gt11&since=2026-11-20T10:00:00Z", http.StatusConflict}, // journalctl not available in tests
	}
	for _, c := range cases {
		rec := e.authorized(http.MethodGet, c.url, "")
		if rec.Code != c.code {
			t.Errorf("GET %s = %d (%s), want %d", c.url, rec.Code, rec.Body.String(), c.code)
		}
	}
}

// ---- stats endpoint -------------------------------------------------------------

const statsServerInfo = `{"version":"0.61.0","totalTrafficIn":1024,"totalTrafficOut":2048,"curConns":4,"clientCounts":1,"proxyTypeCount":{"tcp":1}}`
const statsProxyTCP = `{"proxies":[{"name":"tcp-6000","status":"online","todayTrafficIn":512,"todayTrafficOut":256,"curConns":2}]}`

func TestStatsEndpoint(t *testing.T) {
	e := newTestEnv(t)

	// FRP metrics fixture server (the webServer block will point here).
	mux := http.NewServeMux()
	mux.HandleFunc("/api/serverinfo", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, statsServerInfo)
	})
	mux.HandleFunc("/api/proxy/tcp", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, statsProxyTCP)
	})
	metrics := httptest.NewServer(mux)
	defer metrics.Close()
	port := metricsPort(t, metrics.URL)

	if err := os.MkdirAll(e.srv.paths.ServerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	toml := fmt.Sprintf("bindAddr = \"0.0.0.0\"\nbindPort = 7000\n[webServer]\naddr = \"127.0.0.1\"\nport = %d\nuser = \"admin\"\npassword = \"pw\"\n", port)
	if err := os.WriteFile(filepath.Join(e.srv.paths.ServerDir, "server-7000.toml"), []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := e.authorized(http.MethodGet, "/api/stats", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d: %s", rec.Code, rec.Body.String())
	}
	resp := jsonMap(t, rec)
	instances, _ := resp["instances"].([]any)
	if len(instances) != 1 {
		t.Fatalf("instances = %v", resp)
	}
	st, _ := instances[0].(map[string]any)
	if st["kind"] != "server" || st["name"] != "server-7000" || st["up"] != true {
		t.Fatalf("instance = %v", st)
	}
	if st["version"] != "0.61.0" || st["cur_conns"] != float64(4) {
		t.Fatalf("serverinfo not scraped: %v", st)
	}
	proxies, _ := st["proxies"].([]any)
	if len(proxies) != 1 {
		t.Fatalf("proxies = %v", st["proxies"])
	}
	p, _ := proxies[0].(map[string]any)
	if p["name"] != "tcp-6000" || p["cur_conns"] != float64(2) {
		t.Fatalf("proxy = %v", p)
	}

	// Filter: another instance name yields an empty list but stays 200.
	rec = e.authorized(http.MethodGet, "/api/stats?instance=nope", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("filtered GET = %d", rec.Code)
	}
	resp = jsonMap(t, rec)
	if instances, _ := resp["instances"].([]any); len(instances) != 0 {
		t.Fatalf("filter leaked: %v", instances)
	}
}

func metricsPort(t *testing.T, url string) int {
	t.Helper()
	i := strings.LastIndex(url, ":")
	n := 0
	if _, err := fmt.Sscanf(url[i+1:], "%d", &n); err != nil {
		t.Fatalf("no port in %q", url)
	}
	return n
}
