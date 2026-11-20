package stats

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/frp-suite/panel/internal/frpconf"
	"github.com/frp-suite/panel/internal/svc"
)

// Fixtures pinned from frp's dashboard code (see package comment):
// frps /api/serverinfo + /api/proxy/tcp (camelCase, current FRP) and frpc
// /api/status (snake_case proxy map).

const serverInfoFixture = `{
  "version": "0.61.0",
  "bindPort": 7000,
  "totalTrafficIn": 1048576,
  "totalTrafficOut": 2097152,
  "curConns": 7,
  "clientCounts": 2,
  "proxyTypeCount": {"tcp": 2, "udp": 1}
}`

const serverProxyTCPFixture = `{"proxies":[
  {"name":"tcp-6000","status":"online","todayTrafficIn":1024,"todayTrafficOut":2048,"curConns":3},
  {"name":"tcp-6001","status":"online","todayTrafficIn":512,"todayTrafficOut":256,"curConns":1}
]}`

const serverProxyUDPFixture = `{"proxies":[
  {"name":"udp-6000","status":"online","todayTrafficIn":128,"todayTrafficOut":64,"curConns":1}
]}`

const clientStatusFixture = `{
  "tcp": [{"name":"tcp-6000","type":"tcp","status":"running","err":"","local_addr":"127.0.0.1:6000","plugin":"","remote_addr":":6000"}],
  "udp": [{"name":"udp-6000","type":"udp","status":"running","err":"","local_addr":"127.0.0.1:6000","plugin":"","remote_addr":":6000"}]
}`

// Old-FRP spellings (snake_case) must still decode.
const oldServerInfoFixture = `{
  "version": "0.44.0",
  "total_traffic_in": 11,
  "total_traffic_out": 22,
  "cur_conns": 1,
  "proxy_type_count": {"tcp": 1}
}`

func TestParseServerInfo(t *testing.T) {
	info, ok := ParseServerInfo([]byte(serverInfoFixture))
	if !ok {
		t.Fatal("fixture not recognized")
	}
	if info.Version != "0.61.0" || info.CurConns != 7 || info.ClientCounts != 2 {
		t.Fatalf("info = %+v", info)
	}
	if info.TotalTrafficIn != 1048576 || info.TotalTrafficOut != 2097152 {
		t.Fatalf("traffic = %d/%d", info.TotalTrafficIn, info.TotalTrafficOut)
	}
	if info.ProxyTypeCount["tcp"] != 2 || info.ProxyTypeCount["udp"] != 1 {
		t.Fatalf("proxyTypeCount = %v", info.ProxyTypeCount)
	}

	old, ok := ParseServerInfo([]byte(oldServerInfoFixture))
	if !ok || old.Version != "0.44.0" || old.TotalTrafficIn != 11 || old.CurConns != 1 {
		t.Fatalf("old spellings not tolerated: %+v ok=%v", old, ok)
	}
	if _, ok := ParseServerInfo([]byte(`{"unrelated":true}`)); ok {
		t.Fatal("unrecognized payload must not parse")
	}
	if _, ok := ParseServerInfo([]byte(`not json`)); ok {
		t.Fatal("garbage must not parse")
	}
}

func TestParseProxyList(t *testing.T) {
	proxies, ok := ParseProxyList([]byte(serverProxyTCPFixture))
	if !ok || len(proxies) != 2 {
		t.Fatalf("proxies = %+v ok=%v", proxies, ok)
	}
	p := proxies[0]
	if p.Name != "tcp-6000" || p.Status != "online" || p.CurConns != 3 ||
		p.TodayTrafficIn != 1024 || p.TodayTrafficOut != 2048 {
		t.Fatalf("proxy[0] = %+v", p)
	}
	if _, ok := ParseProxyList([]byte(`{"other":1}`)); ok {
		t.Fatal("non-proxy payload must not parse")
	}
}

func TestParseStatusMap(t *testing.T) {
	proxies, ok := ParseStatusMap([]byte(clientStatusFixture))
	if !ok || len(proxies) != 2 {
		t.Fatalf("proxies = %+v ok=%v", proxies, ok)
	}
	var tcp, udp ProxyStat
	for _, p := range proxies {
		switch p.Type {
		case "tcp":
			tcp = p
		case "udp":
			udp = p
		}
	}
	if tcp.Name != "tcp-6000" || tcp.Status != "running" || tcp.LocalAddr != "127.0.0.1:6000" {
		t.Fatalf("tcp = %+v", tcp)
	}
	if udp.Name != "udp-6000" || udp.Type != "udp" {
		t.Fatalf("udp = %+v", udp)
	}
	// The map's key supplies the type when the entry omits it.
	minimal, ok := ParseStatusMap([]byte(`{"tcp":[{"name":"x"}]}`))
	if !ok || len(minimal) != 1 || minimal[0].Type != "tcp" {
		t.Fatalf("type fallback failed: %+v ok=%v", minimal, ok)
	}
}

// ---- scraper end-to-end over a fixture HTTP server ---------------------------

func writeConfig(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

const serverTOML = `
bindAddr = "0.0.0.0"
bindPort = 7000
[webServer]
addr = "127.0.0.1"
port = %d
user = "admin"
password = "secret"
`

const clientTOML = `
serverAddr = "10.100.111.2"
serverPort = 7000
[webServer]
addr = "127.0.0.1"
port = %d
user = "admin"
password = "secret"
`

func TestCollectEndToEnd(t *testing.T) {
	var sawAuth bool
	mux := http.NewServeMux()
	mux.HandleFunc("/api/serverinfo", func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		sawAuth = ok && user == "admin" && pass == "secret"
		w.Write([]byte(serverInfoFixture))
	})
	mux.HandleFunc("/api/proxy/tcp", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(serverProxyTCPFixture))
	})
	mux.HandleFunc("/api/proxy/udp", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(serverProxyUDPFixture))
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(clientStatusFixture))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	root := t.TempDir()
	// Point the webServer blocks at the fixture server's port.
	port := portOf(t, ts.URL)
	writeConfig(t, filepath.Join(root, "server"), "s1.toml", fmt.Sprintf(serverTOML, port))
	writeConfig(t, filepath.Join(root, "client"), "c1.toml", fmt.Sprintf(clientTOML, port))
	writeConfig(t, filepath.Join(root, "client"), "c-no-metrics.toml", "serverAddr = \"1.2.3.4\"\nserverPort = 7000\n")
	paths := svc.Paths{Root: root, ServerDir: filepath.Join(root, "server"), ClientDir: filepath.Join(root, "client")}

	clock := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	sc := New(nil, func() time.Time { return clock })

	out := sc.Collect(paths)
	if len(out) != 2 {
		t.Fatalf("instances = %d (%+v), want 2 (no-metrics client skipped)", len(out), out)
	}
	if !sawAuth {
		t.Fatal("basic auth from the TOML was not sent")
	}
	if out[0].Kind != "client" || out[0].Name != "c1" {
		t.Fatalf("order = %+v then %+v", out[0], out[1])
	}
	cli := out[0]
	if !cli.Up || len(cli.Proxies) != 2 {
		t.Fatalf("client scrape = %+v", cli)
	}
	srv := out[1]
	if !srv.Up || srv.Version != "0.61.0" || srv.CurConns != 7 || srv.TotalTrafficIn != 1048576 {
		t.Fatalf("server scrape = %+v", srv)
	}
	if len(srv.Proxies) != 3 {
		t.Fatalf("server proxies = %+v", srv.Proxies)
	}

	// History: first Collect samples; a second Collect within the same
	// minute does not duplicate.
	if h := sc.History("server", "s1"); len(h) != 1 || h[0].In != 1048576 || h[0].Conns != 7 {
		t.Fatalf("history = %+v", h)
	}
	sc.Collect(paths)
	if h := sc.History("server", "s1"); len(h) != 1 {
		t.Fatalf("sample duplicated inside the minute: %+v", h)
	}
	// A minute later it samples again.
	clock = clock.Add(90 * time.Second)
	sc.Collect(paths)
	if h := sc.History("server", "s1"); len(h) != 2 {
		t.Fatalf("expected second sample, got %+v", h)
	}
}

func TestCollectDownInstance(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, filepath.Join(root, "server"), "s1.toml", fmt.Sprintf(serverTOML, 1)) // nothing listens on :1
	paths := svc.Paths{Root: root, ServerDir: filepath.Join(root, "server")}

	sc := New(nil, time.Now)
	out := sc.Collect(paths)
	if len(out) != 1 || out[0].Up || out[0].Error == "" {
		t.Fatalf("down instance = %+v", out)
	}
	if h := sc.History("server", "s1"); len(h) != 0 {
		t.Fatalf("down instance must not add history: %+v", h)
	}
}

func TestLegacyServerStatusFallback(t *testing.T) {
	// frps without /api/serverinfo falls back to legacy /api/status info.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/serverinfo", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(oldServerInfoFixture))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	root := t.TempDir()
	writeConfig(t, filepath.Join(root, "server"), "old.toml", fmt.Sprintf(serverTOML, portOf(t, ts.URL)))
	paths := svc.Paths{Root: root, ServerDir: filepath.Join(root, "server")}

	out := New(nil, time.Now).Collect(paths)
	if len(out) != 1 || !out[0].Up || out[0].Version != "0.44.0" {
		t.Fatalf("legacy fallback = %+v", out)
	}
}

func TestFetchErrorReported(t *testing.T) {
	sc := New(func(url, user, pass string) ([]byte, int, error) {
		return nil, 0, errors.New("connection refused")
	}, time.Now)
	st := sc.scrapeClient("http://127.0.0.1:1", "a", "b")
	if st.Up || !strings.Contains(st.Error, "connection refused") {
		t.Fatalf("client error = %+v", st)
	}
	st = sc.scrapeServer("http://127.0.0.1:1", "a", "b")
	if st.Up || st.Error == "" {
		t.Fatalf("server error = %+v", st)
	}
}

func TestJobLoopbackNormalization(t *testing.T) {
	sc := New(nil, nil)
	cases := map[string]string{
		"":         "127.0.0.1",
		"0.0.0.0":  "127.0.0.1",
		"::":       "[::1]",
		"::1":      "[::1]",
		"10.1.2.3": "10.1.2.3",
	}
	for addr, wantHost := range cases {
		j := sc.job("server", "x", webServerOf(addr))
		if !strings.HasPrefix(j.url, "http://"+wantHost+":") {
			t.Fatalf("job(%q) url = %q, want prefix http://%s:", addr, j.url, wantHost)
		}
		if j.port != 7500 || j.user != "admin" || j.pass != "pw" {
			t.Fatalf("job fields drifted: %+v", j)
		}
	}
}

func webServerOf(addr string) (w frpconf.WebServer) {
	w.Addr = addr
	w.Port = 7500
	w.User = "admin"
	w.Password = "pw"
	return
}

func portOf(t *testing.T, url string) int {
	t.Helper()
	i := strings.LastIndex(url, ":")
	if i < 0 {
		t.Fatalf("no port in %q", url)
	}
	n := 0
	for _, c := range url[i+1:] {
		if c < '0' || c > '9' {
			t.Fatalf("bad port in %q", url)
		}
		n = n*10 + int(c-'0')
	}
	return n
}
