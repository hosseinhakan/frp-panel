package frpconf

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// -update rewrites the golden files from the current renderer output:
//
//	go test ./internal/frpconf -update
var update = flag.Bool("update", false, "rewrite golden files from rendered output")

const goldenToken = "K7mQz2xVb9LrT4nY8wPd3cJ6hFgA1sEu" // 32 chars, fixture only

func goldenPath(name string) string { return filepath.Join("golden", name) }

func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := goldenPath(name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("golden %s missing (run go test ./internal/frpconf -update): %v", name, err)
	}
	if string(want) != got {
		t.Errorf("golden %s mismatch:\n--- want ---\n%s\n--- got ---\n%s", name, want, got)
	}
}

// ---- range parser ------------------------------------------------------

func TestParsePortSpecs(t *testing.T) {
	tests := []struct {
		in      string
		want    []PortSpec
		wantErr bool
	}{
		{"22", []PortSpec{{22, 22}}, false},
		{"22,6000-6006,6007", []PortSpec{{22, 22}, {6000, 6006}, {6007, 6007}}, false},
		{" 22 , 6000 - 6006 ", []PortSpec{{22, 22}, {6000, 6006}}, false},
		{"", nil, true},
		{"abc", nil, true},
		{"0", nil, true},
		{"70000", nil, true},
		{"6000-5999", nil, true},
		{"6000-70000", nil, true},
		{"80,80", nil, true},    // duplicate single port
		{"80,79-81", nil, true}, // duplicate inside range overlap
		{"6000-6002,6003-6004", []PortSpec{{6000, 6002}, {6003, 6004}}, false},
	}
	for _, tc := range tests {
		got, err := ParsePortSpecs(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParsePortSpecs(%q): expected error, got %v", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePortSpecs(%q): unexpected error %v", tc.in, err)
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ParsePortSpecs(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestExpandAll(t *testing.T) {
	specs, err := ParsePortSpecs("22,6000-6002")
	if err != nil {
		t.Fatal(err)
	}
	ports, err := ExpandAll(specs, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []int{22, 6000, 6001, 6002}
	if !reflect.DeepEqual(ports, want) {
		t.Errorf("ExpandAll = %v, want %v", ports, want)
	}
	if _, err := ExpandAll(specs, 3); err == nil {
		t.Error("ExpandAll should reject expansion above the limit")
	}
}

func TestBuildProxies(t *testing.T) {
	specs, _ := ParsePortSpecs("22,6000-6001")

	both := BuildProxies(specs, ProtoTCPAndUDP, "127.0.0.1", true, false)
	if len(both) != 6 { // 3 ports x 2 types
		t.Fatalf("BuildProxies(both) length = %d, want 6", len(both))
	}
	wantNames := []string{"tcp-22", "udp-22", "tcp-6000", "udp-6000", "tcp-6001", "udp-6001"}
	for i, want := range wantNames {
		if both[i].Name != want {
			t.Errorf("proxy[%d].Name = %q, want %q", i, both[i].Name, want)
		}
	}
	if both[0].Transport.UseEncryption != true || both[0].Transport.UseCompression != false {
		t.Error("encryption/compression defaults not applied")
	}

	tcpOnly := BuildProxies(specs, ProtoTCPOnly, "127.0.0.1", true, false)
	if len(tcpOnly) != 3 {
		t.Fatalf("BuildProxies(tcp only) length = %d, want 3", len(tcpOnly))
	}
	for _, p := range tcpOnly {
		if p.Type != "tcp" {
			t.Errorf("unexpected type %q in tcp-only build", p.Type)
		}
	}

	udpOnly := BuildProxies(specs, ProtoUDPOnly, "127.0.0.1", true, false)
	if len(udpOnly) != 3 {
		t.Fatalf("BuildProxies(udp only) length = %d, want 3", len(udpOnly))
	}
}

// ---- token generator ---------------------------------------------------

func TestRandomToken(t *testing.T) {
	tok, err := RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != 32 {
		t.Fatalf("token length = %d, want 32", len(tok))
	}
	if !regexp.MustCompile(`^[A-Za-z0-9]{32}$`).MatchString(tok) {
		t.Fatalf("token charset invalid: %q", tok)
	}
	seen := map[string]bool{tok: true}
	for i := 0; i < 100; i++ {
		tok2, err := RandomToken()
		if err != nil {
			t.Fatal(err)
		}
		if seen[tok2] {
			t.Fatalf("duplicate token generated at iteration %d", i)
		}
		seen[tok2] = true
	}
}

// ---- golden render + round trip ----------------------------------------

func serverQuicFixture() *ServerConfig {
	c, err := NewServerConfig(ServerOptions{
		BindAddr:    "10.100.111.2",
		BindPort:    7000,
		Protocol:    ProtoQUIC,
		TCPMux:      false,
		Token:       goldenToken,
		WebPort:     7500,
		WebPassword: "FixtureWebPass1234567890",
	})
	if err != nil {
		panic(err)
	}
	return c
}

func serverPlainFixture() *ServerConfig {
	c, err := NewServerConfig(ServerOptions{
		BindAddr:    "::",
		BindPort:    7000,
		Protocol:    ProtoNone,
		Token:       goldenToken,
		WebPort:     7501,
		WebUser:     "admin",
		WebPassword: "FixtureWebPassPlain12345",
	})
	if err != nil {
		panic(err)
	}
	return c
}

func clientBothFixture() *ClientConfig {
	ports, err := ParsePortSpecs("22,6000-6002")
	if err != nil {
		panic(err)
	}
	c, err := NewClientConfig(ClientOptions{
		ServerAddr:  "10.100.111.2",
		ServerPort:  7000,
		Token:       goldenToken,
		Protocol:    "tcp",
		UseTLS:      true,
		Ports:       ports,
		Proto:       ProtoTCPAndUDP,
		WebPort:     7400,
		WebPassword: "FixtureWebPassClient12345",
	})
	if err != nil {
		panic(err)
	}
	return c
}

func clientTCPFixture() *ClientConfig {
	ports, _ := ParsePortSpecs("22")
	c, err := NewClientConfig(ClientOptions{
		ServerAddr:     "203.0.113.10",
		ServerPort:     7000,
		Token:          goldenToken,
		Protocol:       "websocket",
		TCPMux:         true,
		UseTLS:         false,
		UseCompression: true,
		Ports:          ports,
		Proto:          ProtoTCPOnly,
		WebPort:        7401,
		WebPassword:    "FixtureWebPassTCPOnly1234",
	})
	if err != nil {
		panic(err)
	}
	return c
}

func TestRenderServerGoldenQuic(t *testing.T) {
	checkGolden(t, "server-quic.toml", RenderServer(serverQuicFixture()))
}

func TestRenderServerGoldenPlain(t *testing.T) {
	checkGolden(t, "server-plain.toml", RenderServer(serverPlainFixture()))
}

// Enabling transport TLS must round-trip through render, parse, classify and
// merge so structured edits never silently drop the frps-side requirement.
func TestServerTLSForceRoundTrip(t *testing.T) {
	c, err := NewServerConfig(ServerOptions{
		BindAddr: "10.100.111.2", BindPort: 7025, TLSForce: true, Token: goldenToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	rendered := RenderServer(c)
	if !strings.Contains(rendered, "transport.tls.force = true") {
		t.Fatalf("renderer omitted transport.tls.force:\n%s", rendered)
	}
	cfg, err := ParseServer([]byte(rendered))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Transport.TLS.Force {
		t.Error("parser dropped transport.tls.force")
	}
	if _, unknown, err := Classify([]byte(rendered), KindServer); err != nil || unknown != "" {
		t.Errorf("classify = %q/%v, want managed with no unknown keys", unknown, err)
	}
	cfg.Transport.HeartbeatTimeout = 30
	merged, err := MergeServer([]byte(rendered), cfg)
	if err != nil {
		t.Fatal(err)
	}
	mergedCfg, err := ParseServer(merged)
	if err != nil {
		t.Fatal(err)
	}
	if !mergedCfg.Transport.TLS.Force {
		t.Errorf("merge dropped transport.tls.force:\n%s", merged)
	}

	// Turning it off removes the key again (no stale force = true).
	cfg.Transport.TLS.Force = false
	merged, err = MergeServer(merged, cfg)
	if err != nil {
		t.Fatal(err)
	}
	offCfg, err := ParseServer(merged)
	if err != nil {
		t.Fatal(err)
	}
	if offCfg.Transport.TLS.Force || strings.Contains(string(merged), "force") {
		t.Errorf("merge kept a stale transport.tls.force:\n%s", merged)
	}
}

// The balanced v1.2.10 transport profile is the suite default.
func TestDefaultTransportProfile(t *testing.T) {
	srv, err := NewServerConfig(ServerOptions{BindPort: 7000})
	if err != nil {
		t.Fatal(err)
	}
	if srv.Transport.HeartbeatTimeout != 45 || srv.Transport.TCPKeepalive != 30 ||
		srv.Transport.MaxPoolCount != 65535 || srv.Transport.TCPMux {
		t.Errorf("server transport = %+v, want heartbeat 45 / keepalive 30 / pool 65535 / no mux", srv.Transport)
	}

	cli, err := NewClientConfig(ClientOptions{ServerAddr: "10.100.111.2", Token: goldenToken})
	if err != nil {
		t.Fatal(err)
	}
	if cli.Transport.PoolCount != 20 || cli.Transport.DialServerTimeout != 10 ||
		cli.Transport.DialServerKeepalive != 30 || cli.Transport.HeartbeatInterval != 15 ||
		cli.Transport.HeartbeatTimeout != 45 || cli.Transport.TCPMux || cli.LoginFailExit {
		t.Errorf("client transport = %+v, want pool 20 / dial 10+30 / heartbeat 15+45 / no mux", cli.Transport)
	}
}

// A private/GRE bindAddr must not leak onto the forwarded user ports: frps has
// to keep the control port on the tunnel while the forwarded ports stay public.
func TestServerProxyBindAddrForPrivateBindAddr(t *testing.T) {
	c, err := NewServerConfig(ServerOptions{BindAddr: "10.100.113.2", BindPort: 7000})
	if err != nil {
		t.Fatal(err)
	}
	if c.ProxyBindAddr != "0.0.0.0" {
		t.Fatalf("ProxyBindAddr = %q, want 0.0.0.0", c.ProxyBindAddr)
	}
	rendered := RenderServer(c)
	if !strings.Contains(rendered, `proxyBindAddr = "0.0.0.0"`) {
		t.Errorf("rendered frps config missing proxyBindAddr:\n%s", rendered)
	}
	// Round-trip and merge must preserve it on structured edits.
	cfg, err := ParseServer([]byte(rendered))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProxyBindAddr != "0.0.0.0" {
		t.Errorf("parsed ProxyBindAddr = %q", cfg.ProxyBindAddr)
	}
	cfg.Transport.HeartbeatTimeout = 60
	merged, err := MergeServer([]byte(rendered), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(merged), "proxyBindAddr") {
		t.Errorf("merge dropped proxyBindAddr:\n%s", merged)
	}
}

// A wildcard bindAddr already accepts the forwarded ports on every interface,
// so no proxyBindAddr is emitted (frp's own default applies).
func TestServerProxyBindAddrWildcard(t *testing.T) {
	for _, addr := range []string{"0.0.0.0", "::"} {
		c, err := NewServerConfig(ServerOptions{BindAddr: addr, BindPort: 7000})
		if err != nil {
			t.Fatal(err)
		}
		if c.ProxyBindAddr != "" {
			t.Errorf("bindAddr %q: ProxyBindAddr = %q, want empty", addr, c.ProxyBindAddr)
		}
		if strings.Contains(RenderServer(c), "proxyBindAddr") {
			t.Errorf("bindAddr %q: unexpected proxyBindAddr line", addr)
		}
	}
}

func TestRenderClientGoldenBoth(t *testing.T) {
	checkGolden(t, "client-both.toml", RenderClient(clientBothFixture()))
}

func TestRenderClientGoldenTCPOnly(t *testing.T) {
	checkGolden(t, "client-tcp.toml", RenderClient(clientTCPFixture()))
}

// Round trip: parse a golden file, re-render, bytes must be identical.
// This is the contract the panel relies on for structured edits.
func TestRoundTripServer(t *testing.T) {
	for _, name := range []string{"server-quic.toml", "server-plain.toml"} {
		raw, err := os.ReadFile(goldenPath(name))
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := ParseServer(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := RenderServer(cfg); got != string(raw) {
			t.Errorf("%s: round trip mismatch:\n--- original ---\n%s\n--- re-rendered ---\n%s", name, raw, got)
		}
	}
}

func TestRoundTripClient(t *testing.T) {
	for _, name := range []string{"client-both.toml", "client-tcp.toml"} {
		raw, err := os.ReadFile(goldenPath(name))
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := ParseClient(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := RenderClient(cfg); got != string(raw) {
			t.Errorf("%s: round trip mismatch:\n--- original ---\n%s\n--- re-rendered ---\n%s", name, raw, got)
		}
	}
}

// ---- classify ----------------------------------------------------------

func TestClassify(t *testing.T) {
	raw, err := os.ReadFile(goldenPath("client-both.toml"))
	if err != nil {
		t.Fatal(err)
	}
	style, _, err := Classify(raw, KindClient)
	if err != nil || style != StyleManaged {
		t.Errorf("golden client: style=%v err=%v, want managed", style, err)
	}

	serverRaw, err := os.ReadFile(goldenPath("server-quic.toml"))
	if err != nil {
		t.Fatal(err)
	}
	style, unknown, err := Classify(serverRaw, KindServer)
	if err != nil || style != StyleManaged || unknown != "" {
		t.Errorf("golden server: style=%v unknown=%q err=%v, want managed", style, unknown, err)
	}

	// Valid TOML with extra keys stays structurally editable; "unknown" only
	// tells the compose layer to merge those keys back on save.
	extra := []byte("serverAddr = \"1.2.3.4\"\nserverPort = 7000\n[log]\nto = \"file\"\n")
	style, unknown, err = Classify(extra, KindClient)
	if err != nil || style != StyleManaged || unknown != "log" {
		t.Errorf("extra-key client: style=%v unknown=%q err=%v, want managed/log", style, unknown, err)
	}

	// parseNumberRangePair is the proven mikeesierrah layout: structurally
	// editable, never raw-only.
	template := []byte("serverAddr = \"1.2.3.4\"\n{{- range $_, $v := parseNumberRangePair \"6000-6001\" \"6000-6001\" }}\n[[proxies]]\nname = \"tcp-{{ $v.First }}\"\ntype = \"tcp\"\nlocalIP = \"127.0.0.1\"\nlocalPort = {{ $v.First }}\nremotePort = {{ $v.Second }}\n{{- end }}\n")
	style, _, err = Classify(template, KindClient)
	if err != nil || style != StyleManaged {
		t.Errorf("range-template client: style=%v err=%v, want managed", style, err)
	}

	// Any other Go template stays raw-only.
	otherTemplate := []byte("serverAddr = \"1.2.3.4\"\n{{ if .X }}\nserverPort = 7000\n{{ end }}\n")
	style, _, err = Classify(otherTemplate, KindClient)
	if err != nil || style != StyleTemplate {
		t.Errorf("other-template client: style=%v err=%v, want template", style, err)
	}

	broken := []byte("serverAddr = [\n")
	style, _, err = Classify(broken, KindClient)
	if err == nil || style != StyleAdvanced {
		t.Errorf("broken client: style=%v err=%v, want advanced/error", style, err)
	}

	// The keys reported from live configs must not trigger the old lockout.
	live := []byte("bindAddr = \"::\"\nbindPort = 7018\n" +
		"transport.tcpMuxKeepaliveInterval = 10\n" +
		"transport.quic.keepalivePeriod = 10\n" +
		"transport.tls.enable = false\n")
	style, unknown, err = Classify(live, KindServer)
	if err != nil || style != StyleManaged {
		t.Errorf("live server style=%v unknown=%q err=%v, want managed", style, unknown, err)
	}
	if unknown != "" && unknown != "transport.tls" && unknown != "transport.tls.enable" {
		t.Errorf("live server first unknown = %q, want transport.tls.enable or empty", unknown)
	}
}

func TestComposeClientPreservesExtraKeys(t *testing.T) {
	raw := []byte(`serverAddr = "10.100.111.2"
serverPort = 7000
[log]
to = "file"

[[proxies]]
name = "tcp-8989"
type = "tcp"
localIP = "127.0.0.1"
localPort = 8989
remotePort = 8989
subdomain = "video"
transport.useEncryption = true
transport.useCompression = false
[proxies.annotations]
role = "stream"
`)
	cfg, err := ParseClient(raw)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Transport.TLS.Enable = false
	cfg.Proxies[0].Transport.UseEncryption = false
	out, err := ComposeClient(raw, cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{"[log]", "subdomain", "video", "[proxies.annotations]", "role", "stream", "useEncryption = false"} {
		if !strings.Contains(s, want) {
			t.Errorf("compose dropped %q:\n%s", want, s)
		}
	}
}

// ---- webServer port allocation ------------------------------------------

func TestRangeTemplateParseAndCompose(t *testing.T) {
	raw := []byte(`serverAddr = "10.100.111.2"
serverPort = 7025

loginFailExit = false

auth.method = "token"
auth.token = "ServerToken1234567890"

transport.protocol = "tcp"
transport.tcpMux = false
transport.tcpMuxKeepaliveInterval = 10
transport.dialServerTimeout = 10
transport.dialServerKeepalive = 120
transport.poolCount = 20
transport.heartbeatInterval = 30
transport.heartbeatTimeout = 90
transport.tls.enable = false
transport.quic.keepalivePeriod = 10
transport.quic.maxIdleTimeout = 30
transport.quic.maxIncomingStreams = 100000

{{- range $_, $v := parseNumberRangePair "8989,6000-6002" "8989,6000-6002" }}
[[proxies]]
name = "tcp-{{ $v.First }}"
type = "tcp"
localIP = "127.0.0.1"
localPort = {{ $v.First }}
remotePort = {{ $v.Second }}
transport.useEncryption = false
transport.useCompression = false
{{- end }}
`)
	style, unknown, err := Classify(raw, KindClient)
	if err != nil || style != StyleManaged || unknown != "" {
		t.Fatalf("classify = %v/%q/%v, want managed/empty", style, unknown, err)
	}
	cfg, err := ParseClient(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RangeTemplate || len(cfg.Proxies) != 4 {
		t.Fatalf("parsed range cfg = range:%v proxies:%d, want true/4", cfg.RangeTemplate, len(cfg.Proxies))
	}
	if cfg.Proxies[0].Name != "tcp-8989" || cfg.Proxies[3].Name != "tcp-6002" {
		t.Errorf("range proxies = %v", cfg.Proxies)
	}

	// Replace the ports while keeping the compact template.
	specs, _ := ParsePortSpecs("8989,9443")
	cfg.Proxies = BuildProxies(specs, ProtoTCPOnly, "127.0.0.1", false, false)
	cfg.RangeLocal = "8989,9443"
	cfg.RangeRemote = "8989,9443"
	cfg.Transport.TLS.Enable = true
	out, err := ComposeClient(raw, cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{
		`parseNumberRangePair "8989,9443" "8989,9443"`,
		"transport.tls.enable = true",
		`name = "tcp-{{ $v.First }}"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("composed range config missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "6000") {
		t.Errorf("old ports survived the edit:\n%s", s)
	}
}

func TestUsedWebServerPorts(t *testing.T) {
	dir := t.TempDir()
	if err := WriteServer(filepath.Join(dir, "server-7000.toml"), serverQuicFixture()); err != nil {
		t.Fatal(err)
	}
	if err := WriteClient(filepath.Join(dir, "client-7000.toml"), clientBothFixture()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.toml"), []byte("not [ valid toml"), 0o600); err != nil {
		t.Fatal(err)
	}

	used, err := UsedWebServerPorts(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !used[7500] || !used[7400] {
		t.Errorf("used = %v, want 7500 and 7400 present", used)
	}

	p, ok := AllocatePort(used, ServerWebPortLo, ServerWebPortHi)
	if !ok || p != 7501 {
		t.Errorf("AllocatePort(server range) = %d ok=%v, want 7501", p, ok)
	}
}

func TestListConfigs(t *testing.T) {
	dir := t.TempDir()
	if err := WriteServer(filepath.Join(dir, "server-7000.toml"), serverQuicFixture()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	names, err := ListConfigs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "server-7000" {
		t.Errorf("ListConfigs = %v, want [server-7000]", names)
	}
}

func TestUsedServerAndClientPorts(t *testing.T) {
	sdir, cdir := t.TempDir(), t.TempDir()
	if err := WriteServer(filepath.Join(sdir, "s1.toml"), serverQuicFixture()); err != nil {
		t.Fatal(err)
	} // bind 7000 + quic 7000

	ports, _ := ParsePortSpecs("6000-6001")
	cli, err := NewClientConfig(ClientOptions{
		ServerAddr: "10.100.111.2", ServerPort: 7000, Token: goldenToken,
		Ports: ports, Proto: ProtoTCPOnly, WebPort: 7400, WebPassword: "FxPass1234",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteClient(filepath.Join(cdir, "c1.toml"), cli); err != nil {
		t.Fatal(err)
	}

	srv, err := UsedServerPorts(sdir)
	if err != nil {
		t.Fatal(err)
	}
	if !srv[7000] || len(srv) != 1 {
		t.Errorf("UsedServerPorts = %v, want {7000}", srv)
	}
	rem, err := UsedClientRemotePorts(cdir)
	if err != nil {
		t.Fatal(err)
	}
	if !rem[6000] || !rem[6001] || len(rem) != 2 {
		t.Errorf("UsedClientRemotePorts = %v, want {6000,6001}", rem)
	}

	// Missing dirs behave as empty, not error.
	if m, err := UsedServerPorts(filepath.Join(sdir, "nope")); err != nil || len(m) != 0 {
		t.Errorf("missing dir: %v %v", m, err)
	}
	if m, err := UsedClientRemotePorts(filepath.Join(cdir, "nope")); err != nil || len(m) != 0 {
		t.Errorf("missing dir: %v %v", m, err)
	}
}
