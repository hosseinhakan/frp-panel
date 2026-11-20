package frpconf

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
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
		{"80,80", nil, true},               // duplicate single port
		{"80,79-81", nil, true},            // duplicate inside range overlap
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
		Protocol:   ProtoQUIC,
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
		BindAddr:  "::",
		BindPort:  7000,
		Protocol:  ProtoNone,
		Token:     goldenToken,
		WebPort:   7501,
		WebUser:   "admin",
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
		ServerAddr: "10.100.111.2",
		ServerPort: 7000,
		Token:      goldenToken,
		Protocol:   "tcp",
		UseTLS:     true,
		Ports:      ports,
		Proto:      ProtoTCPAndUDP,
		WebPort:    7400,
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

	advanced := []byte("serverAddr = \"1.2.3.4\"\nserverPort = 7000\n[log]\nto = \"file\"\n")
	style, unknown, err = Classify(advanced, KindClient)
	if err != nil || style != StyleAdvanced || unknown != "log" {
		t.Errorf("advanced client: style=%v unknown=%q err=%v, want advanced/log", style, unknown, err)
	}

	template := []byte("serverAddr = \"1.2.3.4\"\n{{- range $_, $v := parseNumberRangePair \"6000-6001\" }}\n[[proxies]]\n{{- end }}\n")
	style, _, err = Classify(template, KindClient)
	if err != nil || style != StyleTemplate {
		t.Errorf("template client: style=%v err=%v, want template", style, err)
	}
}

// ---- webServer port allocation ------------------------------------------

func TestUsedWebServerPortsAndAllocate(t *testing.T) {
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
