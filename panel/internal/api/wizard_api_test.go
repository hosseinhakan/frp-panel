package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/frp-suite/panel/internal/gre"
	"github.com/frp-suite/panel/internal/watchdog"
)

const wizardPingOut = `PING 10.100.111.2 (10.100.111.2) from 10.100.111.1 gt11: 56(84) bytes of data.
64 bytes from 10.100.111.2: icmp_seq=1 ttl=64 time=11.7 ms

--- 10.100.111.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 11.700/12.433/13.500/0.900 ms
`

func TestWizardIranCreatesEntryAndMirror(t *testing.T) {
	e := newTestEnv(t)
	e.runner.active["gre-tunnel@gt11"] = "active"
	e.runner.active["frps@server-7025"] = "active"

	rec := e.authorized(http.MethodPost, "/api/wizard/gre-frp",
		`{"role":"iran","iranPublicIp":"1.2.3.4","foreignPublicIp":"5.6.7.8"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("wizard iran = %d: %s", rec.Code, rec.Body.String())
	}
	resp := jsonMap(t, rec)

	tunnel, _ := resp["tunnel"].(map[string]any)
	if tunnel == nil {
		t.Fatalf("no tunnel in response: %v", resp)
	}
	// Entry side is the .2 end of the /30 and owns frps.
	if tunnel["local_private_ip"] != "10.100.111.2/30" || tunnel["remote_private_ip"] != "10.100.111.1/30" {
		t.Errorf("entry private pair = %v/%v", tunnel["local_private_ip"], tunnel["remote_private_ip"])
	}
	if tunnel["mtu"] != float64(1400) {
		t.Errorf("mtu = %v", tunnel["mtu"])
	}
	if tunnel["mss_mode"] != "1220" {
		t.Errorf("mss_mode = %v, want 1220", tunnel["mss_mode"])
	}

	server, _ := resp["server"].(map[string]any)
	if server == nil {
		t.Fatalf("no server in response: %v", resp)
	}
	if server["bindAddr"] != "10.100.111.2" || server["bindPort"] != float64(7025) || server["protocol"] != "tcp" {
		t.Errorf("server = %v", server)
	}
	token, _ := server["token"].(string)
	if len(token) != 32 {
		t.Errorf("token = %q, want a 32-char random token", token)
	}

	// frps must be bound to the tunnel IP, never the public address.
	raw, err := os.ReadFile(filepath.Join(e.srv.paths.ServerDir, "server-7025.toml"))
	if err != nil {
		t.Fatalf("frps config missing: %v", err)
	}
	if !strings.Contains(string(raw), `bindAddr = "10.100.111.2"`) ||
		!strings.Contains(string(raw), `bindPort = 7025`) {
		t.Errorf("frps config is not bound to the tunnel IP:\n%s", raw)
	}
	env, err := os.ReadFile(filepath.Join(e.srv.paths.GREDir, "gt11.env"))
	if err != nil {
		t.Fatalf("gre env missing: %v", err)
	}
	if !strings.Contains(string(env), "LOCAL_PRIVATE_IP=10.100.111.2/30") {
		t.Errorf("gre env not entry-side:\n%s", env)
	}

	payload, _ := resp["mirror_payload"].(string)
	for _, want := range []string{
		"LOCAL_PUBLIC_IP=5.6.7.8",
		"REMOTE_PUBLIC_IP=1.2.3.4",
		"LOCAL_PRIVATE_IP=10.100.111.1/30",
		"REMOTE_PRIVATE_IP=10.100.111.2/30",
		"SERVER_ADDR=10.100.111.2",
		"CONTROL_PORT=7025",
		"PROTOCOL=tcp",
		"TOKEN=" + token,
	} {
		if !strings.Contains(payload, want) {
			t.Errorf("mirror payload missing %q:\n%s", want, payload)
		}
	}
	if cmd, _ := resp["mirror_command"].(string); !strings.Contains(cmd, "frp-manager reverse foreign") {
		t.Errorf("mirror command = %q", cmd)
	}
	foreignScript, _ := resp["foreign_script"].(string)
	for _, want := range []string{
		"FRP_FOREIGN_SETUP",
		"FOREIGN_PUBLIC_IP='5.6.7.8'",
		"IRAN_PUBLIC_IP='1.2.3.4'",
		"FOREIGN_PRIVATE_IP='10.100.111.1/30'",
		"IRAN_PRIVATE_IP='10.100.111.2/30'",
		"SERVER_ADDR='10.100.111.2'",
		`auth.token = "` + token + `"`,
		"ip tunnel add",
		"systemctl is-active",
	} {
		if !strings.Contains(foreignScript, want) {
			t.Errorf("foreign installer missing %q:\n%s", want, foreignScript)
		}
	}

	if !e.runner.called("systemctl:enable --now gre-tunnel@gt11") {
		t.Error("gre-tunnel@gt11 not enabled")
	}
	if !e.runner.called("systemctl:enable --now frps@server-7025") {
		t.Error("frps@server-7025 not enabled")
	}
}

func TestWizardIranCustomTokenAndBind(t *testing.T) {
	e := newTestEnv(t)
	rec := e.authorized(http.MethodPost, "/api/wizard/gre-frp",
		`{"role":"iran","iranPublicIp":"1.2.3.4","foreignPublicIp":"5.6.7.8",`+
			`"bindAddr":"::","token":"my-custom-token-123"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("wizard iran custom = %d: %s", rec.Code, rec.Body.String())
	}
	resp := jsonMap(t, rec)
	server, _ := resp["server"].(map[string]any)
	if server["bindAddr"] != "::" || server["token"] != "my-custom-token-123" {
		t.Errorf("server = %v", server)
	}
	raw, err := os.ReadFile(filepath.Join(e.srv.paths.ServerDir, "server-7025.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `bindAddr = "::"`) ||
		!strings.Contains(string(raw), `auth.token = "my-custom-token-123"`) {
		t.Errorf("custom bind/token not written:\n%s", raw)
	}
	payload, _ := resp["mirror_payload"].(string)
	if !strings.Contains(payload, "SERVER_ADDR=10.100.111.2") ||
		!strings.Contains(payload, "TOKEN=my-custom-token-123") {
		t.Errorf("mirror still must dial the GRE IP and carry the custom token:\n%s", payload)
	}
}

func TestWizardForeignRawSpeed(t *testing.T) {
	e := newTestEnv(t)
	payload := "IFACE=gt11\nLOCAL_PUBLIC_IP=5.6.7.8\nREMOTE_PUBLIC_IP=1.2.3.4\n" +
		"LOCAL_PRIVATE_IP=10.100.111.1/30\nREMOTE_PRIVATE_IP=10.100.111.2/30\n" +
		"MTU=1400\nMSS_MODE=1220\nSERVER_ADDR=10.100.111.2\n" +
		"CONTROL_PORT=7025\nPROTOCOL=tcp\nTOKEN=abcdefghijklmnopqrstuvwxyz012345\n"
	body := `{"role":"foreign","mirrorPayload":` + jsonQuote(payload) +
		`,"localPorts":"443","proto":"tcp","rawSpeed":true}`
	rec := e.authorized(http.MethodPost, "/api/wizard/gre-frp", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("wizard foreign raw speed = %d: %s", rec.Code, rec.Body.String())
	}
	raw, err := os.ReadFile(filepath.Join(e.srv.paths.ClientDir, "client-7025.toml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`transport.tls.enable = false`,
		`transport.useEncryption = false`,
		`transport.useCompression = false`,
		`transport.tcpMux = false`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("raw-speed config missing %q:\n%s", want, raw)
		}
	}
	client, _ := jsonMap(t, rec)["client"].(map[string]any)
	if client["rawSpeed"] != true || client["tls"] != false {
		t.Errorf("client response = %v", client)
	}
}

func TestWizardForeignFromMirrorPayload(t *testing.T) {
	e := newTestEnv(t)
	e.runner.active["gre-tunnel@gt11"] = "active"
	e.runner.active["frpc@client-7025"] = "active"
	e.runner.execOut["ping -c 3 -W 2 -I gt11 10.100.111.2"] = wizardPingOut

	payload := "IFACE=gt11\n" +
		"LOCAL_PUBLIC_IP=5.6.7.8\n" +
		"REMOTE_PUBLIC_IP=1.2.3.4\n" +
		"LOCAL_PRIVATE_IP=10.100.111.1/30\n" +
		"REMOTE_PRIVATE_IP=10.100.111.2/30\n" +
		"MTU=1400\nMSS_MODE=1220\n" +
		"SERVER_ADDR=10.100.111.2\nCONTROL_PORT=7025\nPROTOCOL=tcp\n" +
		"TOKEN=abcdefghijklmnopqrstuvwxyz012345\n"
	body := `{"role":"foreign","mirrorPayload":` + jsonQuote(payload) + `,"localPorts":"443,2053","proto":"tcp"}`
	rec := e.authorized(http.MethodPost, "/api/wizard/gre-frp", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("wizard foreign = %d: %s", rec.Code, rec.Body.String())
	}
	resp := jsonMap(t, rec)
	tunnel, _ := resp["tunnel"].(map[string]any)
	if tunnel["local_private_ip"] != "10.100.111.1/30" || tunnel["remote_private_ip"] != "10.100.111.2/30" {
		t.Errorf("exit private pair = %v/%v", tunnel["local_private_ip"], tunnel["remote_private_ip"])
	}

	client, _ := resp["client"].(map[string]any)
	if client == nil {
		t.Fatalf("no client in response: %v", resp)
	}
	if client["serverAddr"] != "10.100.111.2" || client["serverPort"] != float64(7025) {
		t.Errorf("client = %v", client)
	}
	if client["tls"] != true {
		t.Error("TLS must be enabled by default")
	}
	if client["proxies"] != float64(2) {
		t.Errorf("proxies = %v, want 2 tcp proxies", client["proxies"])
	}
	if wp, _ := client["webPort"].(float64); wp < 7400 || wp > 7499 {
		t.Errorf("webPort = %v, want a loopback metrics port for proxy health", client["webPort"])
	}

	raw, err := os.ReadFile(filepath.Join(e.srv.paths.ClientDir, "client-7025.toml"))
	if err != nil {
		t.Fatalf("frpc config missing: %v", err)
	}
	for _, want := range []string{
		`serverAddr = "10.100.111.2"`,
		`serverPort = 7025`,
		`transport.tls.enable = true`,
		`transport.useEncryption = true`,
		`transport.useCompression = false`,
		`localPort = 443`,
		`remotePort = 443`,
		`localPort = 2053`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("frpc config missing %q:\n%s", want, raw)
		}
	}

	link, _ := resp["link_test"].(map[string]any)
	if link == nil {
		t.Fatalf("no link_test in response: %v", resp)
	}
	if link["reachable"] != true || link["frpc_active"] != true || link["ok"] != true {
		t.Errorf("link_test = %v", link)
	}
	if rtt, _ := link["rtt_ms"].(float64); rtt != 12.433 {
		t.Errorf("rtt_ms = %v", link["rtt_ms"])
	}
}

func TestWizardForeignExplicitInputs(t *testing.T) {
	e := newTestEnv(t)
	e.runner.active["frpc@client-7025"] = "active"
	body := `{"role":"exit","foreignPublicIp":"5.6.7.8","iranPublicIp":"1.2.3.4",
	          "controlPort":7025,"token":"abcdefghijklmnopqrstuvwxyz012345",
	          "protocol":"quic","localPorts":"8443","proto":"both"}`
	rec := e.authorized(http.MethodPost, "/api/wizard/gre-frp", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("wizard foreign explicit = %d: %s", rec.Code, rec.Body.String())
	}
	raw, err := os.ReadFile(filepath.Join(e.srv.paths.ClientDir, "client-7025.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `transport.protocol = "quic"`) {
		t.Errorf("protocol not propagated:\n%s", raw)
	}
	// both toggle => tcp-8443 + udp-8443
	if strings.Count(string(raw), "[[proxies]]") != 2 {
		t.Errorf("expected 2 proxies:\n%s", raw)
	}
}

func TestWizardMirrorRoundTrip(t *testing.T) {
	e := newTestEnv(t)
	e.runner.active["gre-tunnel@gt11"] = "active"
	e.runner.active["frps@server-7025"] = "active"
	e.runner.active["frpc@client-7025"] = "active"
	e.runner.execOut["ping -c 3 -W 2 -I gt11 10.100.111.2"] = wizardPingOut

	rec := e.authorized(http.MethodPost, "/api/wizard/gre-frp",
		`{"role":"iran","iranPublicIp":"1.2.3.4","foreignPublicIp":"5.6.7.8"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("iran = %d: %s", rec.Code, rec.Body.String())
	}
	payload, _ := jsonMap(t, rec)["mirror_payload"].(string)
	if payload == "" {
		t.Fatal("no mirror payload")
	}

	body := `{"role":"foreign","mirrorPayload":` + jsonQuote(payload) + `,"localPorts":"8443","proto":"tcp"}`
	rec = e.authorized(http.MethodPost, "/api/wizard/gre-frp", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("foreign from generated payload = %d: %s", rec.Code, rec.Body.String())
	}
	client, _ := jsonMap(t, rec)["client"].(map[string]any)
	if client["serverAddr"] != "10.100.111.2" || client["serverPort"] != float64(7025) {
		t.Errorf("round-trip client = %v", client)
	}
}

func TestWizardWatchdogDefaultAndOptOut(t *testing.T) {
	e := newTestEnv(t)
	rec := e.authorized(http.MethodPost, "/api/wizard/gre-frp",
		`{"role":"iran","iranPublicIp":"1.2.3.4","foreignPublicIp":"5.6.7.8"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("iran = %d: %s", rec.Code, rec.Body.String())
	}
	wd, _ := jsonMap(t, rec)["watchdog"].(map[string]any)
	if wd == nil || wd["enabled"] != true {
		t.Errorf("watchdog = %v, want enabled", wd)
	}
	if !e.runner.called("systemctl:enable --now frp-watchdog") {
		t.Error("wizard did not enable frp-watchdog")
	}
	raw, err := os.ReadFile(filepath.Join(e.srv.paths.EtcPanelDir, "watchdog.env"))
	if err != nil {
		t.Fatalf("watchdog.env not seeded: %v", err)
	}
	if string(raw) != watchdog.Render(watchdog.Default()) {
		t.Errorf("watchdog.env = %q, want fast defaults", raw)
	}

	// Opt-out leaves the unit alone and reports the skip.
	e2 := newTestEnv(t)
	rec = e2.authorized(http.MethodPost, "/api/wizard/gre-frp",
		`{"role":"iran","iranPublicIp":"1.2.3.4","foreignPublicIp":"5.6.7.8","enableWatchdog":false}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("iran opt-out = %d: %s", rec.Code, rec.Body.String())
	}
	wd, _ = jsonMap(t, rec)["watchdog"].(map[string]any)
	if wd == nil || wd["skipped"] != true {
		t.Errorf("watchdog = %v, want skipped", wd)
	}
	if e2.runner.called("systemctl:enable --now frp-watchdog") {
		t.Error("opt-out still enabled frp-watchdog")
	}
}

func TestWizardValidation(t *testing.T) {
	e := newTestEnv(t)

	cases := []struct {
		name string
		body string
	}{
		{"unknown role", `{"role":"moon"}`},
		{"missing public ips", `{"role":"iran"}`},
		{"same public ips", `{"role":"iran","iranPublicIp":"1.2.3.4","foreignPublicIp":"1.2.3.4"}`},
		{"bad protocol", `{"role":"iran","iranPublicIp":"1.2.3.4","foreignPublicIp":"5.6.7.8","protocol":"sctp"}`},
		{"bad port", `{"role":"iran","iranPublicIp":"1.2.3.4","foreignPublicIp":"5.6.7.8","controlPort":70000}`},
		{"foreign without token", `{"role":"foreign","foreignPublicIp":"5.6.7.8","iranPublicIp":"1.2.3.4","localPorts":"443"}`},
		{"foreign without ports", `{"role":"foreign","foreignPublicIp":"5.6.7.8","iranPublicIp":"1.2.3.4","token":"abcdefghijklmnopqrstuvwxyz012345"}`},
	}
	for _, c := range cases {
		if rec := e.authorized(http.MethodPost, "/api/wizard/gre-frp", c.body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: = %d, want 400: %s", c.name, rec.Code, rec.Body.String())
		}
	}

	// Nothing was written by the rejected requests.
	entries, _ := os.ReadDir(e.srv.paths.GREDir)
	if len(entries) != 0 {
		t.Errorf("failed wizard left %d GRE files", len(entries))
	}
}

// seedWizardTunnel writes an existing GRE env (different public IPs unless
// the test wants the same pair).
func seedWizardTunnel(t *testing.T, e *testEnv, iface, localPub, remotePub, octet string) {
	t.Helper()
	if err := gre.Write(e.srv.paths.GREDir, gre.Tunnel{
		Name:            iface,
		Iface:           iface,
		LocalPublicIP:   localPub,
		RemotePublicIP:  remotePub,
		LocalPrivateIP:  "10.100." + octet + ".2/30",
		RemotePrivateIP: "10.100." + octet + ".1/30",
		MTU:             1400,
		MSSMode:         "1220",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestWizardDefaultsSkipBusyIfaceSubnetAndPort(t *testing.T) {
	e := newTestEnv(t)
	seedWizardTunnel(t, e, "gt11", "9.9.9.9", "8.8.8.8", "111")
	if err := os.MkdirAll(e.srv.paths.ServerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.srv.paths.ServerDir, "server-7025.toml"),
		[]byte("bindPort = 7025\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := e.authorized(http.MethodGet, "/api/wizard/gre-frp/defaults", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("defaults = %d: %s", rec.Code, rec.Body.String())
	}
	d := jsonMap(t, rec)
	if d["iface"] != "gt12" {
		t.Errorf("iface = %v, want gt12", d["iface"])
	}
	if d["subnet"] != "10.100.112.0/30" {
		t.Errorf("subnet = %v, want 10.100.112.0/30", d["subnet"])
	}
	if d["localPrivateIp"] != "10.100.112.2/30" || d["remotePrivateIp"] != "10.100.112.1/30" {
		t.Errorf("private pair = %v/%v", d["localPrivateIp"], d["remotePrivateIp"])
	}
	if d["controlPort"] != float64(7026) {
		t.Errorf("controlPort = %v, want 7026", d["controlPort"])
	}
	if d["serverAddr"] != "10.100.112.2" {
		t.Errorf("serverAddr = %v", d["serverAddr"])
	}
}

func TestWizardIranAutoFallbackOnBusyTunnelAndPort(t *testing.T) {
	e := newTestEnv(t)
	seedWizardTunnel(t, e, "gt11", "9.9.9.9", "8.8.8.8", "111")
	if err := os.MkdirAll(e.srv.paths.ServerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.srv.paths.ServerDir, "server-7025.toml"),
		[]byte("bindPort = 7025\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := e.authorized(http.MethodPost, "/api/wizard/gre-frp",
		`{"role":"iran","iranPublicIp":"1.2.3.4","foreignPublicIp":"5.6.7.8"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("iran = %d: %s", rec.Code, rec.Body.String())
	}
	resp := jsonMap(t, rec)

	tunnel, _ := resp["tunnel"].(map[string]any)
	if tunnel["iface"] != "gt12" {
		t.Errorf("iface = %v, want gt12", tunnel["iface"])
	}
	if tunnel["local_private_ip"] != "10.100.112.2/30" || tunnel["remote_private_ip"] != "10.100.112.1/30" {
		t.Errorf("private pair = %v/%v", tunnel["local_private_ip"], tunnel["remote_private_ip"])
	}
	server, _ := resp["server"].(map[string]any)
	if server["bindPort"] != float64(7026) || server["bindAddr"] != "10.100.112.2" {
		t.Errorf("server = %v, want 10.100.112.2:7026", server)
	}

	warnings, _ := resp["warnings"].([]any)
	joined := ""
	for _, w := range warnings {
		joined += w.(string) + "\n"
	}
	for _, want := range []string{
		"gt11 was busy; allocated gt12",
		"port 7025 was in use; switched to 7026",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings missing %q:\n%s", want, joined)
		}
	}

	payload, _ := resp["mirror_payload"].(string)
	for _, want := range []string{
		"IFACE=gt12",
		"CONTROL_PORT=7026",
		"SERVER_ADDR=10.100.112.2",
		"LOCAL_PRIVATE_IP=10.100.112.1/30",
		"REMOTE_PRIVATE_IP=10.100.112.2/30",
	} {
		if !strings.Contains(payload, want) {
			t.Errorf("mirror payload missing %q:\n%s", want, payload)
		}
	}
	if !e.runner.called("systemctl:enable --now frps@server-7026") {
		t.Error("frps@server-7026 not enabled")
	}
}

func TestWizardIranRerunKeepsOwnTunnel(t *testing.T) {
	e := newTestEnv(t)
	seedWizardTunnel(t, e, "gt11", "1.2.3.4", "5.6.7.8", "111")

	rec := e.authorized(http.MethodPost, "/api/wizard/gre-frp",
		`{"role":"iran","iranPublicIp":"1.2.3.4","foreignPublicIp":"5.6.7.8","iface":"gt12","subnet":"10.100.112.0/30"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("rerun = %d: %s", rec.Code, rec.Body.String())
	}
	resp := jsonMap(t, rec)
	tunnel, _ := resp["tunnel"].(map[string]any)
	if tunnel["iface"] != "gt11" || tunnel["local_private_ip"] != "10.100.111.2/30" {
		t.Errorf("rerun cloned the tunnel instead of refreshing: %v", tunnel)
	}
	if warnings, _ := resp["warnings"].([]any); len(warnings) != 0 {
		t.Errorf("rerun warned: %v", warnings)
	}
}

func TestWizardIranRerunReusesServerPort(t *testing.T) {
	e := newTestEnv(t)
	body := `{"role":"iran","iranPublicIp":"1.2.3.4","foreignPublicIp":"5.6.7.8"}`
	if rec := e.authorized(http.MethodPost, "/api/wizard/gre-frp", body); rec.Code != http.StatusCreated {
		t.Fatalf("first run = %d: %s", rec.Code, rec.Body.String())
	}
	rec := e.authorized(http.MethodPost, "/api/wizard/gre-frp", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("rerun = %d: %s", rec.Code, rec.Body.String())
	}
	server, _ := jsonMap(t, rec)["server"].(map[string]any)
	if server["name"] != "server-7025" || server["bindPort"] != float64(7025) {
		t.Errorf("rerun allocated a second instance: %v", server)
	}
	if _, err := os.Stat(filepath.Join(e.srv.paths.ServerDir, "server-7026.toml")); err == nil {
		t.Error("rerun created server-7026.toml")
	}
}

func TestWizardForeignRerunRefreshesClient(t *testing.T) {
	e := newTestEnv(t)
	payload := "IFACE=gt11\n" +
		"LOCAL_PUBLIC_IP=5.6.7.8\n" +
		"REMOTE_PUBLIC_IP=1.2.3.4\n" +
		"LOCAL_PRIVATE_IP=10.100.111.1/30\n" +
		"REMOTE_PRIVATE_IP=10.100.111.2/30\n" +
		"MTU=1400\nMSS_MODE=1220\n" +
		"SERVER_ADDR=10.100.111.2\nCONTROL_PORT=7025\nPROTOCOL=tcp\n" +
		"TOKEN=abcdefghijklmnopqrstuvwxyz012345\n"
	body := `{"role":"foreign","mirrorPayload":` + jsonQuote(payload) + `,"localPorts":"443,2053","proto":"tcp"}`
	for i := 0; i < 2; i++ {
		rec := e.authorized(http.MethodPost, "/api/wizard/gre-frp", body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("run %d = %d: %s", i+1, rec.Code, rec.Body.String())
		}
	}
	entries, err := os.ReadDir(e.srv.paths.ClientDir)
	if err != nil {
		t.Fatal(err)
	}
	var tomls []string
	for _, ent := range entries {
		if strings.HasSuffix(ent.Name(), ".toml") {
			tomls = append(tomls, ent.Name())
		}
	}
	if len(tomls) != 1 || tomls[0] != "client-7025.toml" {
		t.Errorf("rerun created duplicate clients: %v", tomls)
	}
	raw, err := os.ReadFile(filepath.Join(e.srv.paths.ClientDir, "client-7025.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(raw), "[[proxies]]") != 2 {
		t.Errorf("rerun duplicated proxies:\n%s", raw)
	}
}

func TestWizardForeignIfaceFallbackKeepsMirroredSubnet(t *testing.T) {
	e := newTestEnv(t)
	seedWizardTunnel(t, e, "gt11", "7.7.7.7", "6.6.6.6", "120")

	payload := "IFACE=gt11\n" +
		"LOCAL_PUBLIC_IP=5.6.7.8\n" +
		"REMOTE_PUBLIC_IP=1.2.3.4\n" +
		"LOCAL_PRIVATE_IP=10.100.111.1/30\n" +
		"REMOTE_PRIVATE_IP=10.100.111.2/30\n" +
		"MTU=1400\nMSS_MODE=1220\n" +
		"SERVER_ADDR=10.100.111.2\nCONTROL_PORT=7025\nPROTOCOL=tcp\n" +
		"TOKEN=abcdefghijklmnopqrstuvwxyz012345\n"
	rec := e.authorized(http.MethodPost, "/api/wizard/gre-frp",
		`{"role":"foreign","mirrorPayload":`+jsonQuote(payload)+`,"localPorts":"443","proto":"tcp"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("foreign = %d: %s", rec.Code, rec.Body.String())
	}
	resp := jsonMap(t, rec)
	tunnel, _ := resp["tunnel"].(map[string]any)
	if tunnel["iface"] != "gt12" {
		t.Errorf("iface = %v, want gt12", tunnel["iface"])
	}
	if tunnel["local_private_ip"] != "10.100.111.1/30" {
		t.Errorf("mirrored subnet changed: %v", tunnel["local_private_ip"])
	}
	warnings, _ := resp["warnings"].([]any)
	if len(warnings) == 0 || !strings.Contains(warnings[0].(string), "gt11 was busy locally") {
		t.Errorf("warnings = %v", warnings)
	}
}

func jsonQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
