package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

	if !e.runner.called("systemctl:enable --now gre-tunnel@gt11") {
		t.Error("gre-tunnel@gt11 not enabled")
	}
	if !e.runner.called("systemctl:enable --now frps@server-7025") {
		t.Error("frps@server-7025 not enabled")
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
