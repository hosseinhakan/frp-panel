package api

import (
	"net/http"
	"strings"
	"testing"
)

func TestForeignScriptFromLinkedGRE(t *testing.T) {
	e := newTestEnv(t)
	if rec := e.authorized(http.MethodPost, "/api/servers",
		`{"bindPort":7025,"bindAddr":"10.100.111.2","protocol":"tcp","token":"ServerToken1234567890"}`); rec.Code != http.StatusCreated {
		t.Fatalf("server create = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := e.authorized(http.MethodPost, "/api/gre",
		`{"name":"gt11","localPublicIp":"1.2.3.4","remotePublicIp":"5.6.7.8",`+
			`"localPrivateIp":"10.100.111.2/30","remotePrivateIp":"10.100.111.1/30"}`); rec.Code != http.StatusCreated {
		t.Fatalf("gre create = %d: %s", rec.Code, rec.Body.String())
	}

	rec := e.authorized(http.MethodPost, "/api/servers/server-7025/foreign-script",
		`{"foreignPublicIp":"5.6.7.8","ports":"8989,8443","proto":"tcp","rawSpeed":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("foreign script = %d: %s", rec.Code, rec.Body.String())
	}
	resp := jsonMap(t, rec)
	if resp["linkedTunnel"] != true {
		t.Errorf("linkedTunnel = %v, want true", resp["linkedTunnel"])
	}
	if resp["clientName"] != "client-7025" || resp["serverAddr"] != "10.100.111.2" ||
		resp["serverPort"] != float64(7025) {
		t.Errorf("routing metadata = %v", resp)
	}
	if resp["tls"] != false || resp["encryption"] != false {
		t.Errorf("profile must default TLS/encryption off: tls=%v encryption=%v", resp["tls"], resp["encryption"])
	}
	script, _ := resp["script"].(string)
	for _, want := range []string{
		"FRP_FOREIGN_SETUP",
		"FOREIGN_PUBLIC_IP='5.6.7.8'",
		"IRAN_PUBLIC_IP='1.2.3.4'",
		"FOREIGN_PRIVATE_IP='10.100.111.1/30'",
		"IRAN_PRIVATE_IP='10.100.111.2/30'",
		"SERVER_ADDR='10.100.111.2'",
		"CLIENT_NAME='client-7025'",
		"ip tunnel add",       // embedded frp-gre helper
		"systemctl is-active", // verification step
		`serverAddr = "10.100.111.2"`,
		"serverPort = 7025",
		`auth.token = "ServerToken1234567890"`,
		"transport.tls.enable = false",
		"transport.useEncryption = false",
		"transport.useCompression = false",
		"transport.tcpMux = false",
		`parseNumberRangePair "8989,8443" "8989,8443"`,
		`name = "tcp-{{ $v.First }}"`,
		"transport.dialServerTimeout = 10",
		"transport.dialServerKeepalive = 120",
		"transport.poolCount = 20",
		"transport.heartbeatInterval = 30",
		"transport.heartbeatTimeout = 90",
		"/usr/local/bin/frpc",
		"net.core.default_qdisc=fq", // BBR + fq tuning
		"pkill -10 -x frpc",         // 3h GC cron
	} {
		if !strings.Contains(script, want) {
			t.Errorf("foreign script missing %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, `name = "udp-`) {
		t.Errorf("proto=tcp emitted UDP proxies:\n%s", script)
	}
}

func TestForeignScriptUnlinkedRequiresPublicIP(t *testing.T) {
	e := newTestEnv(t)
	if rec := e.authorized(http.MethodPost, "/api/servers",
		`{"bindPort":7030,"bindAddr":"0.0.0.0","protocol":"tcp"}`); rec.Code != http.StatusCreated {
		t.Fatalf("server create = %d", rec.Code)
	}

	rec := e.authorized(http.MethodPost, "/api/servers/server-7030/foreign-script", `{}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "foreignPublicIp is required") {
		t.Fatalf("unlinked script without IP = %d: %s", rec.Code, rec.Body.String())
	}

	rec = e.authorized(http.MethodPost, "/api/servers/server-7030/foreign-script",
		`{"foreignPublicIp":"5.6.7.8","iranPublicIp":"1.2.3.4","ports":"8989"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("unlinked script = %d: %s", rec.Code, rec.Body.String())
	}
	script, _ := jsonMap(t, rec)["script"].(string)
	if !strings.Contains(script, "SERVER_ADDR='10.100.111.2'") ||
		!strings.Contains(script, "FOREIGN_PRIVATE_IP='10.100.111.1/30'") {
		t.Errorf("default /30 not used:\n%s", script)
	}
}
