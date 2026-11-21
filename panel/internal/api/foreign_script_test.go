package api

import (
	"net/http"
	"os/exec"
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
		"SERVER_PORT='7025'",
		"PROTOCOL='tcp'",
		"TOKEN='ServerToken1234567890'",
		"PORTS='8989,8443'",
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
		"transport.dialServerKeepalive = 30",
		"transport.poolCount = 20",
		"transport.heartbeatInterval = 15",
		"transport.heartbeatTimeout = 45",
		"TLS_ENABLE='false'",
		// Anti-disconnect hardening: local SYN MSS, rp_filter/MTU probing, and
		// a non-destructive duplicate-GRE guard before ip tunnel add. A
		// Protocol-47 NOTRACK is left to `frp-gre up`, which installs it
		// idempotently.
		"LOCAL_MSS=$((MTU - 80))",
		`iptables -t mangle -A POSTROUTING -o "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$LOCAL_MSS"`,
		`iptables -C INPUT -i "$IFACE" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i "$IFACE" -j ACCEPT`,
		`net.ipv4.conf."$IFACE".rp_filter=0`,
		"net.ipv4.tcp_mtu_probing=1",
		"ip -d tunnel show", // conflicts are detected, never deleted
		`$2~/^gre(\/|$)/`,   // `ip -d tunnel show` prints gre/ip on modern kernels
		"GRE_REUSED=0",      // matching live tunnel is reused untouched
		"reusing live GRE $IFACE",
		"refusing to create $IFACE",
		"/usr/local/bin/frpc",
		"net.core.default_qdisc = fq",           // BBR + fq tuning
		`tc qdisc replace dev "$IFACE" root fq`, // fq on the GRE device itself
		"pkill -10 -x frpc",                     // 3h GC cron
	} {
		if !strings.Contains(script, want) {
			t.Errorf("foreign script missing %q:\n%s", want, script)
		}
	}
	for _, forbid := range []string{
		"purge_remote_conflicts",
		`systemctl stop "gre-tunnel@`,
		`systemctl stop "frpc@`,
		"removing stale GRE",
		`systemctl restart "gre-tunnel@`,
		"net.ipv4.tcp_notsent_lowat = 16384",
		"net.ipv4.tcp_fastopen = 3",
	} {
		if strings.Contains(script, forbid) {
			t.Errorf("foreign script must not contain %q (destructive/harmful):\n%s", forbid, script)
		}
	}
	if !strings.Contains(script, "net.ipv4.tcp_notsent_lowat=4294967295") ||
		!strings.Contains(script, "net.ipv4.tcp_fastopen=0") {
		t.Errorf("foreign script must reset the old harmful sysctls at runtime:\n%s", script)
	}
	if strings.Contains(script, `iptables -t raw -A PREROUTING -p 47 -j NOTRACK`) ||
		strings.Contains(script, `iptables -t raw -A OUTPUT -p 47 -j NOTRACK`) {
		t.Errorf("foreign script duplicates the raw NOTRACK rule that frp-gre up already installs:\n%s", script)
	}
	if strings.Contains(script, "$2==\"gre\"") {
		t.Errorf("foreign script still matches only the bare gre link type:\n%s", script)
	}
	if strings.Contains(script, `name = "udp-`) {
		t.Errorf("proto=tcp emitted UDP proxies:\n%s", script)
	}

	// The generated block must be valid bash (nested heredocs included). Skip
	// on hosts without bash — Windows CI runners have Git Bash on PATH.
	if bash, err := exec.LookPath("bash"); err == nil {
		cmd := exec.Command(bash, "-n")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("generated FRP_FOREIGN_SETUP has a syntax error: %v\n%s", err, out)
		}
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

func TestForeignScriptGREAwkMatchesGREIP(t *testing.T) {
	// Modern kernels print the link type as `gre/ip`; the conflict-detection
	// pipeline must still extract the interface name (it refuses to create a
	// new tunnel while another one points at the same remote).
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	const input = "gt11: gre/ip remote 206.1.100.7 local 212.108.97.131 ttl 255\n"
	awk := `awk -v r="206.1.100.7" '$2 ~ /^gre(\/|$)/ { n = $1; sub(/:$/, "", n); for (i = 3; i < NF; i++) if ($i == "remote" && $(i + 1) == r) { print n; break } }'`
	cmd := exec.Command(bash, "-c", awk)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("awk: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "gt11" {
		t.Errorf("gre/ip row matched %q, want gt11:\n%s", got, out)
	}
}
