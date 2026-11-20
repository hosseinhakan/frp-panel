package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/frp-suite/panel/internal/gre"
)

const pingOut = `PING 10.100.111.2 (10.100.111.2) from 10.100.111.1 gt11: 56(84) bytes of data.
64 bytes from 10.100.111.2: icmp_seq=1 ttl=64 time=11.7 ms
64 bytes from 10.100.111.2: icmp_seq=2 ttl=64 time=12.1 ms
64 bytes from 10.100.111.2: icmp_seq=3 ttl=64 time=13.5 ms

--- 10.100.111.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 11.700/12.433/13.500/0.900 ms
`

func TestGRECreateWritesCLIByteIdenticalEnv(t *testing.T) {
	e := newTestEnv(t)
	e.runner.active["gre-tunnel@gt11"] = "active"
	e.runner.execOut["ping -c 3 -W 2 -I gt11 10.100.111.2"] = pingOut

	body := `{"name":"gt11","localPublicIp":"1.2.3.4","remotePublicIp":"5.6.7.8"}`
	rec := e.authorized(http.MethodPost, "/api/gre", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	resp := jsonMap(t, rec)
	tunnel, _ := resp["tunnel"].(map[string]any)
	if tunnel == nil {
		t.Fatalf("response has no tunnel: %v", resp)
	}
	// Private pair auto-suggested (first free /30 == CLI default 111).
	// (gre.Tunnel embeds with its own snake_case json tags.)
	if tunnel["local_private_ip"] != "10.100.111.1/30" || tunnel["remote_private_ip"] != "10.100.111.2/30" {
		t.Errorf("suggested private pair wrong: %v/%v", tunnel["local_private_ip"], tunnel["remote_private_ip"])
	}

	// The env file must be byte-identical to what the CLI writes.
	envPath := filepath.Join(e.srv.paths.GREDir, "gt11.env")
	raw, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	want := gre.RenderEnv(gre.Tunnel{
		Name: "gt11", LocalPublicIP: "1.2.3.4", RemotePublicIP: "5.6.7.8", Iface: "gt11",
		LocalPrivateIP: "10.100.111.1/30", RemotePrivateIP: "10.100.111.2/30",
		MTU: 1400, MSSMode: "clamp",
	})
	if string(raw) != want {
		t.Errorf("env drift vs CLI:\n--- want ---\n%s\n--- got ---\n%s", want, raw)
	}

	// Canonical assets installed from the embedded copies + daemon-reload.
	helper, err := os.ReadFile(filepath.Join(e.srv.paths.BinDir, "frp-gre"))
	if err != nil {
		t.Fatalf("frp-gre helper not installed: %v", err)
	}
	if !strings.Contains(string(helper), "notrack_ensure") {
		t.Error("installed helper is not the canonical frp-gre")
	}
	unit, err := os.ReadFile(filepath.Join(e.srv.paths.UnitDir, "gre-tunnel@.service"))
	if err != nil {
		t.Fatalf("gre-tunnel@.service not installed: %v", err)
	}
	if !strings.Contains(string(unit), "frp-gre up %i") {
		t.Error("installed unit is not the canonical gre-tunnel@.service")
	}
	if !e.runner.called("systemctl:daemon-reload") {
		t.Error("daemon-reload missing after asset install")
	}

	// Unit enabled.
	if !e.runner.called("systemctl:enable --now gre-tunnel@gt11") {
		t.Error("gre-tunnel@gt11 not enabled")
	}
}

func TestGRECreateWithoutSystemdReportsUnitError(t *testing.T) {
	e := newTestEnv(t)
	e.runner.systemctlErr = true
	rec := e.authorized(http.MethodPost, "/api/gre", `{"name":"gt11","localPublicIp":"1.2.3.4","remotePublicIp":"5.6.7.8"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d, want 201 (env is saved)", rec.Code)
	}
	if ue, _ := jsonMap(t, rec)["unit_error"].(string); ue == "" {
		t.Error("unit_error must carry the systemctl failure reason")
	}
	// The .env must exist regardless.
	if _, err := os.Stat(filepath.Join(e.srv.paths.GREDir, "gt11.env")); err != nil {
		t.Errorf("env file missing despite systemd failure: %v", err)
	}
}

func TestGRECreateValidationParity(t *testing.T) {
	e := newTestEnv(t)

	// Same public IPs (CLI rule).
	rec := e.authorized(http.MethodPost, "/api/gre", `{"name":"gt11","localPublicIp":"1.2.3.4","remotePublicIp":"1.2.3.4"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("same IPs = %d, want 400", rec.Code)
	}
	// Bad MTU.
	rec = e.authorized(http.MethodPost, "/api/gre", `{"name":"gt11","localPublicIp":"1.2.3.4","remotePublicIp":"5.6.7.8","mtu":9999}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad MTU = %d, want 400", rec.Code)
	}
	// Half-given private pair.
	rec = e.authorized(http.MethodPost, "/api/gre", `{"name":"gt11","localPublicIp":"1.2.3.4","remotePublicIp":"5.6.7.8","localPrivateIp":"10.100.111.1/30"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("half pair = %d, want 400", rec.Code)
	}
	// No files written by failed attempts.
	entries, _ := os.ReadDir(e.srv.paths.GREDir)
	if len(entries) != 0 {
		t.Errorf("failed creates left %d files", len(entries))
	}

	// Mismatched /24 is a warning, not a rejection.
	rec = e.authorized(http.MethodPost, "/api/gre",
		`{"name":"gt11","localPublicIp":"1.2.3.4","remotePublicIp":"5.6.7.8","localPrivateIp":"10.100.111.1/30","remotePrivateIp":"10.101.112.2/30"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("mismatched /24 create = %d: %s", rec.Code, rec.Body.String())
	}
	if w, _ := jsonMap(t, rec)["warnings"].([]any); len(w) == 0 {
		t.Error("expected the /24 mismatch warning in the response")
	}
}

func TestGREOverwriteKeepsBak(t *testing.T) {
	e := newTestEnv(t)
	body := `{"name":"gt11","localPublicIp":"1.2.3.4","remotePublicIp":"5.6.7.8"}`
	if rec := e.authorized(http.MethodPost, "/api/gre", body); rec.Code != http.StatusCreated {
		t.Fatalf("create = %d", rec.Code)
	}
	changed := `{"name":"gt11","localPublicIp":"1.2.3.4","remotePublicIp":"9.9.9.9"}`
	rec := e.authorized(http.MethodPost, "/api/gre", changed)
	if rec.Code != http.StatusCreated {
		t.Fatalf("overwrite = %d: %s", rec.Code, rec.Body.String())
	}
	if bak, _ := jsonMap(t, rec)["backup"].(string); bak == "" || !strings.HasSuffix(bak, ".env.bak-") && !strings.Contains(bak, ".env.bak-") {
		t.Errorf("overwrite backup = %q", bak)
	}
	raw, _ := os.ReadFile(filepath.Join(e.srv.paths.GREDir, "gt11.env"))
	if !strings.Contains(string(raw), "REMOTE_PUBLIC_IP=9.9.9.9") {
		t.Errorf("overwrite not applied:\n%s", raw)
	}
}

func TestGREListDetailMirror(t *testing.T) {
	e := newTestEnv(t)
	e.runner.active["gre-tunnel@gt11"] = "active"
	body := `{"name":"gt11","localPublicIp":"1.2.3.4","remotePublicIp":"5.6.7.8"}`
	if rec := e.authorized(http.MethodPost, "/api/gre", body); rec.Code != http.StatusCreated {
		t.Fatalf("create = %d", rec.Code)
	}

	// List carries unit + interface status.
	rec := e.authorized(http.MethodGet, "/api/gre", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d", rec.Code)
	}
	var list struct {
		Tunnels []map[string]any `json:"tunnels"`
	}
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Tunnels) != 1 {
		t.Fatalf("tunnels = %d", len(list.Tunnels))
	}
	status, _ := list.Tunnels[0]["status"].(map[string]any)
	if status == nil || status["unitActive"] != "active" {
		t.Errorf("status = %v", status)
	}

	// Detail.
	rec = e.authorized(http.MethodGet, "/api/gre/gt11", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("detail = %d", rec.Code)
	}

	// Mirror matches the CLI's copy-paste output.
	rec = e.authorized(http.MethodGet, "/api/gre/gt11/mirror", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("mirror = %d", rec.Code)
	}
	resp := jsonMap(t, rec)
	envText, _ := resp["env_file"].(string)
	// The handler renders the env path with a forward slash exactly like
	// the CLI does ($GRE_DIR/$IFACE.env) — build `want` the same way.
	want := `# ---- mirror config for the REMOTE node (gt11) ----
# Either use the interactive wizard (frp-manager, menu 10) or run:
frp-manager gre create \
  --local-public 5.6.7.8 \
  --remote-public 1.2.3.4 \
  --iface gt11 \
  --local-private 10.100.111.2/30 \
  --remote-private 10.100.111.1/30 \
  --mtu 1400 \
  --mss clamp

# Equivalent env file (`
	want += e.srv.paths.GREDir + "/gt11.env" + `):
LOCAL_PUBLIC_IP=5.6.7.8
REMOTE_PUBLIC_IP=1.2.3.4
IFACE=gt11
LOCAL_PRIVATE_IP=10.100.111.2/30
REMOTE_PRIVATE_IP=10.100.111.1/30
MTU=1400
MSS_MODE=clamp
`
	if envText != want {
		t.Errorf("mirror text drift vs CLI:\n--- want ---\n%s\n--- got ---\n%s", want, envText)
	}
}

func TestGRELinkTest(t *testing.T) {
	e := newTestEnv(t)
	body := `{"name":"gt11","localPublicIp":"1.2.3.4","remotePublicIp":"5.6.7.8"}`
	if rec := e.authorized(http.MethodPost, "/api/gre", body); rec.Code != http.StatusCreated {
		t.Fatalf("create = %d", rec.Code)
	}
	e.runner.execOut["ping -c 3 -W 2 -I gt11 10.100.111.2"] = pingOut

	rec := e.authorized(http.MethodPost, "/api/gre/gt11/test", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("link test = %d: %s", rec.Code, rec.Body.String())
	}
	resp := jsonMap(t, rec)
	if resp["reachable"] != true {
		t.Errorf("reachable = %v", resp["reachable"])
	}
	if rtt, _ := resp["rtt_ms"].(float64); rtt < 12 || rtt > 13 {
		t.Errorf("rtt_ms = %v, want ~12.433", resp["rtt_ms"])
	}
	if loss, _ := resp["loss_pct"].(float64); loss != 0 {
		t.Errorf("loss_pct = %v", resp["loss_pct"])
	}

	// Unreachable tunnel still returns 200 with reachable=false.
	e.runner.execOut = map[string]string{}
	e.runner.execErr = map[string]string{"ping": ""}
	rec = e.authorized(http.MethodPost, "/api/gre/gt11/test", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("failed link test = %d, want 200 with reachable=false", rec.Code)
	}
	if jsonMap(t, rec)["reachable"] != false {
		t.Errorf("reachable = %v, want false", jsonMap(t, rec)["reachable"])
	}
}

func TestGREDeleteTearsDown(t *testing.T) {
	e := newTestEnv(t)
	body := `{"name":"gt11","localPublicIp":"1.2.3.4","remotePublicIp":"5.6.7.8"}`
	if rec := e.authorized(http.MethodPost, "/api/gre", body); rec.Code != http.StatusCreated {
		t.Fatalf("create = %d", rec.Code)
	}

	rec := e.authorized(http.MethodDelete, "/api/gre/gt11", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("delete = %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(e.srv.paths.GREDir, "gt11.env")); !os.IsNotExist(err) {
		t.Error("env file not removed")
	}
	if !e.runner.called("systemctl:disable --now gre-tunnel@gt11") {
		t.Error("unit not disabled")
	}
	if !e.runner.called("exec:frp-gre down gt11") {
		t.Error("frp-gre down not invoked")
	}

	// Missing tunnel → 404; path-traversal name → 400.
	if rec := e.authorized(http.MethodDelete, "/api/gre/gt11", ""); rec.Code != http.StatusNotFound {
		t.Errorf("delete missing = %d", rec.Code)
	}
	if rec := e.authorized(http.MethodGet, "/api/gre/..%2Fetc", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("traversal name = %d, want 400", rec.Code)
	}
}

func TestParsePing(t *testing.T) {
	loss, avg := parsePing(pingOut)
	if loss != 0 || avg != 12.433 {
		t.Errorf("parsePing = %v/%v, want 0/12.433", loss, avg)
	}
	lossy := "3 packets transmitted, 0 received, 100% packet loss, time 2000ms"
	if l, a := parsePing(lossy); l != 100 || a != 0 {
		t.Errorf("parsePing(lossy) = %v/%v", l, a)
	}
}
