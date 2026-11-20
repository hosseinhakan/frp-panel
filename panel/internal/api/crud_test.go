package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/frp-suite/panel/internal/frpconf"
)

func TestUnitStateLabels(t *testing.T) {
	if got := normalizeActive("", nil); got != "inactive" {
		t.Errorf("missing active state = %q, want inactive", got)
	}
	if got := normalizeActive("unknown", nil); got != "inactive" {
		t.Errorf("unknown active state = %q, want inactive", got)
	}
	if got := normalizeActive("failed", nil); got != "failed" {
		t.Errorf("failed active state = %q, want failed", got)
	}
	if got := normalizeEnabled("", nil); got != "disabled" {
		t.Errorf("missing enabled state = %q, want disabled", got)
	}
	if got := normalizeEnabled("not-found", nil); got != "disabled" {
		t.Errorf("not-found enabled state = %q, want disabled", got)
	}
	if got := normalizeEnabled("static", nil); got != "static" {
		t.Errorf("static enabled state = %q, want static", got)
	}
}

// jsonMap decodes a recorder body into a generic map.
func jsonMap(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("invalid JSON response: %v\n%s", err, rec.Body.String())
	}
	return m
}

func TestServersCreateHappyPath(t *testing.T) {
	e := newTestEnv(t)
	e.runner.active["frps@server-7000"] = "active"

	rec := e.authorized(http.MethodPost, "/api/servers", `{"bindPort":7000,"bindAddr":"10.100.111.2","protocol":"quic"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	resp := jsonMap(t, rec)
	if resp["name"] != "server-7000" {
		t.Errorf("name = %v", resp["name"])
	}
	if tok, _ := resp["token"].(string); len(tok) != 32 {
		t.Errorf("token = %v, want 32 chars", resp["token"])
	}
	if resp["verify"] != "server-verify" {
		t.Errorf("verify = %v, want server-verify (binary gate)", resp["verify"])
	}
	if p, _ := resp["webPort"].(float64); p != 7500 {
		t.Errorf("webPort = %v, want 7500 (allocator)", resp["webPort"])
	}
	if pw, _ := resp["webPassword"].(string); len(pw) != 24 {
		t.Errorf("webPassword = %v, want 24 chars", resp["webPassword"])
	}

	// File exists, parses, and carries the secure defaults.
	path := filepath.Join(e.srv.paths.ServerDir, "server-7000.toml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := frpconf.ParseServer(raw)
	if err != nil {
		t.Fatalf("written config does not parse: %v", err)
	}
	if cfg.BindAddr != "10.100.111.2" || cfg.BindPort != 7000 || cfg.QUICBindPort != 7000 {
		t.Errorf("cfg = %+v", cfg)
	}
	if cfg.Auth.Token == "" || cfg.Auth.Token == "mikeesierrah" {
		t.Error("auth token must be a fresh random value")
	}

	// Verify gate ran against the candidate; unit was enabled.
	if !e.runner.called("verify:server:") {
		t.Error("write gate did not run frps verify")
	}
	if !e.runner.called("systemctl:enable --now frps@server-7000") {
		t.Error("unit was not enabled via systemctl")
	}
}

func TestServersCreateDefaultsAndValidation(t *testing.T) {
	e := newTestEnv(t)

	// Missing port.
	rec := e.authorized(http.MethodPost, "/api/servers", `{"bindAddr":"::"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing bindPort = %d, want 400", rec.Code)
	}
	// Bad protocol.
	rec = e.authorized(http.MethodPost, "/api/servers", `{"bindPort":7001,"protocol":"sctp"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad protocol = %d, want 400", rec.Code)
	}
	// Bad bindAddr.
	rec = e.authorized(http.MethodPost, "/api/servers", `{"bindPort":7001,"bindAddr":"not-an-ip"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad bindAddr = %d, want 400", rec.Code)
	}
	// Bad instance name.
	rec = e.authorized(http.MethodPost, "/api/servers", `{"bindPort":7001,"name":"../evil"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad name = %d, want 400", rec.Code)
	}

	// Defaults: name server-<port>, dual-stack bind, quic, web on.
	rec = e.authorized(http.MethodPost, "/api/servers", `{"bindPort":7010}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("default create = %d: %s", rec.Code, rec.Body.String())
	}
	resp := jsonMap(t, rec)
	if resp["name"] != "server-7010" {
		t.Errorf("default name = %v", resp["name"])
	}
	raw, _ := os.ReadFile(filepath.Join(e.srv.paths.ServerDir, "server-7010.toml"))
	if !strings.Contains(string(raw), `bindAddr = "::"`) {
		t.Errorf("default bindAddr missing:\n%s", raw)
	}
}

func TestServersCreateCollisions(t *testing.T) {
	e := newTestEnv(t)
	if rec := e.authorized(http.MethodPost, "/api/servers", `{"bindPort":7000}`); rec.Code != http.StatusCreated {
		t.Fatalf("first create = %d", rec.Code)
	}
	// Same port again.
	rec := e.authorized(http.MethodPost, "/api/servers", `{"bindPort":7000,"name":"other"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("port collision = %d, want 409", rec.Code)
	}
	// Same name again.
	rec = e.authorized(http.MethodPost, "/api/servers", `{"bindPort":7001,"name":"server-7000"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("name collision = %d, want 409", rec.Code)
	}
	// Explicit webServer port already taken by the first instance (7500).
	rec = e.authorized(http.MethodPost, "/api/servers", `{"bindPort":7002,"webPort":7500}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("explicit webPort collision = %d, want 409", rec.Code)
	}
}

func TestWriteGateRejectsAndKeepsOldFile(t *testing.T) {
	e := newTestEnv(t)
	// Create a valid instance first.
	if rec := e.authorized(http.MethodPost, "/api/servers", `{"bindPort":7000}`); rec.Code != http.StatusCreated {
		t.Fatalf("create = %d", rec.Code)
	}
	path := filepath.Join(e.srv.paths.ServerDir, "server-7000.toml")
	before, _ := os.ReadFile(path)

	// Simulate frps verify rejecting everything.
	e.runner.verifyFailure = frpVerifyErr()
	rec := e.authorized(http.MethodPut, "/api/servers/server-7000", `{"bindPort":7500}`)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("update with failing verify = %d, want 422", rec.Code)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Error("rejected write must not touch the file")
	}
}

func TestBinaryMissingFallsBackToInternalVerify(t *testing.T) {
	e := newTestEnv(t)
	e.runner.verifyMissing = true
	rec := e.authorized(http.MethodPost, "/api/servers", `{"bindPort":7000}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create without frps binary = %d: %s", rec.Code, rec.Body.String())
	}
	if jsonMap(t, rec)["verify"] != "internal" {
		t.Errorf("verify mode = %v, want internal", jsonMap(t, rec)["verify"])
	}
}

func TestServersCreateWithoutSystemdStillReportsUnitError(t *testing.T) {
	// Dev hosts / broken systemd: the config is saved (201) but the
	// enable failure must surface in unit_error — never silently succeed.
	e := newTestEnv(t)
	e.runner.systemctlErr = true
	rec := e.authorized(http.MethodPost, "/api/servers", `{"bindPort":7000}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d, want 201 (config still saved)", rec.Code)
	}
	ue, _ := jsonMap(t, rec)["unit_error"].(string)
	if ue == "" {
		t.Error("unit_error must carry the systemctl failure reason")
	}
}

func TestServersListAndGetAndDelete(t *testing.T) {
	e := newTestEnv(t)
	e.runner.active["frps@server-7000"] = "active"
	if rec := e.authorized(http.MethodPost, "/api/servers", `{"bindPort":7000}`); rec.Code != http.StatusCreated {
		t.Fatalf("create = %d", rec.Code)
	}

	// List.
	rec := e.authorized(http.MethodGet, "/api/servers", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d", rec.Code)
	}
	var list struct {
		Servers []map[string]any `json:"servers"`
	}
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Servers) != 1 {
		t.Fatalf("list has %d servers", len(list.Servers))
	}
	srv := list.Servers[0]
	if srv["name"] != "server-7000" || srv["unit"].(map[string]any)["active"] != "active" {
		t.Errorf("summary = %v", srv)
	}

	// Detail (with token — needed for copy/regenerate flows).
	rec = e.authorized(http.MethodGet, "/api/servers/server-7000", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("detail = %d", rec.Code)
	}
	detail := jsonMap(t, rec)
	if tok, _ := detail["token"].(string); len(tok) != 32 {
		t.Errorf("detail token = %v", detail["token"])
	}

	// Delete: unit disabled, file .bak'd.
	rec = e.authorized(http.MethodDelete, "/api/servers/server-7000", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("delete = %d", rec.Code)
	}
	if _, err := os.Stat(filepath.Join(e.srv.paths.ServerDir, "server-7000.toml")); !os.IsNotExist(err) {
		t.Error("config file still exists after delete")
	}
	baks, _ := filepath.Glob(filepath.Join(e.srv.paths.ServerDir, "server-7000.toml.bak-*"))
	if len(baks) != 1 {
		t.Errorf("expected exactly one .bak, got %v", baks)
	}
	if !e.runner.called("systemctl:disable --now frps@server-7000") {
		t.Error("unit not disabled on delete")
	}

	// Detail now 404s.
	rec = e.authorized(http.MethodGet, "/api/servers/server-7000", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("deleted detail = %d, want 404", rec.Code)
	}
}

func TestServerUpdateManagedAndBak(t *testing.T) {
	e := newTestEnv(t)
	e.runner.active["frps@server-7000"] = "active"
	if rec := e.authorized(http.MethodPost, "/api/servers", `{"bindPort":7000}`); rec.Code != http.StatusCreated {
		t.Fatalf("create = %d", rec.Code)
	}
	path := filepath.Join(e.srv.paths.ServerDir, "server-7000.toml")

	rec := e.authorized(http.MethodPut, "/api/servers/server-7000", `{"bindAddr":"10.100.111.2"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("update = %d: %s", rec.Code, rec.Body.String())
	}
	raw, _ := os.ReadFile(path)
	cfg, _ := frpconf.ParseServer(raw)
	if cfg.BindAddr != "10.100.111.2" || cfg.BindPort != 7000 {
		t.Errorf("update not applied: %+v", cfg)
	}
	baks, _ := filepath.Glob(path + ".bak-*")
	if len(baks) != 1 {
		t.Errorf("update must leave one .bak, got %v", baks)
	}
	if !e.runner.called("systemctl:restart frps@server-7000") {
		t.Error("active unit must be restarted after update")
	}
}

func TestServerUpdatePreservesUnknownKeys(t *testing.T) {
	e := newTestEnv(t)
	dir := e.srv.paths.ServerDir
	os.MkdirAll(dir, 0o755)
	extra := "bindAddr = \"::\"\nbindPort = 7000\ntransport.tcpMuxKeepaliveInterval = 10\n" +
		"transport.tls.force = true\n[log]\nto = \"file\"\n"
	os.WriteFile(filepath.Join(dir, "adv.toml"), []byte(extra), 0o600)

	rec := e.authorized(http.MethodPut, "/api/servers/adv", `{"bindAddr":"10.100.111.2","tcpMux":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("extra-key update = %d: %s", rec.Code, rec.Body.String())
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "adv.toml"))
	cfg, err := frpconf.ParseServer(raw)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BindAddr != "10.100.111.2" {
		t.Errorf("bindAddr = %q, want 10.100.111.2", cfg.BindAddr)
	}
	if !strings.Contains(string(raw), "[log]") || !strings.Contains(string(raw), "file") {
		t.Errorf("structured edit dropped [log]:\n%s", raw)
	}
	if !strings.Contains(string(raw), "force = true") || !strings.Contains(string(raw), "tls") {
		t.Errorf("structured edit dropped transport.tls:\n%s", raw)
	}

	// Raw editor still round-trips the same file.
	rec = e.authorized(http.MethodPut, "/api/servers/adv/raw", `{"content":"bindAddr = \"::\"\nbindPort = 7000\n[log]\nto = \"file\"\n"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("raw put = %d: %s", rec.Code, rec.Body.String())
	}
	rec = e.authorized(http.MethodGet, "/api/servers/adv/raw", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "[log]") {
		t.Errorf("raw get = %d %s", rec.Code, rec.Body.String())
	}
}

func TestTokenRegenerateAndPropagate(t *testing.T) {
	e := newTestEnv(t)
	// Server + client sharing the token (client reuses server's token).
	if rec := e.authorized(http.MethodPost, "/api/servers", `{"bindPort":7000}`); rec.Code != http.StatusCreated {
		t.Fatalf("server create = %d", rec.Code)
	}
	srvRec := e.authorized(http.MethodGet, "/api/servers/server-7000", "")
	oldTok, _ := jsonMap(t, srvRec)["token"].(string)

	e.runner.active["frps@server-7000"] = "active"
	e.runner.active["frpc@client-7000"] = "active"
	clientBody := `{"serverAddr":"10.100.111.2","serverPort":7000,"ports":"6000","proto":"both"}`
	clientRec := e.authorized(http.MethodPost, "/api/clients", clientBody)
	if clientRec.Code != http.StatusCreated {
		t.Fatalf("client create = %d: %s", clientRec.Code, clientRec.Body.String())
	}
	if got, _ := jsonMap(t, clientRec)["token"].(string); got != oldTok {
		t.Errorf("client should reuse the local server token: %q vs %q", got, oldTok)
	}

	// Regenerate with propagation.
	e.runner.resetCalls()
	rec := e.authorized(http.MethodPost, "/api/servers/server-7000/token/regenerate", `{"propagate":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("regen = %d: %s", rec.Code, rec.Body.String())
	}
	resp := jsonMap(t, rec)
	newTok, _ := resp["token"].(string)
	if newTok == oldTok || len(newTok) != 32 {
		t.Errorf("new token = %q", newTok)
	}
	propagated, _ := resp["propagated"].([]any)
	if len(propagated) != 1 || propagated[0] != "client-7000" {
		t.Errorf("propagated = %v", resp["propagated"])
	}
	if !e.runner.called("systemctl:restart frps@server-7000") {
		t.Error("frps unit not restarted after token change")
	}
	if !e.runner.called("systemctl:restart frpc@client-7000") {
		t.Error("affected frpc unit not restarted")
	}

	// The client file now carries the new token.
	craw, _ := os.ReadFile(filepath.Join(e.srv.paths.ClientDir, "client-7000.toml"))
	ccfg, err := frpconf.ParseClient(craw)
	if err != nil {
		t.Fatal(err)
	}
	if ccfg.Auth.Token != newTok {
		t.Errorf("client token not propagated: %q", ccfg.Auth.Token)
	}
	// Server file too.
	sraw, _ := os.ReadFile(filepath.Join(e.srv.paths.ServerDir, "server-7000.toml"))
	scfg, _ := frpconf.ParseServer(sraw)
	if scfg.Auth.Token != newTok {
		t.Errorf("server token not updated: %q", scfg.Auth.Token)
	}
}

func TestClientsCreateDualProtoAndCollision(t *testing.T) {
	e := newTestEnv(t)
	if rec := e.authorized(http.MethodPost, "/api/servers", `{"bindPort":7000}`); rec.Code != http.StatusCreated {
		t.Fatalf("server create = %d", rec.Code)
	}

	body := `{"serverAddr":"10.100.111.2","serverPort":7000,"ports":"22,6000-6001","proto":"both"}`
	rec := e.authorized(http.MethodPost, "/api/clients", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("client create = %d: %s", rec.Code, rec.Body.String())
	}
	resp := jsonMap(t, rec)
	if resp["name"] != "client-7000" {
		t.Errorf("name = %v", resp["name"])
	}
	if int(resp["proxies"].(float64)) != 6 { // 3 ports × (tcp+udp)
		t.Errorf("proxies = %v, want 6", resp["proxies"])
	}

	// Secure transport defaults in the file.
	raw, _ := os.ReadFile(filepath.Join(e.srv.paths.ClientDir, "client-7000.toml"))
	cfg, err := frpconf.ParseClient(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Transport.TLS.Enable {
		t.Error("transport.tls.enable must default to true")
	}
	if cfg.Transport.Protocol != "tcp" {
		t.Errorf("protocol = %q", cfg.Transport.Protocol)
	}
	for _, px := range cfg.Proxies {
		if !px.Transport.UseEncryption || px.Transport.UseCompression {
			t.Errorf("proxy %s: encryption/compression defaults wrong", px.Name)
		}
	}
	if cfg.WebServer.Port != 7400 {
		t.Errorf("client webPort = %d, want 7400", cfg.WebServer.Port)
	}

	// Second client forwarding an overlapping port → 409.
	rec = e.authorized(http.MethodPost, "/api/clients", `{"serverAddr":"10.100.111.2","serverPort":7000,"ports":"6001","name":"other"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("remote port collision = %d, want 409", rec.Code)
	}

	// Token required when no local server exists.
	e2 := newTestEnv(t)
	rec = e2.authorized(http.MethodPost, "/api/clients", `{"serverAddr":"1.2.3.4","ports":"22"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("client without token/server = %d, want 400", rec.Code)
	}
}

func TestClientProxiesAddReplaceDelete(t *testing.T) {
	e := newTestEnv(t)
	if rec := e.authorized(http.MethodPost, "/api/servers", `{"bindPort":7000}`); rec.Code != http.StatusCreated {
		t.Fatalf("server create = %d", rec.Code)
	}
	body := `{"serverAddr":"10.100.111.2","serverPort":7000,"ports":"22","proto":"tcp"}`
	if rec := e.authorized(http.MethodPost, "/api/clients", body); rec.Code != http.StatusCreated {
		t.Fatalf("client create = %d", rec.Code)
	}

	// Add a range with the dual toggle.
	rec := e.authorized(http.MethodPost, "/api/clients/client-7000/proxies", `{"ports":"6000-6001","proto":"both"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("proxies add = %d: %s", rec.Code, rec.Body.String())
	}
	resp := jsonMap(t, rec)
	if int(resp["added"].(float64)) != 4 || int(resp["total"].(float64)) != 5 {
		t.Errorf("add = %+v", resp)
	}

	// Collision with the server's own port → 409.
	rec = e.authorized(http.MethodPost, "/api/clients/client-7000/proxies", `{"ports":"7000"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("collision with server bind port = %d, want 409", rec.Code)
	}

	// Delete by port removes the paired tcp/udp blocks.
	rec = e.authorized(http.MethodDelete, "/api/clients/client-7000/proxies?ports=6000", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("proxies delete = %d: %s", rec.Code, rec.Body.String())
	}
	removed, _ := jsonMap(t, rec)["removed"].([]any)
	if len(removed) != 2 {
		t.Errorf("removed = %v, want tcp-6000 + udp-6000", removed)
	}

	// Full replace with validation.
	replace := `{"proxies":[{"name":"ssh","type":"tcp","localIp":"127.0.0.1","localPort":22,"remotePort":22},{"name":"bad","type":"sctp","localIp":"127.0.0.1","localPort":1,"remotePort":1}]}`
	rec = e.authorized(http.MethodPut, "/api/clients/client-7000/proxies", replace)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid replace = %d, want 400", rec.Code)
	}
	replace = `{"proxies":[{"name":"ssh","type":"tcp","localIp":"127.0.0.1","localPort":22,"remotePort":22}]}`
	rec = e.authorized(http.MethodPut, "/api/clients/client-7000/proxies", replace)
	if rec.Code != http.StatusOK {
		t.Fatalf("replace = %d: %s", rec.Code, rec.Body.String())
	}
	if int(jsonMap(t, rec)["total"].(float64)) != 1 {
		t.Errorf("replace total = %v", jsonMap(t, rec)["total"])
	}

	// Client update: flip TLS off.
	rec = e.authorized(http.MethodPut, "/api/clients/client-7000", `{"useTls":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("client update = %d: %s", rec.Code, rec.Body.String())
	}
	raw, _ := os.ReadFile(filepath.Join(e.srv.paths.ClientDir, "client-7000.toml"))
	if !strings.Contains(string(raw), "transport.tls.enable = false") {
		t.Errorf("TLS not updated:\n%s", raw)
	}

	// Structured port + raw-speed edit replaces the forwarded list.
	rec = e.authorized(http.MethodPut, "/api/clients/client-7000",
		`{"ports":"8989,8443,2053","proto":"tcp","useEncryption":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("port edit = %d: %s", rec.Code, rec.Body.String())
	}
	raw, _ = os.ReadFile(filepath.Join(e.srv.paths.ClientDir, "client-7000.toml"))
	ccfg, err := frpconf.ParseClient(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(ccfg.Proxies) != 3 {
		t.Fatalf("proxies = %d, want 3", len(ccfg.Proxies))
	}
	for _, p := range ccfg.Proxies {
		if p.RemotePort != 8989 && p.RemotePort != 8443 && p.RemotePort != 2053 {
			t.Errorf("unexpected remote port %d", p.RemotePort)
		}
		if p.Transport.UseEncryption {
			t.Errorf("proxy %s still encrypts after raw-speed edit", p.Name)
		}
	}

	// Extra keys survive a structured connection edit (merge path).
	withLog := string(raw) + "\n[log]\nto = \"file\"\n"
	if err := os.WriteFile(filepath.Join(e.srv.paths.ClientDir, "client-7000.toml"), []byte(withLog), 0o600); err != nil {
		t.Fatal(err)
	}
	rec = e.authorized(http.MethodPut, "/api/clients/client-7000", `{"useTls":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("merge update = %d: %s", rec.Code, rec.Body.String())
	}
	raw, _ = os.ReadFile(filepath.Join(e.srv.paths.ClientDir, "client-7000.toml"))
	if !strings.Contains(string(raw), "[log]") {
		t.Errorf("client merge dropped [log]:\n%s", raw)
	}
	rec = e.authorized(http.MethodPut, "/api/clients/client-7000",
		`{"ports":"9443","proto":"tcp","useEncryption":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("merge port edit = %d: %s", rec.Code, rec.Body.String())
	}
	raw, _ = os.ReadFile(filepath.Join(e.srv.paths.ClientDir, "client-7000.toml"))
	ccfg, err = frpconf.ParseClient(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(ccfg.Proxies) != 1 || ccfg.Proxies[0].RemotePort != 9443 {
		t.Errorf("merge port edit proxies = %+v", ccfg.Proxies)
	}
	if !strings.Contains(string(raw), "[log]") {
		t.Errorf("merge port edit dropped [log]:\n%s", raw)
	}
}

func TestServerEditExposesAllTransportFields(t *testing.T) {
	e := newTestEnv(t)
	if rec := e.authorized(http.MethodPost, "/api/servers",
		`{"bindPort":7018,"bindAddr":"0.0.0.0","protocol":"quic","token":"ServerToken1234567890"}`); rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}

	// Detail must return the exact bind address (0.0.0.0 must never become ::)
	// and every transport field the edit modal exposes.
	rec := e.authorized(http.MethodGet, "/api/servers/server-7018", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get = %d: %s", rec.Code, rec.Body.String())
	}
	cfg, _ := jsonMap(t, rec)["config"].(map[string]any)
	if cfg == nil {
		t.Fatalf("no config in detail: %s", rec.Body.String())
	}
	if cfg["bindAddr"] != "0.0.0.0" {
		t.Errorf("bindAddr = %v, want 0.0.0.0", cfg["bindAddr"])
	}
	for field, want := range map[string]float64{
		"tcpMuxKeepaliveInterval": 10,
		"heartbeatTimeout":        30,
		"tcpKeepalive":            30,
		"maxPoolCount":            65535,
		"quicKeepalivePeriod":     10,
		"quicMaxIdleTimeout":      30,
		"quicMaxIncomingStreams":  100000,
	} {
		if cfg[field] != want {
			t.Errorf("%s = %v, want %v", field, cfg[field], want)
		}
	}

	e.runner.active["frps@server-7018"] = "active"
	e.runner.resetCalls()
	rec = e.authorized(http.MethodPut, "/api/servers/server-7018", `{
		"bindAddr":"10.100.111.2","bindPort":7019,"protocol":"quic",
		"tcpMux":true,"tcpMuxKeepaliveInterval":15,
		"heartbeatTimeout":90,"tcpKeepalive":120,"maxPoolCount":2048,
		"quicKeepalivePeriod":12,"quicMaxIdleTimeout":45,"quicMaxIncomingStreams":5000,
		"restart":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("update = %d: %s", rec.Code, rec.Body.String())
	}
	raw, _ := os.ReadFile(filepath.Join(e.srv.paths.ServerDir, "server-7018.toml"))
	for _, want := range []string{
		`bindAddr = "10.100.111.2"`,
		"bindPort = 7019",
		"quicBindPort = 7019",
		"transport.tcpMux = true",
		"transport.tcpMuxKeepaliveInterval = 15",
		"transport.heartbeatTimeout = 90",
		"transport.tcpKeepalive = 120",
		"transport.maxPoolCount = 2048",
		"transport.quic.keepalivePeriod = 12",
		"transport.quic.maxIdleTimeout = 45",
		"transport.quic.maxIncomingStreams = 5000",
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("updated config missing %q:\n%s", want, raw)
		}
	}
	if !e.runner.called("systemctl:restart frps@server-7018") {
		t.Error("restart-after-save was requested but systemctl restart was not called")
	}

	// restart:false writes the file without touching the running unit.
	e.runner.resetCalls()
	rec = e.authorized(http.MethodPut, "/api/servers/server-7018", `{"heartbeatTimeout":60,"restart":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("update without restart = %d: %s", rec.Code, rec.Body.String())
	}
	if e.runner.called("systemctl:restart frps@server-7018") {
		t.Error("restart:false still restarted frps")
	}
}

func TestClientEditExposesAllTransportFields(t *testing.T) {
	e := newTestEnv(t)
	if rec := e.authorized(http.MethodPost, "/api/servers", `{"bindPort":7000}`); rec.Code != http.StatusCreated {
		t.Fatalf("server create = %d", rec.Code)
	}
	if rec := e.authorized(http.MethodPost, "/api/clients",
		`{"serverAddr":"10.100.111.2","serverPort":7000,"ports":"8989","proto":"tcp"}`); rec.Code != http.StatusCreated {
		t.Fatalf("client create = %d: %s", rec.Code, rec.Body.String())
	}
	e.runner.active["frpc@client-7000"] = "active"
	e.runner.resetCalls()

	rec := e.authorized(http.MethodPut, "/api/clients/client-7000", `{
		"serverAddr":"10.100.111.2","serverPort":7000,"protocol":"tcp",
		"tcpMux":false,"tcpMuxKeepaliveInterval":15,
		"dialServerTimeout":7,"dialServerKeepalive":45,"poolCount":50,
		"heartbeatInterval":12,"heartbeatTimeout":40,"loginFailExit":true,
		"useTls":false,"useEncryption":false,"useCompression":false,
		"ports":"8989,8443","proto":"both","localIp":"127.0.0.1","restart":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("update = %d: %s", rec.Code, rec.Body.String())
	}
	raw, _ := os.ReadFile(filepath.Join(e.srv.paths.ClientDir, "client-7000.toml"))
	cfg, err := frpconf.ParseClient(raw)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LoginFailExit != true {
		t.Error("loginFailExit not saved")
	}
	if cfg.Transport.TCPMuxKeepaliveInterval != 15 ||
		cfg.Transport.DialServerTimeout != 7 ||
		cfg.Transport.DialServerKeepalive != 45 ||
		cfg.Transport.PoolCount != 50 ||
		cfg.Transport.HeartbeatInterval != 12 ||
		cfg.Transport.HeartbeatTimeout != 40 {
		t.Errorf("transport fields not saved: %+v", cfg.Transport)
	}
	if cfg.Transport.TLS.Enable {
		t.Error("TLS should be off after raw-speed edit")
	}
	if len(cfg.Proxies) != 4 { // 2 ports × tcp+udp
		t.Fatalf("proxies = %d, want 4", len(cfg.Proxies))
	}
	for _, p := range cfg.Proxies {
		if p.Transport.UseEncryption || p.Transport.UseCompression {
			t.Errorf("proxy %s kept encryption/compression", p.Name)
		}
	}
	if !e.runner.called("systemctl:restart frpc@client-7000") {
		t.Error("restart-after-save was requested but systemctl restart was not called")
	}
}

func TestServicesListAndAction(t *testing.T) {
	e := newTestEnv(t)
	if rec := e.authorized(http.MethodPost, "/api/servers", `{"bindPort":7000}`); rec.Code != http.StatusCreated {
		t.Fatalf("server create = %d", rec.Code)
	}

	rec := e.authorized(http.MethodGet, "/api/services", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("services list = %d", rec.Code)
	}
	var list struct {
		Services []map[string]any `json:"services"`
	}
	json.Unmarshal(rec.Body.Bytes(), &list)
	found := map[string]bool{}
	for _, s := range list.Services {
		found[s["unit"].(string)] = true
	}
	for _, want := range []string{"frps@server-7000", "frp-panel", "tunnel-turbo", "frp-watchdog"} {
		if !found[want] {
			t.Errorf("services list missing %s (have %v)", want, found)
		}
	}

	// Valid action.
	rec = e.authorized(http.MethodPost, "/api/services/frps@server-7000/action", `{"action":"restart"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("restart = %d: %s", rec.Code, rec.Body.String())
	}
	if !e.runner.called("systemctl:restart frps@server-7000") {
		t.Error("restart not recorded")
	}

	// Invalid action / unit.
	if rec := e.authorized(http.MethodPost, "/api/services/frps@server-7000/action", `{"action":"reboot"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("bad action = %d", rec.Code)
	}
	if rec := e.authorized(http.MethodPost, "/api/services/evil@x/action", `{"action":"start"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("unwhitelisted unit = %d", rec.Code)
	}
	if rec := e.authorized(http.MethodPost, "/api/services/frps@;reboot/action", `{"action":"start"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("injection unit = %d", rec.Code)
	}

	// Template instance without config → 404.
	if rec := e.authorized(http.MethodPost, "/api/services/frps@ghost/action", `{"action":"start"}`); rec.Code != http.StatusNotFound {
		t.Errorf("ghost instance = %d, want 404", rec.Code)
	}
}

func TestBackupTimestampMatchesCLIFormat(t *testing.T) {
	now := time.Date(2026, 11, 20, 14, 30, 5, 0, time.UTC)
	got := backupTimestamp(now)
	// The CLI uses `date +%Y%m%d-%H%M%S` in server local time; the panel
	// stamps in UTC — same shape, and unambiguous across hosts.
	if got != "20261120-143005" {
		t.Errorf("backupTimestamp = %q", got)
	}
	if !strings.Contains(got, "-") || len(got) != 15 {
		t.Errorf("format shape wrong: %q", got)
	}
}

// frpVerifyErr builds the sentinel error the fake runner returns.
func frpVerifyErr() error { return &verifyErrStub{} }

type verifyErrStub struct{}

func (*verifyErrStub) Error() string { return "frps: exit status 1" }
