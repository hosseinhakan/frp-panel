package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/frp-suite/panel/internal/turbo"
)

const turboStatusOut = "frp-turbo: qdisc=fq cc=bbr tcp_base_mss=1024 rmem_max=33554432 wmem_max=33554432 somaxconn=65535 ip_forward=1 dropin=installed\n"
const zramStatusOut = "/dev/zram0                              partition   2.0G   123M  100\n"

func TestTurboGetState(t *testing.T) {
	e := newTestEnv(t)
	e.runner.active["tunnel-turbo"] = "active"
	e.runner.execOut["frp-turbo status"] = turboStatusOut
	e.runner.execOut["frp-turbo zram-status"] = zramStatusOut

	// Drop-in present + zram env configured.
	if err := os.MkdirAll(e.srv.paths.SysctlDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.srv.paths.SysctlDir, "99-tunnel-turbo.conf"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(e.srv.paths.EtcPanelDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.srv.paths.EtcPanelDir, "zram.env"), []byte(turbo.RenderZramEnv(turbo.ZramEnv{SizeMB: 2048, Algo: "lz4"})), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := e.authorized(http.MethodGet, "/api/system/turbo", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d: %s", rec.Code, rec.Body.String())
	}
	resp := jsonMap(t, rec)
	if resp["dropin"] != "installed" {
		t.Errorf("dropin = %v", resp["dropin"])
	}
	sysctl, _ := resp["sysctl"].(map[string]any)
	if sysctl == nil || sysctl["cc"] != "bbr" || sysctl["qdisc"] != "fq" {
		t.Errorf("sysctl = %v", sysctl)
	}
	units, _ := resp["units"].(map[string]any)
	tt, _ := units["tunnel-turbo"].(map[string]any)
	if tt == nil || tt["active"] != "active" {
		t.Errorf("tunnel-turbo unit = %v", tt)
	}
	zr, _ := resp["zram"].(map[string]any)
	cfg, _ := zr["config"].(map[string]any)
	if cfg == nil || cfg["SizeMB"] == nil && cfg["size_mb"] == nil {
		t.Errorf("zram config = %v", zr["config"])
	}
	active, _ := zr["active"].(map[string]any)
	if active == nil || active["priority"] == nil {
		t.Errorf("zram active = %v", zr["active"])
	}
}

func TestTurboSystemUtilities(t *testing.T) {
	e := newTestEnv(t)
	e.runner.execOut["frp-turbo gc-status"] = "frp-turbo: gc-cron=active\n"
	rec := e.authorized(http.MethodGet, "/api/system/turbo", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d: %s", rec.Code, rec.Body.String())
	}
	gc, _ := jsonMap(t, rec)["gcCron"].(map[string]any)
	if gc == nil || gc["active"] != true {
		t.Errorf("gcCron = %v, want active", gc)
	}

	for _, tc := range []struct{ action, output string }{
		{"gc-cron", "frp-turbo: gc-cron=active"},
		{"volatile-logs", "frp-turbo: journald volatile"},
		{"clear-logs", "frp-turbo: system logs cleared"},
	} {
		e.runner.execOut["frp-turbo "+tc.action] = tc.output + "\n"
		rec := e.authorized(http.MethodPost, "/api/system/turbo", `{"action":"`+tc.action+`"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s = %d: %s", tc.action, rec.Code, rec.Body.String())
		}
		if !e.runner.called("exec:frp-turbo " + tc.action) {
			t.Errorf("%s did not call the helper", tc.action)
		}
		if out, _ := jsonMap(t, rec)["output"].(string); out != tc.output {
			t.Errorf("%s output = %q, want %q", tc.action, out, tc.output)
		}
	}
}

func TestTurboGetWithoutHelper(t *testing.T) {
	// Fresh host: no helper, no drop-in — the GET must still succeed.
	e := newTestEnv(t)
	rec := e.authorized(http.MethodGet, "/api/system/turbo", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d: %s", rec.Code, rec.Body.String())
	}
	resp := jsonMap(t, rec)
	if resp["dropin"] != "missing" {
		t.Errorf("dropin = %v", resp["dropin"])
	}
	if _, has := resp["sysctl"]; has {
		t.Error("sysctl section should be absent when the helper is missing")
	}
}

func TestTurboApply(t *testing.T) {
	e := newTestEnv(t)
	rec := e.authorized(http.MethodPost, "/api/system/turbo", `{"action":"apply"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("apply = %d: %s", rec.Code, rec.Body.String())
	}
	// The CLI flow: install assets → enable → restart tunnel-turbo.
	if !e.runner.called("systemctl:enable tunnel-turbo") {
		t.Error("enable tunnel-turbo missing")
	}
	if !e.runner.called("systemctl:restart tunnel-turbo") {
		t.Error("restart tunnel-turbo missing")
	}
	helper, err := os.ReadFile(filepath.Join(e.srv.paths.BinDir, "frp-turbo"))
	if err != nil {
		t.Fatalf("frp-turbo helper not installed: %v", err)
	}
	if !strings.Contains(string(helper), "99-tunnel-turbo.conf") {
		t.Error("installed helper is not the canonical frp-turbo")
	}
	for _, unit := range []string{"tunnel-turbo.service", "frp-zram.service"} {
		if _, err := os.Stat(filepath.Join(e.srv.paths.UnitDir, unit)); err != nil {
			t.Errorf("unit %s not installed: %v", unit, err)
		}
	}
	if !e.runner.called("systemctl:daemon-reload") {
		t.Error("daemon-reload missing after asset sync")
	}
}

func TestTurboRevertBestEffort(t *testing.T) {
	e := newTestEnv(t)
	// frp-turbo binary absent → revert still succeeds (CLI parity: || true).
	rec := e.authorized(http.MethodPost, "/api/system/turbo", `{"action":"revert"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("revert = %d: %s", rec.Code, rec.Body.String())
	}
	if !e.runner.called("systemctl:disable tunnel-turbo") {
		t.Error("disable tunnel-turbo missing")
	}
	resp := jsonMap(t, rec)
	if _, has := resp["unit_error"]; !has {
		t.Error("helper failure should surface as unit_error, not abort")
	}
}

func TestTurboZramOn(t *testing.T) {
	e := newTestEnv(t)
	rec := e.authorized(http.MethodPost, "/api/system/turbo", `{"action":"zram-on","size":4096,"algo":"zstd"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("zram-on = %d: %s", rec.Code, rec.Body.String())
	}
	// Env written byte-identically to the CLI's zram_on printf.
	raw, err := os.ReadFile(filepath.Join(e.srv.paths.EtcPanelDir, "zram.env"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "ZRAM_SIZE_MB=4096\nZRAM_ALGO=zstd\n" {
		t.Fatalf("zram.env drift:\n%q", raw)
	}
	if !e.runner.called("systemctl:enable frp-zram") {
		t.Error("enable frp-zram missing")
	}
	if !e.runner.called("systemctl:restart frp-zram") {
		t.Error("restart frp-zram missing")
	}
}

func TestTurboZramOnInvalid(t *testing.T) {
	e := newTestEnv(t)
	for _, body := range []string{
		`{"action":"zram-on","size":8}`,
		`{"action":"zram-on","algo":"brotli"}`,
	} {
		rec := e.authorized(http.MethodPost, "/api/system/turbo", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("POST %s = %d, want 400", body, rec.Code)
		}
	}
	// Invalid size must not have written the env.
	if _, err := os.Stat(filepath.Join(e.srv.paths.EtcPanelDir, "zram.env")); err == nil {
		t.Error("zram.env written despite invalid request")
	}
}

func TestTurboZramOff(t *testing.T) {
	e := newTestEnv(t)
	rec := e.authorized(http.MethodPost, "/api/system/turbo", `{"action":"zram-off"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("zram-off = %d: %s", rec.Code, rec.Body.String())
	}
	if !e.runner.called("systemctl:disable frp-zram") {
		t.Error("disable frp-zram missing")
	}
}

func TestTurboBadActionAndAuth(t *testing.T) {
	e := newTestEnv(t)
	rec := e.authorized(http.MethodPost, "/api/system/turbo", `{"action":"self-destruct"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad action = %d, want 400", rec.Code)
	}
	rec = e.do(http.MethodGet, "/api/system/turbo", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated GET = %d, want 401", rec.Code)
	}
}
