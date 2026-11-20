package api

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/frp-suite/panel/internal/backup"
)

func seedBackupState(t *testing.T, e *testEnv) {
	t.Helper()
	for _, dir := range []string{e.srv.paths.ServerDir, e.srv.paths.ClientDir, e.srv.paths.GREDir,
		e.srv.paths.EtcPanelDir, e.srv.paths.SysctlDir, e.srv.paths.UnitDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFileT(t, e.srv.paths.ServerDir, "server-7000.toml",
		"auth.token = \"TOKEN1234567890TOKEN1234567890\"\nbindPort = 7000\n")
	writeFileT(t, e.srv.paths.ClientDir, "c1.toml",
		"auth.token = \"TOKEN1234567890TOKEN1234567890\"\nserverAddr = \"10.0.0.1\"\nserverPort = 7000\n")
	writeFileT(t, e.srv.paths.GREDir, "gt11.env", "LOCAL_PUBLIC_IP=1.2.3.4\n")
	writeFileT(t, e.srv.paths.UnitDir, "frps@.service", "[Unit]\nDescription=x\n")
	writeFileT(t, e.srv.paths.EtcPanelDir, "panel.toml", "[auth]\nadmin_hash = \"$2a$10$xyz\"\n")
	writeFileT(t, e.srv.paths.SysctlDir, "99-tunnel-turbo.conf", "net.core.default_qdisc = fq\n")
}

func writeFileT(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// multipartBody builds an upload with the zip plus form fields.
func multipartBody(t *testing.T, fields map[string]string, zipBytes []byte) (string, string) {
	t.Helper()
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	fw, err := w.CreateFormFile("file", "backup.zip")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(zipBytes); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String(), w.FormDataContentType()
}

// authorizedMultipart sends a multipart POST with session + origin headers.
func (e *testEnv) authorizedMultipart(t *testing.T, path string, fields map[string]string, zipBytes []byte) *httptest.ResponseRecorder {
	t.Helper()
	cookie, code := e.login("admin", e.password)
	if code != http.StatusOK {
		t.Fatalf("login = %d", code)
	}
	body, contentType := multipartBody(t, fields, zipBytes)
	return e.do(http.MethodPost, path, body, map[string]string{
		"Cookie":          "frp_session=" + cookie,
		"Origin":          "http://panel.local",
		"Content-Type":    contentType,
		"X-Requested-With": "XMLHttpRequest",
	})
}

func zipEntries(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/zip") {
		t.Fatalf("content type = %q", ct)
	}
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("response is not a zip: %v", err)
	}
	out := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		out[f.Name] = string(b)
	}
	return out
}

func TestBackupExportEndpointRedacts(t *testing.T) {
	e := newTestEnv(t)
	seedBackupState(t, e)

	rec := e.authorized(http.MethodGet, "/api/backup/export", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d: %s", rec.Code, rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, `filename="frp-suite-backup-`) {
		t.Errorf("content disposition = %q", cd)
	}
	entries := zipEntries(t, rec)
	srv := entries["root/frp/server/server-7000.toml"]
	if strings.Contains(srv, "TOKEN1234567890TOKEN1234567890") {
		t.Fatalf("token leaked:\n%s", srv)
	}
	if !strings.Contains(srv, backup.Redacted) {
		t.Fatalf("token not redacted:\n%s", srv)
	}
	if _, ok := entries["etc/frp-panel/panel.toml"]; ok {
		t.Fatal("panel.toml exported without the secrets toggle")
	}
	var m backup.Manifest
	if err := json.Unmarshal([]byte(entries[backup.ManifestName]), &m); err != nil {
		t.Fatalf("manifest invalid: %v", err)
	}
	if !m.Redacted || m.SecretsIncluded {
		t.Fatalf("manifest flags = %+v", m)
	}
}

func TestBackupExportEndpointWithSecrets(t *testing.T) {
	e := newTestEnv(t)
	seedBackupState(t, e)

	rec := e.authorized(http.MethodGet, "/api/backup/export?secrets=1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d", rec.Code)
	}
	entries := zipEntries(t, rec)
	srv := entries["root/frp/server/server-7000.toml"]
	if !strings.Contains(srv, "TOKEN1234567890TOKEN1234567890") {
		t.Fatal("secrets export redacted the token anyway")
	}
	if entries["etc/frp-panel/panel.toml"] == "" {
		t.Fatal("panel.toml missing from secrets export")
	}
}

func TestBackupImportEndpointRoundTrip(t *testing.T) {
	e := newTestEnv(t)
	seedBackupState(t, e)

	// Export the seeded state.
	rec := e.authorized(http.MethodGet, "/api/backup/export", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d", rec.Code)
	}
	zipBytes := rec.Body.Bytes()

	// Diverge the host: clobber the client config, add a stray instance.
	writeFileT(t, e.srv.paths.ClientDir, "c1.toml", "auth.token = \"CHANGED\"\nserverAddr = \"9.9.9.9\"\nserverPort = 7000\n")
	writeFileT(t, e.srv.paths.ClientDir, "c2.toml", "serverAddr = \"8.8.8.8\"\nserverPort = 7001\n")
	e.runner.active["frps@server-7000"] = "active" // restart path applies

	rec = e.authorizedMultipart(t, "/api/backup/import", map[string]string{"restart": "1"}, zipBytes)
	if rec.Code != http.StatusOK {
		t.Fatalf("import = %d: %s", rec.Code, rec.Body.String())
	}
	resp := jsonMap(t, rec)
	summary, _ := resp["summary"].(map[string]any)
	if summary == nil {
		t.Fatalf("no summary: %v", resp)
	}

	// The redacted token was regenerated (fresh 32-char value, not the
	// CHANGED one) and frpc@c1's pre-import state was .bak'd.
	raw, err := os.ReadFile(filepath.Join(e.srv.paths.ClientDir, "c1.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), backup.Redacted) || strings.Contains(string(raw), "CHANGED") {
		t.Fatalf("token not regenerated:\n%s", raw)
	}
	if !strings.Contains(string(raw), "auth.token") {
		t.Fatalf("token line lost:\n%s", raw)
	}
	bak, err := os.ReadFile(filepath.Join(e.srv.paths.ClientDir, "c1.toml.bak-"+backupTimestamp(e.clock.now)))
	if err != nil || !strings.Contains(string(bak), "CHANGED") {
		t.Fatalf("pre-import client state not .bak'd: %v", err)
	}

	// Instances outside the archive untouched.
	if b, err := os.ReadFile(filepath.Join(e.srv.paths.ClientDir, "c2.toml")); err != nil ||
		!strings.Contains(string(b), "8.8.8.8") {
		t.Fatalf("stray instance modified: %v", err)
	}

	// systemctl side effects: unit files restored → daemon-reload; the
	// active instance restarted.
	if !e.runner.called("systemctl:daemon-reload") {
		t.Error("daemon-reload missing after unit restore")
	}
	if !e.runner.called("systemctl:restart frps@server-7000") {
		t.Error("active affected instance not restarted")
	}
	regen, _ := summary["regenerated"].([]any)
	if len(regen) != 2 {
		t.Errorf("regenerated = %v, want server+client", regen)
	}
	notes, _ := resp["notes"].([]any)
	if len(notes) == 0 {
		t.Error("notes missing from response")
	}
}

func TestBackupImportCategoryFilter(t *testing.T) {
	e := newTestEnv(t)
	seedBackupState(t, e)

	rec := e.authorized(http.MethodGet, "/api/backup/export?secrets=1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d", rec.Code)
	}
	zipBytes := rec.Body.Bytes()

	// Swap the whole Paths onto a fresh host so nothing pre-exists.
	fresh := t.TempDir()
	e.srv.paths.ServerDir = filepath.Join(fresh, "server")
	e.srv.paths.ClientDir = filepath.Join(fresh, "client")
	e.srv.paths.GREDir = filepath.Join(fresh, "gre")
	e.srv.paths.PanelCfg = filepath.Join(fresh, "etc", "frp-panel", "panel.toml")
	e.srv.paths.EtcPanelDir = filepath.Join(fresh, "etc", "frp-panel")
	e.srv.paths.SysctlDir = filepath.Join(fresh, "etc", "sysctl.d")
	e.srv.paths.ModulesDir = filepath.Join(fresh, "etc", "modules-load.d")
	e.srv.paths.UnitDir = filepath.Join(fresh, "etc", "systemd", "system")

	rec = e.authorizedMultipart(t, "/api/backup/import",
		map[string]string{"categories": "frp", "restart": "0"}, zipBytes)
	if rec.Code != http.StatusOK {
		t.Fatalf("import = %d: %s", rec.Code, rec.Body.String())
	}
	resp := jsonMap(t, rec)
	summary, _ := resp["summary"].(map[string]any)
	restored, _ := summary["restored"].(map[string]any)
	if len(restored) == 0 {
		t.Fatalf("nothing restored: %v", summary)
	}
	for name := range restored {
		if cat := backup.CategoryOf(name); cat != backup.CatFRP {
			t.Errorf("category filter leaked %q (%s)", name, cat)
		}
	}
	if _, err := os.Stat(filepath.Join(e.srv.paths.ServerDir, "server-7000.toml")); err != nil {
		t.Fatalf("frp config not restored: %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.srv.paths.UnitDir, "frps@.service")); err == nil {
		t.Error("systemd category restored despite filter")
	}
}

func TestBackupImportZipSlipRejected(t *testing.T) {
	e := newTestEnv(t)
	seedBackupState(t, e)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range []string{"../evil.txt", "root/frp/server/../../../evil.toml", `C:\evil`} {
		fw, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		fw.Write([]byte("pwned"))
	}
	zw.Close()

	rec := e.authorizedMultipart(t, "/api/backup/import", nil, buf.Bytes())
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("zip-slip import = %d (%s), want 422", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(e.root, "evil.txt")); err == nil {
		t.Fatal("file escaped the staging root")
	}
}

func TestBackupImportBadUploads(t *testing.T) {
	e := newTestEnv(t)

	// Missing file field.
	rec := e.authorizedMultipart(t, "/api/backup/import", nil, []byte("not a zip"))
	if rec.Code == http.StatusOK {
		// not a zip → 400 either way; assert not restored
		t.Fatalf("garbage accepted: %d", rec.Code)
	}
	// Unknown category.
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	fw, _ := zw.Create(backup.ManifestName)
	fw.Write([]byte(`{"format":"frp-suite-backup","version":1}`))
	zw.Close()
	rec = e.authorizedMultipart(t, "/api/backup/import",
		map[string]string{"categories": "everything"}, zipBuf.Bytes())
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown category = %d, want 400", rec.Code)
	}
}

func TestBackupExportRequiresAuth(t *testing.T) {
	e := newTestEnv(t)
	rec := e.do(http.MethodGet, "/api/backup/export", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated export = %d, want 401", rec.Code)
	}
	rec = e.do(http.MethodPost, "/api/backup/import", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated import = %d, want 401", rec.Code)
	}
}
