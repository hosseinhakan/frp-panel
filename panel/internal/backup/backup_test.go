package backup

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/frp-suite/panel/internal/svc"
)

var epoch = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

// buildEnv creates a populated fake host: two server tomls, a client, a GRE
// env, a unit, turbo files and a panel.toml.
func buildEnv(t *testing.T) (svc.Paths, string) {
	t.Helper()
	root := t.TempDir()
	paths := svc.Paths{
		Root:        root,
		ServerDir:   filepath.Join(root, "root", "frp", "server"),
		ClientDir:   filepath.Join(root, "root", "frp", "client"),
		GREDir:      filepath.Join(root, "root", "frp", "gre"),
		PanelCfg:    filepath.Join(root, "etc", "frp-panel", "panel.toml"),
		EtcPanelDir: filepath.Join(root, "etc", "frp-panel"),
		SysctlDir:   filepath.Join(root, "etc", "sysctl.d"),
		ModulesDir:  filepath.Join(root, "etc", "modules-load.d"),
		UnitDir:     filepath.Join(root, "etc", "systemd", "system"),
	}

	const tokenLine = "auth.token = \"SECRETTOKEN1234567890abcdefgh\"\n"
	write(t, paths.ServerDir, "server-7000.toml", tokenLine+
		"bindAddr = \"0.0.0.0\"\nbindPort = 7000\n\n[webServer]\naddr = \"127.0.0.1\"\nport = 7500\nuser = \"admin\"\npassword = \"websecretpw\"\n")
	write(t, paths.ServerDir, "server-7500.toml", tokenLine+"bindPort = 7500\n")
	write(t, paths.ClientDir, "c1.toml", tokenLine+"serverAddr = \"10.0.0.1\"\nserverPort = 7000\n")
	write(t, paths.GREDir, "gt11.env", "LOCAL_PUBLIC_IP=1.2.3.4\n")
	write(t, paths.UnitDir, "frps@.service", "[Unit]\nDescription=x\n")
	write(t, paths.SysctlDir, "99-tunnel-turbo.conf", "net.core.default_qdisc = fq\n")
	write(t, paths.ModulesDir, "bbr.conf", "tcp_bbr\n")
	write(t, paths.EtcPanelDir, "zram.env", "ZRAM_SIZE_MB=2048\nZRAM_ALGO=lz4\n")
	write(t, paths.EtcPanelDir, "panel.toml", "[auth]\nadmin_hash = \"$2a$10$secret\"\n")
	write(t, paths.ClientDir, "c1.toml.bak-20260101-000000", "stale backup droppings\n")
	return paths, root
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestExportRedactsByDefault(t *testing.T) {
	paths, _ := buildEnv(t)
	var buf bytes.Buffer
	sum, err := Export(&buf, paths, false, epoch)
	if err != nil {
		t.Fatal(err)
	}
	if sum.SecretsIncluded {
		t.Fatal("secrets flag leaked into summary")
	}
	if sum.Redacted != 3 {
		t.Fatalf("redacted %d files, want 3 (two servers + one client)", sum.Redacted)
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	var manifestRaw []byte
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		if f.Name == ManifestName {
			manifestRaw = b
			continue
		}
		found[f.Name] = string(b)
	}
	srv := found["root/frp/server/server-7000.toml"]
	if strings.Contains(srv, "SECRETTOKEN1234567890abcdefgh") || strings.Contains(srv, "websecretpw") {
		t.Fatalf("server toml secrets leaked:\n%s", srv)
	}
	if !strings.Contains(srv, "auth.token = "+quote(Redacted)) {
		t.Fatalf("token not redacted:\n%s", srv)
	}
	if !strings.Contains(srv, "password = "+quote(Redacted)) {
		t.Fatalf("webServer password not redacted (bare key under [webServer]):\n%s", srv)
	}
	if _, ok := found["etc/frp-panel/panel.toml"]; ok {
		t.Fatal("panel.toml must be excluded without the secrets toggle")
	}
	if _, ok := found["root/frp/client/c1.toml.bak-20260101-000000"]; ok {
		t.Fatal(".bak droppings must not be exported")
	}
	if found["etc/frp-panel/zram.env"] == "" {
		t.Fatal("zram.env should be exported (no secrets in it)")
	}

	var m Manifest
	if err := json.Unmarshal(manifestRaw, &m); err != nil {
		t.Fatal(err)
	}
	if m.Format != Format || m.Version != ManifestVersion || !m.Redacted {
		t.Fatalf("manifest = %+v", m)
	}
	if len(m.Files) != sum.Files {
		t.Fatalf("manifest files %d != summary %d", len(m.Files), sum.Files)
	}
}

func TestExportWithSecrets(t *testing.T) {
	paths, _ := buildEnv(t)
	var buf bytes.Buffer
	sum, err := Export(&buf, paths, true, epoch)
	if err != nil {
		t.Fatal(err)
	}
	if !sum.SecretsIncluded || sum.Redacted != 0 {
		t.Fatalf("summary = %+v", sum)
	}
	zr, _ := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	for _, f := range zr.File {
		if f.Name == "root/frp/server/server-7000.toml" {
			rc, _ := f.Open()
			b, _ := io.ReadAll(rc)
			rc.Close()
			if !strings.Contains(string(b), "SECRETTOKEN1234567890abcdefgh") {
				t.Fatal("secrets export must keep the real token")
			}
		}
		if f.Name == "etc/frp-panel/panel.toml" {
			return // present, as required
		}
	}
	t.Fatal("panel.toml missing from secrets export")
}

func TestImportRoundTripWithRegeneration(t *testing.T) {
	paths, root := buildEnv(t)

	// Export without secrets into memory.
	var buf bytes.Buffer
	if _, err := Export(&buf, paths, false, epoch); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}

	// Wipe the host state, then seed a conflicting current file for an
	// instance that is in the archive (plus one that is not).
	if err := os.RemoveAll(filepath.Join(root, "root")); err != nil {
		t.Fatal(err)
	}
	write(t, paths.ServerDir, "server-7000.toml", "auth.token = \"OTHER\"\nbindPort = 7000\n")
	write(t, paths.ServerDir, "server-9999.toml", "auth.token = \"OTHER\"\nbindPort = 9999\n")

	sum, err := Import(zr, paths, ImportOptions{RegenerateSecrets: true}, epoch)
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.Restored) == 0 {
		t.Fatal("nothing restored")
	}
	if len(sum.Regenerated) != 3 {
		t.Fatalf("regenerated = %v, want 3 tomls", sum.Regenerated)
	}
	restored, err := os.ReadFile(filepath.Join(paths.ServerDir, "server-7000.toml"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(restored)
	if strings.Contains(s, Redacted) {
		t.Fatalf("REDACTED placeholder survived import:\n%s", s)
	}
	if !strings.Contains(s, "auth.token = \"") || len(regexpFindToken(s)) != 32 {
		t.Fatalf("regenerated token not 32 chars:\n%s", s)
	}
	// The pre-existing conflicting file was backed up, not lost; the local
	// instance that was never in the archive is untouched.
	bak := filepath.Join(paths.ServerDir, "server-7000.toml.bak-"+backupTimestamp(epoch))
	if b, err := os.ReadFile(bak); err != nil || !strings.Contains(string(b), "OTHER") {
		t.Fatalf("existing file not .bak'd: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(paths.ServerDir, "server-9999.toml")); err != nil ||
		!strings.Contains(string(b), "bindPort = 9999") {
		t.Fatalf("local instance outside the archive was modified: %v", err)
	}
	// Affected units derived.
	units := strings.Join(sum.AffectedUnits, " ")
	if !strings.Contains(units, "frps@server-7000") || !strings.Contains(units, "frpc@c1") ||
		!strings.Contains(units, "gre-tunnel@gt11") {
		t.Fatalf("affected units = %v", sum.AffectedUnits)
	}
}

func TestImportSelectiveCategories(t *testing.T) {
	paths, _ := buildEnv(t)
	var buf bytes.Buffer
	if _, err := Export(&buf, paths, true, epoch); err != nil {
		t.Fatal(err)
	}
	zr, _ := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))

	// Fresh host.
	fresh := paths
	fresh.ServerDir = filepath.Join(t.TempDir(), "server")
	fresh.ClientDir = filepath.Join(t.TempDir(), "client")
	fresh.GREDir = filepath.Join(t.TempDir(), "gre")
	fresh.UnitDir = filepath.Join(t.TempDir(), "units")
	fresh.SysctlDir = filepath.Join(t.TempDir(), "sysctl")
	fresh.ModulesDir = filepath.Join(t.TempDir(), "modules")
	fresh.EtcPanelDir = filepath.Join(t.TempDir(), "frp-panel")
	fresh.PanelCfg = filepath.Join(fresh.EtcPanelDir, "panel.toml")

	sum, err := Import(zr, fresh, ImportOptions{Categories: []string{CatFRP}}, epoch)
	if err != nil {
		t.Fatal(err)
	}
	for name := range sum.Restored {
		if cat := CategoryOf(name); cat != CatFRP {
			t.Fatalf("category filter leaked %q (%s)", name, cat)
		}
	}
	if fileExists(filepath.Join(fresh.UnitDir, "frps@.service")) {
		t.Fatal("systemd category restored despite not being selected")
	}
	// Skipped entries are reported.
	joined := strings.Join(sum.Skipped, "\n")
	if !strings.Contains(joined, "category not selected") {
		t.Fatalf("skipped = %v", sum.Skipped)
	}
}

// ---- security guards -------------------------------------------------------------

func craftZip(t *testing.T, entries map[string]string, modes map[string]os.FileMode) *zip.Reader {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		hdr := &zip.FileHeader{Name: name, Method: zip.Store}
		if m, ok := modes[name]; ok {
			hdr.SetMode(m)
		}
		fw, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	return zr
}

func TestImportZipSlipRejected(t *testing.T) {
	paths, root := buildEnv(t)
	evil := "pwned after restore\n"
	attackNames := []string{
		"../evil.txt",
		"root/frp/server/../../../evil.toml",
		"/etc/frp-panel/panel.toml", // absolute
		"C:/evil.toml",
		`root\frp\server\evil.toml`,
		"root//frp/server/evil.toml",
		"root/frp/server/./evil.toml",
	}
	for _, name := range attackNames {
		zr := craftZip(t, map[string]string{name: evil}, nil)
		if _, err := Import(zr, paths, ImportOptions{}, epoch); err == nil {
			t.Fatalf("zip-slip entry %q accepted", name)
		}
		if _, err := os.Stat(filepath.Join(root, "evil.txt")); err == nil {
			t.Fatalf("entry %q escaped the staging root", name)
		}
		if _, err := os.Stat(filepath.Join(root, "evil.toml")); err == nil {
			t.Fatalf("entry %q escaped the staging root", name)
		}
	}
}

func TestImportSymlinkEntryRejected(t *testing.T) {
	paths, _ := buildEnv(t)
	zr := craftZip(t, map[string]string{"root/frp/server/evil.toml": "x"}, map[string]os.FileMode{
		"root/frp/server/evil.toml": os.ModeSymlink | 0o777,
	})
	if _, err := Import(zr, paths, ImportOptions{}, epoch); err == nil {
		t.Fatal("symlink entry accepted")
	}
}

func TestImportUnknownPathsSkipped(t *testing.T) {
	paths, _ := buildEnv(t)
	zr := craftZip(t, map[string]string{
		"root/evil.sh":              "rm -rf /",
		"etc/passwd":                "root:x:0:0",
		"etc/sysctl.d/99-other.conf": "x=1",
		"etc/frp-panel/evil.env":    "EVIL=1",
	}, nil)
	sum, err := Import(zr, paths, ImportOptions{}, epoch)
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.Restored) != 0 {
		t.Fatalf("unknown paths restored: %v", sum.Restored)
	}
	if len(sum.Skipped) != 4 {
		t.Fatalf("skipped = %v", sum.Skipped)
	}
}

func TestImportForeignUnitRejected(t *testing.T) {
	// A file that claims a suite location but is not a suite file is
	// treated as hostile, not skipped.
	paths, _ := buildEnv(t)
	zr := craftZip(t, map[string]string{
		"etc/systemd/system/sshd.service": "[Unit]\n",
		"root/frp/server/../../evil":     "x",
	}, nil)
	if _, err := Import(zr, paths, ImportOptions{}, epoch); err == nil {
		t.Fatal("foreign unit inside a suite path accepted")
	}
	if fileExists(filepath.Join(paths.UnitDir, "sshd.service")) {
		t.Fatal("foreign unit was written")
	}
}

func TestImportManifestChecks(t *testing.T) {
	paths, _ := buildEnv(t)
	zr := craftZip(t, map[string]string{
		ManifestName: `{"format":"someone-elses","version":1}`,
	}, nil)
	if _, err := Import(zr, paths, ImportOptions{}, epoch); err == nil {
		t.Fatal("foreign manifest accepted")
	}
	zr = craftZip(t, map[string]string{
		ManifestName: `{"format":"frp-suite-backup","version":99}`,
	}, nil)
	if _, err := Import(zr, paths, ImportOptions{}, epoch); err == nil {
		t.Fatal("future manifest version accepted")
	}
	// Missing manifest is tolerated (plain zip of the same layout).
	zr = craftZip(t, map[string]string{
		"root/frp/server/s.toml": "bindPort = 1\n",
	}, nil)
	sum, err := Import(zr, paths, ImportOptions{}, epoch)
	if err != nil {
		t.Fatalf("manifest-less import failed: %v", err)
	}
	if sum.Manifest != nil || len(sum.Restored) != 1 {
		t.Fatalf("summary = %+v", sum)
	}
}

func TestImportAtomicityOnPoisonTail(t *testing.T) {
	// A valid entry followed by a poisoned one must restore NOTHING.
	paths, _ := buildEnv(t)
	zr := craftZip(t, map[string]string{
		"root/frp/server/good.toml":  "bindPort = 1\n",
		"root/frp/server/bad.toml.":  "x", // dot-segment variant rejected late in iteration order
	}, nil)
	if _, err := Import(zr, paths, ImportOptions{}, epoch); err == nil {
		t.Fatal("poisoned archive accepted")
	}
	if fileExists(filepath.Join(paths.ServerDir, "good.toml")) {
		t.Fatal("stage-then-apply violated: good entry landed before the poison was seen")
	}
}

func TestImportPanelConfig(t *testing.T) {
	paths, _ := buildEnv(t)
	zr := craftZip(t, map[string]string{
		"etc/frp-panel/panel.toml": "[auth]\nadmin_hash = \"restored-hash\"\n",
	}, nil)
	sum, err := Import(zr, paths, ImportOptions{Categories: []string{CatPanel}}, epoch)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(paths.PanelCfg)
	if err != nil || !strings.Contains(string(b), "restored-hash") {
		t.Fatalf("panel.toml not restored: %v", err)
	}
	if !fileExists(paths.PanelCfg+".bak-"+backupTimestamp(epoch)) {
		t.Fatal("panel.toml not .bak'd")
	}
	if !sum.RestartPanelHint {
		t.Fatal("restart hint missing")
	}
}

func TestRedactTOMLSecretsStyles(t *testing.T) {
	// Dotted keys (advanced style) and table style both redacted.
	raw := "auth.token = \"abc\"\n[webServer]\npassword = \"pw\"\n[x]\npassword = \"keep\"\n"
	out, n := RedactTOMLSecrets(raw)
	if n != 2 {
		t.Fatalf("replaced %d lines, want 2:\n%s", n, out)
	}
	if !strings.Contains(out, "auth.token = "+quote(Redacted)) ||
		!strings.Contains(out, "password = "+quote(Redacted)) {
		t.Fatalf("bad redaction:\n%s", out)
	}
	if strings.Contains(out, quote("keep")) == false {
		t.Fatal("unrelated password line must be untouched")
	}
	if !strings.Contains(out, "[x]") {
		t.Fatal("structure mangled")
	}
	if _, n := RedactTOMLSecrets("bindPort = 1\n"); n != 0 {
		t.Fatal("secret-free file must be untouched")
	}
}

func TestSafeEntryName(t *testing.T) {
	bad := []string{
		"", "..", "a/../b", "a\\b", "/abs", "C:/x", "a//b", "a/./b",
		strings.Repeat("a/", 300) + "x", "a\x00b",
	}
	for _, name := range bad {
		if _, err := SafeEntryName(name); err == nil {
			t.Fatalf("SafeEntryName(%q) accepted", name)
		}
	}
	if _, err := SafeEntryName("root/frp/server/a-b_C.toml"); err != nil {
		t.Fatalf("valid name rejected: %v", err)
	}
}

// helpers

func quote(s string) string { return "\"" + s + "\"" }

func regexpFindToken(s string) string {
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "auth.token") {
			parts := strings.SplitN(t, "\"", 3)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return ""
}
