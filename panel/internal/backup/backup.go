// Package backup implements the suite's config export/import.
//
// Export writes a ZIP whose entry names mirror the CLI's tar.gz layout
// (root/frp/…, etc/systemd/system/…, etc/sysctl.d/…, etc/frp-panel/…)
// plus a manifest.json. Without the secrets toggle, FRP TOML auth tokens
// and webServer passwords are redacted to the literal REDACTED and
// panel.toml (bcrypt hash + JWT secret) is excluded entirely; import
// regenerates fresh values for redacted files.
//
// Import never trusts the archive: every entry name passes the zip-slip
// guard (no absolute paths, drive letters, backslashes or `..` segments),
// every file must map onto a whitelisted category path, symlink entries
// are rejected, and per-entry/total size caps stop zip bombs. Existing
// files are moved to <file>.bak-<UTC ts> before anything is overwritten —
// the same rule every other panel write follows.
package backup

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/frp-suite/panel/internal/frpconf"
	"github.com/frp-suite/panel/internal/svc"
)

// Format / limits.
const (
	Format          = "frp-suite-backup"
	ManifestVersion = 1
	ManifestName    = "manifest.json"
	// Redacted is the placeholder written over secrets in secret-free
	// exports; import replaces it with freshly generated values.
	Redacted = "REDACTED"

	MaxZipBytes   = 100 << 20 // total uncompressed cap
	MaxEntryBytes = 32 << 20  // single-entry cap
)

// SuiteUnits are the only systemd files a backup may carry or restore.
var SuiteUnits = []string{
	"frps@.service", "frpc@.service", "gre-tunnel@.service",
	"tunnel-turbo.service", "frp-zram.service", "frp-watchdog.service",
	"frp-panel.service",
}

// Categories selectable at import time.
const (
	CatFRP     = "frp"
	CatSystemd = "systemd"
	CatTurbo   = "turbo"
	CatPanel   = "panel"
)

// AllCategories is the full import selection.
var AllCategories = []string{CatFRP, CatSystemd, CatTurbo, CatPanel}

// Manifest describes the archive (entry #2 in the ZIP, read on import).
type Manifest struct {
	Format          string   `json:"format"`
	Version         int      `json:"version"`
	Created         string   `json:"created"` // RFC3339 UTC
	SecretsIncluded bool     `json:"secrets_included"`
	Redacted        bool     `json:"redacted"`
	Categories      []string `json:"categories"`
	Files           []string `json:"files"`
}

// ExportSummary reports what Export wrote.
type ExportSummary struct {
	Files           int               `json:"files"`
	Categories      map[string]int    `json:"categories"`
	SecretsIncluded bool              `json:"secrets_included"`
	Redacted        int               `json:"redacted_files"`
}

// ImportOptions controls an import.
type ImportOptions struct {
	// Categories to apply (empty = all found).
	Categories []string
	// RegenerateSecrets replaces REDACTED markers with fresh random
	// credentials while applying. The API layer defaults this to true —
	// restoring placeholder tokens verbatim would break instance auth.
	RegenerateSecrets bool
}

// ImportSummary reports what Import did. The API layer performs the
// systemctl actions (daemon-reload, restarts) from this data.
type ImportSummary struct {
	Manifest         *Manifest          `json:"manifest,omitempty"`
	Categories       []string           `json:"categories"`
	Restored         map[string]string `json:"restored"`            // entry → host path
	Skipped          []string           `json:"skipped,omitempty"`   // entries not selected / unknown
	Backups          []string           `json:"backups,omitempty"`   // .bak-<ts> copies taken
	Regenerated      []string           `json:"regenerated,omitempty"` // files that got fresh secrets
	AffectedUnits    []string           `json:"affected_units,omitempty"`
	DaemonReload     bool               `json:"daemon_reload"`       // systemd files were restored
	RestartPanelHint bool               `json:"restart_panel_hint,omitempty"`
}

// backupTimestamp matches the suite's .bak suffix format.
func backupTimestamp(now time.Time) string { return now.UTC().Format("20060102-150405") }

// ---- export -------------------------------------------------------------------

// Export writes the ZIP to w and returns a summary. includeSecrets is the
// redaction toggle: when false (the safe default), FRP TOML secrets are
// replaced with REDACTED and panel.toml is left out.
func Export(w io.Writer, paths svc.Paths, includeSecrets bool, now time.Time) (*ExportSummary, error) {
	type item struct {
		name string // zip entry name
		src  string // host source path
	}
	items := []item{}

	// frp configs (never include .bak-* droppings — the listers already
	// filter by suffix).
	if names, err := frpconf.ListConfigs(paths.ServerDir); err == nil {
		for _, n := range names {
			items = append(items, item{"root/frp/server/" + n + ".toml", filepath.Join(paths.ServerDir, n+".toml")})
		}
	} else {
		return nil, fmt.Errorf("scan %s: %w", paths.ServerDir, err)
	}
	if names, err := frpconf.ListConfigs(paths.ClientDir); err == nil {
		for _, n := range names {
			items = append(items, item{"root/frp/client/" + n + ".toml", filepath.Join(paths.ClientDir, n+".toml")})
		}
	} else {
		return nil, fmt.Errorf("scan %s: %w", paths.ClientDir, err)
	}
	if envs, err := listEnvFiles(paths.GREDir); err == nil {
		for _, n := range envs {
			items = append(items, item{"root/frp/gre/" + n + ".env", filepath.Join(paths.GREDir, n+".env")})
		}
	} else {
		return nil, fmt.Errorf("scan %s: %w", paths.GREDir, err)
	}
	// systemd units (whitelist).
	for _, u := range SuiteUnits {
		src := filepath.Join(paths.UnitDir, u)
		if fileExists(src) {
			items = append(items, item{"etc/systemd/system/" + u, src})
		}
	}
	// turbo/tuning files.
	for _, tf := range []struct{ name, src string }{
		{"etc/sysctl.d/99-tunnel-turbo.conf", filepath.Join(paths.SysctlDir, "99-tunnel-turbo.conf")},
		{"etc/sysctl.d/99-frp-zram.conf", filepath.Join(paths.SysctlDir, "99-frp-zram.conf")},
		{"etc/modules-load.d/bbr.conf", filepath.Join(paths.ModulesDir, "bbr.conf")},
		{"etc/frp-panel/zram.env", filepath.Join(paths.EtcPanelDir, "zram.env")},
		{"etc/frp-panel/watchdog.env", filepath.Join(paths.EtcPanelDir, "watchdog.env")},
	} {
		if fileExists(tf.src) {
			items = append(items, item{tf.name, tf.src})
		}
	}
	// panel config — only with the secrets toggle.
	if includeSecrets && fileExists(paths.PanelCfg) {
		items = append(items, item{"etc/frp-panel/panel.toml", paths.PanelCfg})
	}

	zw := zip.NewWriter(w)
	summary := &ExportSummary{
		Categories:      map[string]int{},
		SecretsIncluded: includeSecrets,
	}
	cats := map[string]bool{}
	for _, it := range items {
		raw, err := os.ReadFile(it.src)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", it.src, err)
		}
		name := it.name
		if !includeSecrets && strings.HasSuffix(name, ".toml") {
			red, n := RedactTOMLSecrets(string(raw))
			if n > 0 {
				raw = []byte(red)
				summary.Redacted++
			}
		}
		if err := writeZipEntry(zw, name, raw, now); err != nil {
			return nil, err
		}
		summary.Files++
		cat := CategoryOf(name)
		summary.Categories[cat]++
		cats[cat] = true
	}

	manifest := &Manifest{
		Format:          Format,
		Version:         ManifestVersion,
		Created:         now.UTC().Format(time.RFC3339),
		SecretsIncluded: includeSecrets,
		Redacted:        !includeSecrets && summary.Redacted > 0,
		Categories:      sortedKeys(cats),
		Files:           make([]string, 0, len(items)),
	}
	for _, it := range items {
		manifest.Files = append(manifest.Files, it.name)
	}
	mraw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeZipEntry(zw, ManifestName, append(mraw, '\n'), now); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return summary, nil
}

func writeZipEntry(zw *zip.Writer, name string, content []byte, now time.Time) error {
	hdr := &zip.FileHeader{
		Name:     name,
		Method:   zip.Deflate,
		Modified: now,
	}
	hdr.SetMode(0o600)
	fw, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}
	_, err = fw.Write(content)
	return err
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

func listEnvFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".env") {
			continue
		}
		names = append(names, strings.TrimSuffix(e.Name(), ".env"))
	}
	return names, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---- redaction ------------------------------------------------------------------

// RedactTOMLSecrets replaces auth.token and webServer.password values with
// the REDACTED placeholder, working line-by-line so any config style
// (managed or advanced) survives. Understands both bare keys inside their
// TOML table ([auth] → token = …) and dotted keys. Returns the number of
// replaced lines.
func RedactTOMLSecrets(raw string) (string, int) {
	out, n, _ := replaceSecretLines(raw, func(key string) (string, error) {
		if key == "auth.token" || key == "webServer.password" {
			return Redacted, nil
		}
		return "", nil
	})
	return out, n
}

// regenerateTOMLSecrets swaps REDACTED placeholders for fresh random
// credentials (token: 32 chars, webServer password: 24 chars).
func regenerateTOMLSecrets(raw string) (string, int, error) {
	return replaceSecretLines(raw, func(key string) (string, error) {
		switch key {
		case "auth.token":
			return frpconf.RandomToken()
		case "webServer.password":
			return frpconf.RandomPassword()
		}
		return "", nil
	})
}

// replaceSecretLines rewrites value-bearing secret lines. The callback
// returns the replacement value ("" means "not a secret key").
func replaceSecretLines(raw string, value func(key string) (string, error)) (string, int, error) {
	lines := strings.Split(raw, "\n")
	section := ""
	n := 0
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			continue
		}
		key, _, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		full := key
		if !strings.Contains(key, ".") && section != "" {
			full = section + "." + key
		}
		repl, err := value(full)
		if err != nil {
			return "", 0, fmt.Errorf("key %s: %w", full, err)
		}
		if repl == "" {
			continue
		}
		// Preserve indentation of the original line.
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		lines[i] = fmt.Sprintf("%s%s = %q", indent, key, repl)
		n++
	}
	if n == 0 {
		return raw, 0, nil
	}
	return strings.Join(lines, "\n"), n, nil
}

// HasRedactedSecrets reports whether a TOML still contains placeholders.
func HasRedactedSecrets(raw string) bool {
	for _, line := range strings.Split(raw, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if strings.Contains(t, fmt.Sprintf("%q", Redacted)) {
			return true
		}
	}
	return false
}

// ---- entry validation ------------------------------------------------------------

// safeNamePattern constrains each slash-separated segment.
var safeNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,128}$`)

// SafeEntryName validates a zip entry name against the zip-slip attack
// family: no absolute paths, Windows drive letters, backslashes, NULs,
// empty/dotdot segments. Returns the validated slash-separated name.
func SafeEntryName(name string) (string, error) {
	if name == "" {
		return "", errors.New("empty entry name")
	}
	if len(name) > 512 {
		return "", fmt.Errorf("entry name too long (%d bytes)", len(name))
	}
	if strings.ContainsAny(name, "\\\x00") {
		return "", fmt.Errorf("entry %q: backslash or NUL in name", name)
	}
	if strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("entry %q: absolute paths are not allowed", name)
	}
	if len(name) >= 2 && name[1] == ':' {
		return "", fmt.Errorf("entry %q: drive-letter paths are not allowed", name)
	}
	segs := strings.Split(name, "/")
	for _, s := range segs {
		if s == "" {
			return "", fmt.Errorf("entry %q: empty path segment", name)
		}
		if s == "." || s == ".." {
			return "", fmt.Errorf("entry %q: dot segments are not allowed", name)
		}
		if !safeNamePattern.MatchString(s) {
			return "", fmt.Errorf("entry %q: unsafe characters in segment %q", name, s)
		}
	}
	return name, nil
}

// CategoryOf maps a zip entry name onto a backup category ("" when the
// entry is unknown or the manifest).
func CategoryOf(name string) string {
	switch {
	case name == ManifestName:
		return ""
	case strings.HasPrefix(name, "root/frp/server/"),
		strings.HasPrefix(name, "root/frp/client/"),
		strings.HasPrefix(name, "root/frp/gre/"):
		return CatFRP
	case strings.HasPrefix(name, "etc/systemd/system/"):
		return CatSystemd
	case name == "etc/sysctl.d/99-tunnel-turbo.conf",
		name == "etc/sysctl.d/99-frp-zram.conf",
		name == "etc/modules-load.d/bbr.conf",
		name == "etc/frp-panel/zram.env",
		name == "etc/frp-panel/watchdog.env":
		return CatTurbo
	case name == "etc/frp-panel/panel.toml":
		return CatPanel
	}
	return ""
}

// ---- import ----------------------------------------------------------------------

// Import applies a backup ZIP. Nothing is written until every entry has
// been validated and staged in memory, so a poisoned archive never leaves
// a half-restored system.
func Import(zr *zip.Reader, paths svc.Paths, opts ImportOptions, now time.Time) (*ImportSummary, error) {
	// 1) Validate + stage everything first.
	selected := map[string]bool{}
	for _, c := range opts.Categories {
		selected[c] = true
	}
	if len(selected) == 0 {
		for _, c := range AllCategories {
			selected[c] = true
		}
	}

	summary := &ImportSummary{Restored: map[string]string{}, Categories: []string{}}
	type staged struct {
		name    string
		content []byte
		cat     string
	}
	stagedFiles := []staged{}
	cats := map[string]bool{}
	var total int64

	for _, f := range zr.File {
		name, err := SafeEntryName(f.Name)
		if err != nil {
			return nil, err
		}
		if f.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("entry %q: symlink entries are not allowed", name)
		}
		if f.UncompressedSize64 > MaxEntryBytes {
			return nil, fmt.Errorf("entry %q: too large (%d bytes)", name, f.UncompressedSize64)
		}

		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("entry %q: %w", name, err)
		}
		content, err := io.ReadAll(io.LimitReader(rc, MaxEntryBytes+1))
		closeErr := rc.Close()
		if err != nil {
			return nil, fmt.Errorf("entry %q: %w", name, err)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("entry %q: %w", name, closeErr)
		}
		if len(content) > MaxEntryBytes {
			return nil, fmt.Errorf("entry %q: exceeds the %d MB per-file limit", name, MaxEntryBytes>>20)
		}
		total += int64(len(content))
		if total > MaxZipBytes {
			return nil, fmt.Errorf("archive exceeds the %d MB limit", MaxZipBytes>>20)
		}

		if name == ManifestName {
			summary.Manifest = &Manifest{}
			if err := json.Unmarshal(content, summary.Manifest); err != nil {
				return nil, fmt.Errorf("manifest: %w", err)
			}
			if summary.Manifest.Format != "" && summary.Manifest.Format != Format {
				return nil, fmt.Errorf("manifest: format %q is not %q", summary.Manifest.Format, Format)
			}
			if summary.Manifest.Version > ManifestVersion {
				return nil, fmt.Errorf("manifest: format version %d is newer than this panel supports (%d)",
					summary.Manifest.Version, ManifestVersion)
			}
			continue
		}

		cat := CategoryOf(name)
		if cat == "" {
			summary.Skipped = append(summary.Skipped, name+" (unknown path)")
			continue
		}
		if !selected[cat] {
			summary.Skipped = append(summary.Skipped, name+" (category not selected)")
			continue
		}
		if err := validateEntryContent(name, content); err != nil {
			return nil, err
		}
		stagedFiles = append(stagedFiles, staged{name: name, content: content, cat: cat})
		cats[cat] = true
	}
	summary.Categories = sortedKeys(cats)

	// 2) Apply every staged file.
	ts := backupTimestamp(now)
	for _, st := range stagedFiles {
		content := st.content
		if opts.RegenerateSecrets && strings.HasSuffix(st.name, ".toml") && HasRedactedSecrets(string(content)) {
			regen, n, err := regenerateTOMLSecrets(string(content))
			if err != nil {
				return nil, fmt.Errorf("entry %q: secret regeneration failed: %w", st.name, err)
			}
			if n > 0 {
				content = []byte(regen)
				summary.Regenerated = append(summary.Regenerated, st.name)
			}
		}

		target, ok := targetPath(paths, st.name)
		if !ok {
			// CategoryOf accepted it but the mapper refused — defensive.
			return nil, fmt.Errorf("entry %q: no restore target", st.name)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return nil, fmt.Errorf("restore %s: %w", target, err)
		}
		if old, err := os.ReadFile(target); err == nil {
			bak := target + ".bak-" + ts
			if err := os.WriteFile(bak, old, 0o600); err != nil {
				return nil, fmt.Errorf("backup %s: %w", bak, err)
			}
			summary.Backups = append(summary.Backups, bak)
		}
		mode := os.FileMode(0o644)
		if strings.HasSuffix(st.name, ".toml") || strings.HasSuffix(st.name, ".env") {
			mode = 0o600
		}
		if err := os.WriteFile(target, content, mode); err != nil {
			return nil, fmt.Errorf("restore %s: %w", target, err)
		}
		summary.Restored[st.name] = target

		if st.name == "etc/frp-panel/panel.toml" || st.name == "etc/systemd/system/frp-panel.service" {
			summary.RestartPanelHint = true
		}
		if unit, ok := affectedUnit(st.name); ok {
			summary.AffectedUnits = append(summary.AffectedUnits, unit)
			if strings.HasSuffix(st.name, ".service") {
				summary.DaemonReload = true
			}
		}
	}

	return summary, nil
}

// validateEntryContent runs per-category name rules after the generic
// zip-slip guard: even a perfectly-named path must be a file this suite
// would itself have written.
func validateEntryContent(name string, content []byte) error {
	switch {
	case strings.HasPrefix(name, "root/frp/server/"), strings.HasPrefix(name, "root/frp/client/"):
		base := strings.TrimPrefix(strings.TrimPrefix(name, "root/frp/"), "server/")
		base = strings.TrimPrefix(base, "client/")
		if !strings.HasSuffix(base, ".toml") || !instanceName(base[:len(base)-5]) {
			return fmt.Errorf("entry %q: not a valid instance config name", name)
		}
	case strings.HasPrefix(name, "root/frp/gre/"):
		base := strings.TrimPrefix(name, "root/frp/gre/")
		if !strings.HasSuffix(base, ".env") || !instanceName(base[:len(base)-4]) {
			return fmt.Errorf("entry %q: not a valid tunnel env name", name)
		}
	case strings.HasPrefix(name, "etc/systemd/system/"):
		unit := strings.TrimPrefix(name, "etc/systemd/system/")
		known := false
		for _, u := range SuiteUnits {
			if u == unit {
				known = true
				break
			}
		}
		if !known {
			return fmt.Errorf("entry %q: unit is not part of the suite", name)
		}
	}
	return nil
}

var instanceRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func instanceName(s string) bool { return instanceRe.MatchString(s) }

// targetPath maps an entry name onto its host path via svc.Paths.
func targetPath(paths svc.Paths, name string) (string, bool) {
	switch {
	case strings.HasPrefix(name, "root/frp/server/"):
		return filepath.Join(paths.ServerDir, strings.TrimPrefix(name, "root/frp/server/")), true
	case strings.HasPrefix(name, "root/frp/client/"):
		return filepath.Join(paths.ClientDir, strings.TrimPrefix(name, "root/frp/client/")), true
	case strings.HasPrefix(name, "root/frp/gre/"):
		return filepath.Join(paths.GREDir, strings.TrimPrefix(name, "root/frp/gre/")), true
	case strings.HasPrefix(name, "etc/systemd/system/"):
		unit := strings.TrimPrefix(name, "etc/systemd/system/")
		for _, u := range SuiteUnits {
			if u == unit {
				return filepath.Join(paths.UnitDir, unit), true
			}
		}
		return "", false
	case name == "etc/sysctl.d/99-tunnel-turbo.conf":
		return filepath.Join(paths.SysctlDir, "99-tunnel-turbo.conf"), true
	case name == "etc/sysctl.d/99-frp-zram.conf":
		return filepath.Join(paths.SysctlDir, "99-frp-zram.conf"), true
	case name == "etc/modules-load.d/bbr.conf":
		return filepath.Join(paths.ModulesDir, "bbr.conf"), true
	case name == "etc/frp-panel/zram.env":
		return filepath.Join(paths.EtcPanelDir, "zram.env"), true
	case name == "etc/frp-panel/watchdog.env":
		return filepath.Join(paths.EtcPanelDir, "watchdog.env"), true
	case name == "etc/frp-panel/panel.toml":
		return paths.PanelCfg, true
	}
	return "", false
}

// affectedUnit derives the unit a restored file feeds, for restart hints.
func affectedUnit(name string) (string, bool) {
	switch {
	case strings.HasPrefix(name, "root/frp/server/"):
		return "frps@" + strings.TrimSuffix(strings.TrimPrefix(name, "root/frp/server/"), ".toml"), true
	case strings.HasPrefix(name, "root/frp/client/"):
		return "frpc@" + strings.TrimSuffix(strings.TrimPrefix(name, "root/frp/client/"), ".toml"), true
	case strings.HasPrefix(name, "root/frp/gre/"):
		return "gre-tunnel@" + strings.TrimSuffix(strings.TrimPrefix(name, "root/frp/gre/"), ".env"), true
	case strings.HasPrefix(name, "etc/systemd/system/"):
		return strings.TrimSuffix(strings.TrimPrefix(name, "etc/systemd/system/"), ".service"), true
	}
	return "", false
}
