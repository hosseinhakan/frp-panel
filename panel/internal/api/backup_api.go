// Backup API: ZIP export stream (secrets toggle, redaction by default)
// and multipart import with selective categories and restart handling.
// The archive handling itself lives in internal/backup — the handlers
// here only deal with HTTP plumbing and systemctl side effects.
package api

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/frp-suite/panel/internal/backup"
)

// handleBackupExport streams a fresh ZIP. ?secrets=1 opts into including
// /etc/frp-panel/panel.toml and leaving FRP tokens verbatim; without it,
// tokens/passwords are redacted (import regenerates fresh ones).
func (s *Server) handleBackupExport(w http.ResponseWriter, r *http.Request) {
	includeSecrets := r.URL.Query().Get("secrets") == "1"
	if includeSecrets {
		audit("backup export WITH secrets requested from %s", clientIP(r))
	} else {
		audit("backup export (secrets redacted)")
	}
	name := fmt.Sprintf("frp-suite-backup-%s.zip", backupTimestamp(s.now()))

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.WriteHeader(http.StatusOK)

	summary, err := backup.Export(w, s.paths, includeSecrets, s.now())
	if err != nil {
		// The error is already partly written into the stream; the SSE
		// of bytes cannot be un-sent, so log loudly and stop.
		audit("backup export failed mid-stream: %v", err)
		return
	}
	audit("backup export: %d files, categories %v", summary.Files, summary.Categories)
}

// handleBackupImport applies an uploaded ZIP. Multipart fields:
//
//	file        (required) the ZIP
//	categories  (optional, repeatable or comma-separated) frp,systemd,turbo,panel
//	restart     (optional) "1"/"true" — restart affected active units afterwards
//
// Secrets found as REDACTED placeholders are regenerated with fresh random
// values unless regenerate=0.
func (s *Server) handleBackupImport(w http.ResponseWriter, r *http.Request) {
	// Hard cap the whole upload (zip bombs must die at the door).
	r.Body = http.MaxBytesReader(w, r.Body, backup.MaxZipBytes+(1<<20))
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "upload too large or malformed (limit %d MB)", backup.MaxZipBytes>>20)
		return
	}
	defer func() {
		if rmErr := r.MultipartForm.RemoveAll(); rmErr != nil {
			audit("multipart cleanup: %v", rmErr)
		}
	}()

	file, _, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "missing multipart field \"file\"")
		return
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, backup.MaxZipBytes+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "cannot read upload: %v", err)
		return
	}
	if len(raw) > backup.MaxZipBytes {
		writeErr(w, http.StatusRequestEntityTooLarge, "archive exceeds the %d MB limit", backup.MaxZipBytes>>20)
		return
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "not a valid ZIP archive")
		return
	}

	opts := backup.ImportOptions{RegenerateSecrets: true}
	if v := r.FormValue("regenerate"); v == "0" || v == "false" {
		opts.RegenerateSecrets = false
	}
	for _, c := range r.Form["categories"] {
		for _, part := range strings.Split(c, ",") {
			if part = strings.TrimSpace(part); part != "" {
				opts.Categories = append(opts.Categories, part)
			}
		}
	}
	for _, c := range opts.Categories {
		switch c {
		case backup.CatFRP, backup.CatSystemd, backup.CatTurbo, backup.CatPanel:
		default:
			writeErr(w, http.StatusBadRequest, "unknown category %q (want %s)",
				c, strings.Join(backup.AllCategories, ", "))
			return
		}
	}

	summary, err := backup.Import(zr, s.paths, opts, s.now())
	if err != nil {
		audit("backup import rejected: %v", err)
		writeErr(w, http.StatusUnprocessableEntity, "restore rejected: %v", err)
		return
	}
	audit("backup import: %d files restored, %d backed up, categories %v",
		len(summary.Restored), len(summary.Backups), summary.Categories)

	// systemctl side effects.
	notes := []string{}
	if summary.DaemonReload {
		if out, err := s.runner.Systemctl("daemon-reload"); err != nil {
			notes = append(notes, "daemon-reload failed: "+strings.TrimSpace(out))
		} else {
			notes = append(notes, "systemd reloaded (unit files restored)")
		}
	}
	if r.FormValue("restart") == "1" || r.FormValue("restart") == "true" {
		restarted := 0
		for _, unit := range summary.AffectedUnits {
			switch unit {
			case "frps@.service", "frpc@.service", "gre-tunnel@.service", "frp-panel":
				// Templates and the panel itself are never restarted
				// directly; the list above covers live instances.
				continue
			}
			if s.unitIsActive(unit) {
				s.runner.Systemctl("restart", unit)
				restarted++
			}
		}
		notes = append(notes, fmt.Sprintf("%d affected active units restarted", restarted))
	}
	if summary.RestartPanelHint {
		notes = append(notes, "panel config/unit restored — restart frp-panel to apply")
	}

	writeJSON(w, http.StatusOK, map[string]any{"summary": summary, "notes": notes})
}
