// writeGate is the single path through which every config write passes:
//
//  1. render candidate content to <path>.new
//  2. run `frps verify -c` / `frpc verify -c` against it (falling back to the
//     internal frpconf parser when the binary isn't installed yet)
//  3. copy any existing file to <path>.bak-<timestamp> (the suite's .bak rule)
//  4. atomically move the verified candidate into place
//
// Bad TOML never reaches systemd, and nothing is ever written without a
// recoverable backup of the previous state.
package api

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/frp-suite/panel/internal/frpconf"
	"github.com/frp-suite/panel/internal/svc"
)

// backupTimestamp formats the .bak suffix the same way the CLI does
// (`date +%Y%m%d-%H%M%S`).
func backupTimestamp(now time.Time) string {
	return now.UTC().Format("20060102-150405")
}

// writeGateResult reports how the content was validated.
type writeGateResult struct {
	VerifyMode string `json:"verify"`          // "frps-verify" | "frpc-verify" | "internal"
	Backup     string `json:"backup,omitempty"` // previous file, when one existed
}

// writeGate validates and atomically installs new content for a config file.
func (s *Server) writeGate(kind frpconf.Kind, path, content string) (writeGateResult, error) {
	res := writeGateResult{}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return res, err
	}
	candidate := path + ".new"
	if err := os.WriteFile(candidate, []byte(content), 0o600); err != nil {
		return res, err
	}
	defer os.Remove(candidate)

	// 1) external gate — FRP's own verify subcommand (also renders templates).
	out, err := s.runner.Verify(kind, candidate)
	switch {
	case err == nil:
		res.VerifyMode = kind.String() + "-verify"
	case errors.Is(err, svc.ErrBinaryMissing):
		// 2) fallback gate — the internal parser. The rendered output of
		// frpconf always parses, but this also validates raw-PUT content.
		if perr := internalValidate(kind, []byte(content)); perr != nil {
			return res, fmt.Errorf("config invalid: %v", perr)
		}
		res.VerifyMode = "internal"
	default:
		return res, fmt.Errorf("%s rejected the config: %v", kind.String(), trimOutput(err.Error()+"\n"+out))
	}

	// 3) .bak the previous state before overwriting.
	if old, rerr := os.ReadFile(path); rerr == nil {
		bak := path + ".bak-" + backupTimestamp(s.now())
		if err := os.WriteFile(bak, old, 0o600); err != nil {
			return res, fmt.Errorf("failed to write backup %s: %v", bak, err)
		}
		res.Backup = bak
	}

	// 4) install.
	if err := os.Rename(candidate, path); err != nil {
		return res, err
	}
	return res, nil
}

// internalValidate is the no-binary fallback for the write gate.
func internalValidate(kind frpconf.Kind, raw []byte) error {
	if _, _, err := frpconf.Classify(raw, kind); err != nil {
		return err
	}
	if kind == frpconf.KindClient {
		_, err := frpconf.ParseClient(raw)
		return err
	}
	_, err := frpconf.ParseServer(raw)
	return err
}

// backupAndRemove moves a config file aside (delete still keeps a .bak —
// deletion is a write like any other).
func (s *Server) backupAndRemove(path string) (string, error) {
	old, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	bak := path + ".bak-" + backupTimestamp(s.now())
	if err := os.WriteFile(bak, old, 0o600); err != nil {
		return "", err
	}
	if err := os.Remove(path); err != nil {
		return "", err
	}
	return bak, nil
}

func trimOutput(s string) string {
	if len(s) > 500 {
		return s[:500] + "…"
	}
	return s
}
