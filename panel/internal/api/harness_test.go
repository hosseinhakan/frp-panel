// Test harness: an in-memory Runner and a fully-wired Server over temp
// dirs, so every handler test runs on any OS without systemd/root.
package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/frp-suite/panel/internal/cfg"
	"github.com/frp-suite/panel/internal/frpconf"
	"github.com/frp-suite/panel/internal/svc"
)

// fakeRunner records every host command and answers from canned tables.
type fakeRunner struct {
	mu      sync.Mutex
	calls   []string // "systemctl:enable --now frps@x" / "exec:ping -c 3 ..." / "verify:server"
	verifyN int

	systemctlErr bool // every systemctl call fails (no systemd on host)
	// unitStateResults: unit → "active"/"inactive" lines for is-active.
	active map[string]string
	// execResults: lowercase "bin arg arg" prefix → output.
	execOut map[string]string
	// execErr contains prefixes that should fail.
	execErr map[string]string
	// execStreamOut: "bin arg" prefix → canned stream output (EOF after).
	execStreamOut map[string]string
	// execStreamErr: prefixes that should fail to start.
	execStreamErr map[string]string
	// verifyFailure, when set, makes every Verify return this error.
	verifyFailure error
	// verifyMissing makes Verify return ErrBinaryMissing.
	verifyMissing bool
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{
		active:        map[string]string{},
		execOut:       map[string]string{},
		execErr:       map[string]string{},
		execStreamOut: map[string]string{},
	}
}

func (f *fakeRunner) record(format string, a ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fmt.Sprintf(format, a...))
}

// called reports whether a recorded call contains the needle.
func (f *fakeRunner) called(needle string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.Contains(c, needle) {
			return true
		}
	}
	return false
}

func (f *fakeRunner) resetCalls() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

func (f *fakeRunner) Systemctl(args ...string) (string, error) {
	f.record("systemctl:%s", strings.Join(args, " "))
	if f.systemctlErr {
		return "System has not been booted with systemd", errors.New("systemctl: not available")
	}
	if len(args) > 0 && (args[0] == "is-active" || args[0] == "is-enabled") {
		var lines []string
		for _, u := range args[1:] {
			if args[0] == "is-active" {
				if state, ok := f.active[u]; ok {
					lines = append(lines, state)
				} else {
					lines = append(lines, "inactive")
				}
			} else {
				lines = append(lines, "enabled")
			}
		}
		return strings.Join(lines, "\n") + "\n", nil
	}
	return "ok\n", nil
}

func (f *fakeRunner) Exec(name string, args ...string) (string, error) {
	f.record("exec:%s %s", name, strings.Join(args, " "))
	key := name + " " + strings.Join(args, " ")
	for prefix, out := range f.execOut {
		if strings.HasPrefix(key, prefix) {
			return out, nil
		}
	}
	for prefix := range f.execErr {
		if strings.HasPrefix(key, prefix) {
			return "", fmt.Errorf("%s failed", name)
		}
	}
	return "", fmt.Errorf("%s: not found", name)
}

func (f *fakeRunner) Verify(kind frpconf.Kind, file string) (string, error) {
	f.record("verify:%s:%s", kind.String(), filepath.Base(file))
	if f.verifyFailure != nil {
		return "frp: syntax error at line 1", f.verifyFailure
	}
	if f.verifyMissing {
		return "", fmt.Errorf("%w", svc.ErrBinaryMissing)
	}
	return "ok\n", nil
}

func (f *fakeRunner) ExecStream(ctx context.Context, name string, args ...string) (io.ReadCloser, error) {
	f.record("execstream:%s %s", name, strings.Join(args, " "))
	key := name + " " + strings.Join(args, " ")
	for prefix := range f.execStreamErr {
		if strings.HasPrefix(key, prefix) {
			return nil, fmt.Errorf("%s failed to start", name)
		}
	}
	for prefix, out := range f.execStreamOut {
		if strings.HasPrefix(key, prefix) {
			// A completed stream: the handler reads the lines then EOF.
			return io.NopCloser(strings.NewReader(out)), nil
		}
	}
	return nil, fmt.Errorf("%s: not found", name)
}

// ---- test server -----------------------------------------------------------

type testEnv struct {
	t       *testing.T
	srv     *Server
	handler http.Handler
	runner  *fakeRunner
	root    string
	password string
	clock   *fakeClock
}

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "etc", "frp-panel", "panel.toml")
	c, password, err := cfg.Bootstrap(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	paths := svc.Paths{
		Root:        dir,
		ServerDir:   filepath.Join(dir, "root", "frp", "server"),
		ClientDir:   filepath.Join(dir, "root", "frp", "client"),
		GREDir:      filepath.Join(dir, "root", "frp", "gre"),
		PanelCfg:    cfgPath,
		EtcPanelDir: filepath.Join(dir, "etc", "frp-panel"),
		SysctlDir:   filepath.Join(dir, "etc", "sysctl.d"),
		ModulesDir:  filepath.Join(dir, "etc", "modules-load.d"),
		BinDir:      filepath.Join(dir, "usr", "local", "bin"),
		UnitDir:     filepath.Join(dir, "etc", "systemd", "system"),
		SysNetDir:   filepath.Join(dir, "sys", "class", "net"),
		LogDir:      filepath.Join(dir, "var", "log", "frp-panel"),
	}
	runner := newFakeRunner()
	clock := &fakeClock{now: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}
	s := New("test", c, cfgPath, paths, runner)
	s.now = clock.Now
	return &testEnv{
		t: t, srv: s, handler: s.Routes(), runner: runner,
		root: dir, password: password, clock: clock,
	}
}

// do runs a request against the test server. The host is pinned so
// same-origin CSRF checks have a stable reference (Origin: http://panel.local).
func (e *testEnv) do(method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	e.t.Helper()
	var rd strings.Reader
	if body != "" {
		rd = *strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, &rd)
	req.Host = "panel.local"
	req.RemoteAddr = "203.0.113.9:12345"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

// login performs a login and returns the session cookie value.
func (e *testEnv) login(user, password string) (string, int) {
	e.t.Helper()
	body := fmt.Sprintf(`{"username":%q,"password":%q}`, user, password)
	rec := e.do(http.MethodPost, "/api/auth/login", body, nil)
	cookies := rec.Header().Values("Set-Cookie")
	for _, c := range cookies {
		if strings.HasPrefix(c, "frp_session=") {
			return strings.SplitN(strings.SplitN(c, ";", 2)[0], "=", 2)[1], rec.Code
		}
	}
	return "", rec.Code
}

// authHeaders returns headers for an authenticated request.
func (e *testEnv) authHeaders(cookie string) map[string]string {
	return map[string]string{"Cookie": "frp_session=" + cookie}
}

// authorized does an authed request with same-origin headers.
func (e *testEnv) authorized(method, path, body string) *httptest.ResponseRecorder {
	e.t.Helper()
	cookie, code := e.login("admin", e.password)
	if code != http.StatusOK {
		e.t.Fatalf("login failed with %d", code)
	}
	return e.do(method, path, body, map[string]string{
		"Cookie":  "frp_session=" + cookie,
		"Origin":  "http://panel.local",
		"X-Requested-With": "XMLHttpRequest",
	})
}
