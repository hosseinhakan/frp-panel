package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestLoginSuccessSetsSessionCookie(t *testing.T) {
	e := newTestEnv(t)
	cookie, code := e.login("admin", e.password)
	if code != http.StatusOK {
		t.Fatalf("login = %d, want 200", code)
	}
	if cookie == "" {
		t.Fatal("no session cookie issued")
	}

	// First-login flag comes back with the session.
	var resp struct {
		Username           string `json:"username"`
		MustChangePassword bool   `json:"must_change_password"`
	}
	rec := e.do(http.MethodPost, "/api/auth/login",
		`{"username":"admin","password":"`+e.password+`"}`, nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Username != "admin" || !resp.MustChangePassword {
		t.Errorf("login response = %+v", resp)
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	e := newTestEnv(t)
	_, code := e.login("admin", "wrong-password")
	if code != http.StatusUnauthorized {
		t.Fatalf("wrong password login = %d, want 401", code)
	}
	_, code = e.login("root", e.password)
	if code != http.StatusUnauthorized {
		t.Fatalf("wrong username login = %d, want 401", code)
	}
}

func TestSessionCookieAttributes(t *testing.T) {
	e := newTestEnv(t)
	body := `{"username":"admin","password":"` + e.password + `"}`
	rec := e.do(http.MethodPost, "/api/auth/login", body, nil)
	cookies := rec.Header().Values("Set-Cookie")
	if len(cookies) == 0 {
		t.Fatal("no Set-Cookie header")
	}
	c := cookies[0]
	for _, want := range []string{"frp_session=", "HttpOnly", "SameSite=Strict", "Path=/"} {
		if !strings.Contains(c, want) {
			t.Errorf("cookie %q missing %q", c, want)
		}
	}
}

func TestAuthedRoutesRequireSession(t *testing.T) {
	e := newTestEnv(t)
	for _, path := range []string{"/api/servers", "/api/clients", "/api/services", "/api/gre", "/api/auth/me"} {
		rec := e.do(http.MethodGet, path, "", nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s without session = %d, want 401", path, rec.Code)
		}
	}
	// Tampered cookie.
	rec := e.do(http.MethodGet, "/api/servers", "", map[string]string{"Cookie": "frp_session=tampered"})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("tampered session = %d, want 401", rec.Code)
	}
}

func TestMeEndpoint(t *testing.T) {
	e := newTestEnv(t)
	cookie, _ := e.login("admin", e.password)
	rec := e.do(http.MethodGet, "/api/auth/me", "", e.authHeaders(cookie))
	if rec.Code != http.StatusOK {
		t.Fatalf("me = %d", rec.Code)
	}
	var resp struct {
		Username           string `json:"username"`
		MustChangePassword bool   `json:"must_change_password"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Username != "admin" || !resp.MustChangePassword {
		t.Errorf("me = %+v", resp)
	}
}

func TestLogoutClearsCookie(t *testing.T) {
	e := newTestEnv(t)
	cookie, _ := e.login("admin", e.password)
	headers := e.authHeaders(cookie)
	headers["Origin"] = "http://panel.local"
	rec := e.do(http.MethodPost, "/api/auth/logout", "", headers)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout = %d", rec.Code)
	}
	setCookie := rec.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "frp_session=") || !strings.Contains(setCookie, "Max-Age=0") {
		t.Errorf("logout cookie %q should expire the session", setCookie)
	}
}

func TestLoginRateLimitLockout(t *testing.T) {
	e := newTestEnv(t)
	// Five failures in a row: allowed attempts that end 401.
	for i := 0; i < 5; i++ {
		if _, code := e.login("admin", "nope"); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401", i+1, code)
		}
	}
	// Sixth failure within the window trips the lockout → 429.
	if _, code := e.login("admin", "nope"); code != http.StatusTooManyRequests {
		t.Fatalf("sixth failed attempt = %d, want 429", code)
	}
	// Even the correct password is locked out now.
	if _, code := e.login("admin", e.password); code != http.StatusTooManyRequests {
		t.Fatalf("login during lockout = %d, want 429", code)
	}

	// Exponential curve: the first lock doubles after it expires and the
	// guessing continues.
	firstLock := e.srv.limiter.entries["203.0.113.9"].lockedUntil
	e.clock.now = e.clock.now.Add(61 * time.Second)
	if _, code := e.login("admin", "nope"); code != http.StatusTooManyRequests {
		t.Fatalf("post-lockout failure = %d, want 429 (lock must double)", code)
	}
	secondLock := e.srv.limiter.entries["203.0.113.9"].lockedUntil
	if !secondLock.After(firstLock) {
		t.Errorf("second lock %v must outlast first %v", secondLock, firstLock)
	}
}

func TestLoginSuccessResetsLimiter(t *testing.T) {
	e := newTestEnv(t)
	for i := 0; i < 4; i++ {
		e.login("admin", "nope")
	}
	if _, code := e.login("admin", e.password); code != http.StatusOK {
		t.Fatalf("correct login after failures = %d, want 200", code)
	}
	if _, code := e.login("admin", "nope"); code != http.StatusUnauthorized {
		t.Fatalf("failure after reset = %d, want 401 (window cleared)", code)
	}
}

func TestSlidingSessionReissue(t *testing.T) {
	e := newTestEnv(t)
	cookie, _ := e.login("admin", e.password)

	// Fresh session: no re-issue expected (> half the TTL left).
	rec := e.do(http.MethodGet, "/api/auth/me", "", e.authHeaders(cookie))
	if rec.Header().Get("Set-Cookie") != "" {
		t.Error("fresh session should not be re-issued")
	}

	// 7 hours later (< 6 h left): the cookie must slide.
	e.clock.now = e.clock.now.Add(7 * time.Hour)
	rec = e.do(http.MethodGet, "/api/auth/me", "", e.authHeaders(cookie))
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "frp_session=") {
		t.Error("expiring session should be re-issued (sliding expiry)")
	}
}

func TestExpiredSessionRejected(t *testing.T) {
	e := newTestEnv(t)
	cookie, _ := e.login("admin", e.password)
	e.clock.now = e.clock.now.Add(13 * time.Hour) // beyond the 12 h TTL
	rec := e.do(http.MethodGet, "/api/servers", "", e.authHeaders(cookie))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired session = %d, want 401", rec.Code)
	}
}

func TestCSRFRejectsForeignOrigin(t *testing.T) {
	e := newTestEnv(t)
	cookie, _ := e.login("admin", e.password)
	body := `{"name":"x"}`

	// Foreign Origin on a mutating route → 403.
	headers := e.authHeaders(cookie)
	headers["Origin"] = "http://evil.example"
	rec := e.do(http.MethodPost, "/api/servers", body, headers)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-origin POST = %d, want 403", rec.Code)
	}

	// Same-origin Origin passes the CSRF gate.
	headers["Origin"] = "http://panel.local"
	rec = e.do(http.MethodPost, "/api/servers", body, headers)
	if rec.Code == http.StatusForbidden {
		t.Fatal("same-origin POST must pass the CSRF gate")
	}

	// GET is never blocked by CSRF (read-only).
	headers["Origin"] = "http://evil.example"
	rec = e.do(http.MethodGet, "/api/servers", "", headers)
	if rec.Code == http.StatusForbidden {
		t.Fatal("GET must not be CSRF-checked")
	}
}

func TestChangePasswordFlow(t *testing.T) {
	e := newTestEnv(t)
	cookie, _ := e.login("admin", e.password)

	// Wrong current password.
	headers := e.authHeaders(cookie)
	headers["Origin"] = "http://panel.local"
	rec := e.do(http.MethodPost, "/api/auth/password", `{"current_password":"bad","new_password":"NewStrongPass1"}`, headers)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("change with wrong current = %d, want 401", rec.Code)
	}
	// Too-short new password.
	rec = e.do(http.MethodPost, "/api/auth/password", `{"current_password":"`+e.password+`","new_password":"short"}`, headers)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("short new password = %d, want 400", rec.Code)
	}
	// Good change.
	rec = e.do(http.MethodPost, "/api/auth/password",
		`{"current_password":"`+e.password+`","new_password":"NewStrongPass123"}`, headers)
	if rec.Code != http.StatusOK {
		t.Fatalf("password change = %d: %s", rec.Code, rec.Body.String())
	}

	// Old password no longer works; new one does; must_change flag cleared.
	if _, code := e.login("admin", e.password); code != http.StatusUnauthorized {
		t.Error("old password must stop working after change")
	}
	_, code := e.login("admin", "NewStrongPass123")
	if code != http.StatusOK {
		t.Errorf("new password login = %d, want 200", code)
	}
	rec = e.do(http.MethodGet, "/api/auth/me", "", e.authHeaders(cookie))
	var me struct {
		MustChangePassword bool `json:"must_change_password"`
	}
	json.Unmarshal(rec.Body.Bytes(), &me)
	if me.MustChangePassword {
		t.Error("must_change_password should be false after change")
	}
}
