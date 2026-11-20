// Auth: bcrypt credentials + JWT session cookie (HS256), rate-limited
// login with exponential lockout, same-origin CSRF defense, sliding expiry.
//
// No token ever touches localStorage — the session lives in an HttpOnly
// cookie named frp_session (SameSite=Strict, Secure under TLS).
package api

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/frp-suite/panel/internal/cfg"
)

const minNewPasswordLen = 10

// setSessionCookie issues a fresh session cookie for the request. The JWT
// carries sub/iat/exp (HS256, TTL from config).
func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, username string) {
	now := s.now()
	exp := s.cfg.SessionExpiry(now)
	claims := jwt.MapClaims{
		"sub": username,
		"iat": now.Unix(),
		"exp": exp.Unix(),
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).
		SignedString([]byte(s.cfg.Session.JWTSecret))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "session signing failed")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.Session.CookieName,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		Expires:  exp,
	})
}

// clearSessionCookie removes the session cookie.
func (s *Server) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.Session.CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// currentSession validates the request's session cookie. Returns the
// username and remaining validity.
func (s *Server) currentSession(r *http.Request) (string, time.Duration, error) {
	ck, err := r.Cookie(s.cfg.Session.CookieName)
	if err != nil || ck.Value == "" {
		return "", 0, errors.New("no session")
	}
	tok, err := jwt.Parse(ck.Value, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return []byte(s.cfg.Session.JWTSecret), nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithTimeFunc(s.now))
	if err != nil || !tok.Valid {
		return "", 0, errors.New("invalid session token")
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return "", 0, errors.New("invalid session claims")
	}
	sub, _ := claims["sub"].(string)
	if sub == "" || sub != s.cfg.Auth.AdminUsername {
		return "", 0, errors.New("session user mismatch")
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return "", 0, errors.New("session token has no expiry")
	}
	// Remaining validity relative to the panel clock (tests time-travel).
	return sub, exp.Time.Sub(s.now()), nil
}

// authed wraps a handler with session auth, same-origin CSRF enforcement for
// mutating methods and the sliding cookie refresh.
func (s *Server) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, remaining, err := s.currentSession(r)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
			if !sameOrigin(r) {
				writeErr(w, http.StatusForbidden, "cross-origin request rejected")
				return
			}
		}
		// Sliding expiry: re-issue when less than half the TTL remains.
		if remaining < time.Duration(s.cfg.Session.TTLHours)*time.Hour/2 {
			s.setSessionCookie(w, r, username)
		}
		next(w, r)
	}
}

// sameOrigin enforces the CSRF defense-in-depth on top of SameSite=Strict:
// browser-set Origin/Referer must match the request host. Requests without
// either header (curl, the CLI, HTMX from same origin sends them) pass —
// browsers always attach Origin to cross-site POSTs, so this is exactly the
// attack surface SameSite=Strict doesn't already cover.
func sameOrigin(r *http.Request) bool {
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		return err == nil && u.Host == r.Host
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		u, err := url.Parse(ref)
		return err == nil && u.Host == r.Host
	}
	return true
}

// ---- login rate limiting ---------------------------------------------------

type limitEntry struct {
	fails       int
	windowStart time.Time
	lockedUntil time.Time
}

type loginLimiter struct {
	mu      sync.Mutex
	entries map[string]*limitEntry
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{entries: map[string]*limitEntry{}}
}

const (
	limWindow   = time.Minute
	limMaxFails = 5
	limBaseLock = 30 * time.Second
	limMaxLock  = 15 * time.Minute
)

// check reports whether the IP may attempt a login now.
func (l *loginLimiter) check(ip string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[ip]
	if e == nil {
		return true, 0
	}
	if now.Before(e.lockedUntil) {
		return false, time.Until(e.lockedUntil)
	}
	return true, 0
}

// recordFailure counts a failed attempt and manages the lockout curve:
// 5 failures within a minute → lockout, and once past the threshold the
// history sticks — every failure after an expired lock doubles the next
// lockout (30 s → 60 s → 120 s → … capped at 15 minutes), per
// docs/ARCHITECTURE.md §5.3. A successful login clears everything.
func (l *loginLimiter) recordFailure(ip string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[ip]
	if e == nil {
		e = &limitEntry{}
		l.entries[ip] = e
	}
	// Fresh counting window — but only while we are below the threshold.
	if e.fails <= limMaxFails && now.Sub(e.windowStart) > limWindow {
		e.fails = 0
	}
	e.windowStart = now
	e.fails++
	if e.fails > limMaxFails {
		lock := limBaseLock << uint(e.fails-limMaxFails)
		if lock > limMaxLock || lock <= 0 {
			lock = limMaxLock
		}
		e.lockedUntil = now.Add(lock)
		return lock
	}
	return 0
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, ip)
}

// clientIP extracts the remote host (port stripped).
func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// audit writes a security event to stderr (journald captures it when the
// panel runs under frp-panel.service).
func audit(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "frp-panel audit: "+format+"\n", a...)
}

// ---- handlers ---------------------------------------------------------------

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	now := s.now()

	if ok, retry := s.limiter.check(ip, now); !ok {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retry.Seconds())+1))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":      "too many failed logins — locked out",
			"retry_after": int(retry.Seconds()) + 1,
		})
		return
	}

	var req loginReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	userOK := subtle.ConstantTimeCompare(
		[]byte(strings.ToLower(req.Username)), []byte(s.cfg.Auth.AdminUsername)) == 1
	passOK := s.cfg.CheckPassword(req.Password)
	if !userOK || !passOK {
		lock := s.limiter.recordFailure(ip, now)
		audit("login failure user=%q ip=%s lockout=%s", req.Username, ip, lock)
		if lock > 0 {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(lock.Seconds())+1))
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"error":       "too many failed logins — locked out",
				"retry_after": int(lock.Seconds()) + 1,
			})
			return
		}
		writeErr(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	s.limiter.reset(ip)
	audit("login success user=%q ip=%s", req.Username, ip)
	s.setSessionCookie(w, r, s.cfg.Auth.AdminUsername)
	writeJSON(w, http.StatusOK, map[string]any{
		"username":              s.cfg.Auth.AdminUsername,
		"must_change_password":  s.cfg.Auth.MustChangePassword,
		"expires_at":            s.cfg.SessionExpiry(s.now()).Format(time.RFC3339),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	username, remaining, err := s.currentSession(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "authentication required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"username":              username,
		"must_change_password":  s.cfg.Auth.MustChangePassword,
		"session_expires_in":    int(remaining.Seconds()),
	})
}

type changePasswordReq struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req changePasswordReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if !s.cfg.CheckPassword(req.CurrentPassword) {
		writeErr(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}
	if len(req.NewPassword) < minNewPasswordLen {
		writeErr(w, http.StatusBadRequest, "new password must be at least %d characters", minNewPasswordLen)
		return
	}

	s.cfgMu.Lock()
	err := cfg.SetAdminPassword(s.cfgPath, s.cfg, req.NewPassword)
	s.cfgMu.Unlock()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to persist new password: %v", err)
		return
	}
	audit("password changed for %s", s.cfg.Auth.AdminUsername)
	// Session stays valid (same JWT secret); refresh the cookie to be tidy.
	s.setSessionCookie(w, r, s.cfg.Auth.AdminUsername)
	writeJSON(w, http.StatusOK, map[string]any{"status": "password changed", "must_change_password": false})
}
