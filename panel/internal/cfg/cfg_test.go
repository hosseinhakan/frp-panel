package cfg

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestBootstrapCreatesFileAndOneTimePassword(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "panel.toml")

	c, password, err := Bootstrap(path)
	if err != nil {
		t.Fatal(err)
	}
	if password == "" || len(password) != 20 {
		t.Fatalf("one-time password = %q (len %d), want 20 chars", password, len(password))
	}
	if !c.Auth.MustChangePassword {
		t.Error("must_change_password should be set after bootstrap")
	}
	if !c.CheckPassword(password) {
		t.Error("stored bcrypt hash does not match the printed one-time password")
	}
	if len(c.Session.JWTSecret) != 64 {
		t.Errorf("jwt_secret length = %d, want 64 hex chars", len(c.Session.JWTSecret))
	}

	// File must exist and contain no clear-text password.
	// (Mode is only meaningful on Unix; the production target is Linux.)
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), password) {
		t.Error("clear-text password leaked into panel.toml")
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(path); err != nil {
			t.Fatal(err)
		} else if fi.Mode().Perm() != 0o600 {
			t.Errorf("panel.toml mode = %v, want 0600", fi.Mode().Perm())
		}
	}

	// Second bootstrap must refuse to clobber.
	if _, _, err := Bootstrap(path); err == nil {
		t.Error("Bootstrap on existing file must fail")
	}
}

func TestDefaultBindsAllInterfaces(t *testing.T) {
	c := Default()
	if c.Server.Bind != "0.0.0.0" {
		t.Errorf("Default().Server.Bind = %q, want 0.0.0.0", c.Server.Bind)
	}
	if DefaultBind != "0.0.0.0" {
		t.Errorf("DefaultBind = %q, want 0.0.0.0", DefaultBind)
	}
}

func TestLoadDefaultsEmptyBindToAllInterfaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.toml")
	c, _, err := Bootstrap(path)
	if err != nil {
		t.Fatal(err)
	}
	c.Server.Bind = ""
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	loaded, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Server.Bind != "0.0.0.0" {
		t.Errorf("empty bind loaded as %q, want 0.0.0.0", loaded.Server.Bind)
	}
}

func TestLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "panel.toml")

	_, password, err := Bootstrap(path)
	if err != nil {
		t.Fatal(err)
	}
	c, oneTime, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if oneTime != "" {
		t.Error("Load on existing file must not return a one-time password")
	}
	if !c.CheckPassword(password) {
		t.Error("loaded config lost the admin hash")
	}
	if c.Auth.MustChangePassword != true {
		t.Error("must_change_password lost on round trip")
	}
	if c.Session.CookieName != "frp_session" || c.Session.TTLHours != 12 {
		t.Errorf("session defaults wrong: %+v", c.Session)
	}
}

func TestLoadBootstrapsWhenMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "panel.toml")
	c, password, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if password == "" {
		t.Fatal("first-run Load must return the one-time password")
	}
	if !c.CheckPassword(password) {
		t.Error("bootstrapped credentials do not verify")
	}
}

func TestSetAdminPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.toml")
	c, old, err := Bootstrap(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := SetAdminPassword(path, c, "NewStrongPass123"); err != nil {
		t.Fatal(err)
	}
	if !c.CheckPassword("NewStrongPass123") {
		t.Error("new password does not verify after SetAdminPassword")
	}
	if c.CheckPassword(old) {
		t.Error("old password still accepted after change")
	}
	if c.Auth.MustChangePassword {
		t.Error("must_change_password should clear after an explicit change")
	}
}

func TestResetPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.toml")
	_, original, err := Bootstrap(path)
	if err != nil {
		t.Fatal(err)
	}
	newPw, err := ResetPassword(path)
	if err != nil {
		t.Fatal(err)
	}
	if newPw == "" || newPw == original {
		t.Fatalf("reset password %q invalid (original %q)", newPw, original)
	}
	c, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !c.CheckPassword(newPw) {
		t.Error("reset password does not verify")
	}
	if !c.Auth.MustChangePassword {
		t.Error("reset must re-arm must_change_password")
	}
}

func TestResetPasswordBootstrapsMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.toml")
	pw, err := ResetPassword(path)
	if err != nil {
		t.Fatal(err)
	}
	if pw == "" {
		t.Fatal("ResetPassword on missing file should bootstrap and return a password")
	}
}

func TestBcryptCost(t *testing.T) {
	// Pin the cost: silently lowering it would weaken every install.
	hash, err := bcrypt.GenerateFromPassword([]byte("x"), BcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	if cost, err := bcrypt.Cost(hash); err != nil || cost != BcryptCost {
		t.Errorf("bcrypt cost = %d err=%v, want %d", cost, err, BcryptCost)
	}
}

func TestSessionExpiry(t *testing.T) {
	c := Default()
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	want := now.Add(12 * time.Hour)
	if !c.SessionExpiry(now).Equal(want) {
		t.Errorf("SessionExpiry = %v, want %v", c.SessionExpiry(now), want)
	}
}
