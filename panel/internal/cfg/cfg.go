// Package cfg loads, saves and bootstraps the panel's own state file
// /etc/frp-panel/panel.toml — the only private state the panel keeps
// (admin credentials, JWT secret, node role). Everything else the panel
// touches lives under /root/frp and is shared with the bash CLI.
package cfg

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/frp-suite/panel/internal/frpconf"
)

// Defaults for panel runtime knobs.
const (
	DefaultBind       = "127.0.0.1"
	DefaultPort       = 9000
	DefaultCookieName = "frp_session"
	DefaultTTLHours   = 12
	// BcryptCost per docs/ARCHITECTURE.md §5.2.
	BcryptCost = 10
)

// Config is the managed subset of panel.toml.
type Config struct {
	Server struct {
		Bind string `toml:"bind"` // default 127.0.0.1; public bind is opt-in
		Port int    `toml:"port"` // default 9000
	} `toml:"server"`

	Auth struct {
		AdminUsername      string `toml:"admin_username"`       // default "admin"
		AdminHash          string `toml:"admin_hash"`           // bcrypt, cost 10
		MustChangePassword bool   `toml:"must_change_password"` // one-time password pending
	} `toml:"auth"`

	Session struct {
		JWTSecret  string `toml:"jwt_secret"`   // 64 hex chars (32 random bytes)
		CookieName string `toml:"cookie_name"`   // frp_session
		TTLHours   int    `toml:"ttl_hours"`     // 12, sliding expiry
	} `toml:"session"`

	Node struct {
		Role  string `toml:"role"`  // "" | iran | foreign | standalone (cosmetic label)
		Label string `toml:"label"` // free-form, shown on the dashboard
	} `toml:"node"`
}

// Default returns a Config with all knobs filled in.
func Default() *Config {
	c := &Config{}
	c.Server.Bind = DefaultBind
	c.Server.Port = DefaultPort
	c.Auth.AdminUsername = "admin"
	c.Session.CookieName = DefaultCookieName
	c.Session.TTLHours = DefaultTTLHours
	return c
}

// ErrNoAdmin is returned when the config has no usable admin hash yet.
var ErrNoAdmin = errors.New("cfg: no admin credentials configured")

// Load reads panel.toml, or bootstraps it on first run.
//
// On first run it creates the file with a generated JWT secret and a
// one-time random admin password. The password is returned once and never
// written to disk in clear; bootstrapping prints it to the caller via the
// returned value (main prints it to the console/journal).
func Load(path string) (*Config, string, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		c, err := parse(raw)
		if err != nil {
			return nil, "", fmt.Errorf("cfg: %s: %w", path, err)
		}
		applyDefaults(c)
		if c.Auth.AdminHash == "" {
			return nil, "", ErrNoAdmin
		}
		return c, "", nil
	}
	if !os.IsNotExist(err) {
		return nil, "", err
	}

	c, password, err := Bootstrap(path)
	if err != nil {
		return nil, "", err
	}
	return c, password, nil
}

// Bootstrap generates a fresh panel.toml with a one-time admin password.
// If the file already exists it is left untouched and an error returned —
// bootstrap only ever runs once.
func Bootstrap(path string) (*Config, string, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, "", fmt.Errorf("cfg: %s already exists", path)
	}
	c := Default()

	secret, err := frpconf.RandomSecret(32)
	if err != nil {
		return nil, "", err
	}
	c.Session.JWTSecret = fmt.Sprintf("%x", secret)

	password, err := OneTimePassword()
	if err != nil {
		return nil, "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return nil, "", err
	}
	c.Auth.AdminHash = string(hash)
	c.Auth.MustChangePassword = true

	if err := Save(path, c); err != nil {
		return nil, "", err
	}
	return c, password, nil
}

// Save renders the config to TOML and writes it with 0600 permissions,
// atomically (temp file + rename) so a crash never leaves a half-written file.
func Save(path string, c *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := render(c)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// SetAdminPassword bcrypts the password, stores the hash and marks the
// account as no longer requiring a change. Saves immediately.
func SetAdminPassword(path string, c *Config, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return err
	}
	c.Auth.AdminHash = string(hash)
	c.Auth.MustChangePassword = false
	return Save(path, c)
}

// ResetPassword generates a fresh one-time admin password for the config at
// path (used by `frp-panel reset-password` when the password is lost),
// marks must_change_password and saves. Returns the new password.
func ResetPassword(path string) (string, error) {
	c, _, err := Load(path)
	if err != nil {
		// Missing or broken config: bootstrap a whole new one instead.
		if os.IsNotExist(errors.Unwrap(err)) || errors.Is(err, ErrNoAdmin) {
			var password string
			c, password, err = Bootstrap(path)
			if err != nil {
				return "", err
			}
			return password, nil
		}
		return "", err
	}
	password, err := OneTimePassword()
	if err != nil {
		return "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return "", err
	}
	c.Auth.AdminHash = string(hash)
	c.Auth.MustChangePassword = true
	if err := Save(path, c); err != nil {
		return "", err
	}
	return password, nil
}

// CheckPassword verifies a candidate password against the stored hash.
func (c *Config) CheckPassword(password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(c.Auth.AdminHash), []byte(password)) == nil
}

// oneTimeAlphabet avoids the visually ambiguous characters (0/O, 1/l/I) so a
// password read from a console can be retyped reliably.
const oneTimeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

// OneTimePassword returns a 20-char crypto-random password (~103 bits).
func OneTimePassword() (string, error) {
	max := big.NewInt(int64(len(oneTimeAlphabet)))
	out := make([]byte, 0, 20)
	for len(out) < 20 {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out = append(out, oneTimeAlphabet[idx.Int64()])
	}
	return string(out), nil
}

func applyDefaults(c *Config) {
	if c.Server.Bind == "" {
		c.Server.Bind = DefaultBind
	}
	if c.Server.Port <= 0 {
		c.Server.Port = DefaultPort
	}
	if c.Auth.AdminUsername == "" {
		c.Auth.AdminUsername = "admin"
	}
	if c.Session.CookieName == "" {
		c.Session.CookieName = DefaultCookieName
	}
	if c.Session.TTLHours <= 0 {
		c.Session.TTLHours = DefaultTTLHours
	}
}

// SessionExpiry is a convenience for token issuance.
func (c *Config) SessionExpiry(now time.Time) time.Time {
	return now.Add(time.Duration(c.Session.TTLHours) * time.Hour)
}
