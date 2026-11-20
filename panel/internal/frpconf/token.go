package frpconf

import (
	"crypto/rand"
	"math/big"
)

// tokenAlphabet is the strong alphanumeric charset used for auth tokens and
// webServer passwords: 62 chars, ~190 bits of entropy at 32 characters.
const tokenAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// randomString draws n uniform characters from alphabet using crypto/rand.
func randomString(n int, alphabet string) (string, error) {
	max := big.NewInt(int64(len(alphabet)))
	out := make([]byte, 0, n)
	for len(out) < n {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out = append(out, alphabet[idx.Int64()])
	}
	return string(out), nil
}

// RandomToken returns a 32-character random alphanumeric auth token.
// This replaces the old static default token, which was insecure.
func RandomToken() (string, error) { return randomString(32, tokenAlphabet) }

// RandomPassword returns a 24-character random password (used for the FRP
// webServer basic-auth credentials that power metrics scraping).
func RandomPassword() (string, error) { return randomString(24, tokenAlphabet) }

// RandomSecret returns n cryptographically random bytes (JWT signing keys etc).
func RandomSecret(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
