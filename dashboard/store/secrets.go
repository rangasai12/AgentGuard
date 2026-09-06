package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
)

// newSecret returns a random, high-entropy, URL-safe token — used for
// registration tokens, agent API keys, and session ids. These are shown to
// the caller exactly once; only their hash is ever stored (hashSecret).
func newSecret() string {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// hashSecret hashes a high-entropy secret for storage. Plain SHA-256 (not
// bcrypt) is correct here, unlike for user passwords: bcrypt's slow, salted
// hashing defends against brute-forcing a *low-entropy, human-chosen*
// secret; these tokens are 256 random bits, already infeasible to guess, so
// a fast hash is fine and lets a lookup-by-hash query use a plain index.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// secretMatches compares a candidate secret against a stored hash in
// constant time.
func secretMatches(candidate, storedHash string) bool {
	if storedHash == "" {
		return false
	}
	got := hashSecret(candidate)
	return subtle.ConstantTimeCompare([]byte(got), []byte(storedHash)) == 1
}
