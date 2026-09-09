package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

// NonceSize and SaltSize are the lengths in bytes of the GCM nonce and
// the Argon2id salt, matching the vault header layout.
const (
	NonceSize = 12
	SaltSize  = 16
	// TagSize is the AES-GCM authentication tag length. Any ciphertext
	// shorter than this cannot possibly be valid, regardless of key —
	// worth checking before spending an Argon2id derivation on it.
	TagSize = 16
)

// ErrAuthFailed means GCM tag verification failed: either the password
// was wrong or the ciphertext was corrupted or tampered with. The two
// are indistinguishable by design — see the spec's threat model.
var ErrAuthFailed = errors.New("crypto: authentication failed (wrong password or corrupted vault)")

// Seal encrypts plaintext with AES-256-GCM under key, using nonce and
// binding aad as additional authenticated data. key must be KeySize
// bytes and nonce must be NonceSize bytes.
func Seal(key, nonce, aad, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

// Open decrypts and authenticates ciphertext (which includes the
// trailing GCM tag) with AES-256-GCM under key, using nonce and aad.
func Open(key, nonce, aad, ciphertext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrAuthFailed
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// RandomBytes returns n cryptographically random bytes from
// crypto/rand, as used for salts and nonces.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
