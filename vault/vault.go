package vault

import "github.com/FormlessEvoker/passgo/crypto"

// Create encrypts plaintext under a freshly generated salt and nonce,
// using the default Argon2id parameters, and returns the complete
// vault file contents (header || ciphertext || tag). Used by `init`.
func Create(password string, plaintext []byte) ([]byte, error) {
	salt, err := crypto.RandomBytes(crypto.SaltSize)
	if err != nil {
		return nil, err
	}
	nonce, err := crypto.RandomBytes(crypto.NonceSize)
	if err != nil {
		return nil, err
	}

	h := Header{Version: FormatV1, KDFID: KDFArgon2id, Params: crypto.DefaultParams}
	copy(h.Salt[:], salt)
	copy(h.Nonce[:], nonce)

	key := crypto.DeriveKey(password, h.Salt[:], h.Params)
	defer zero(key)

	return seal(h, key, plaintext)
}

// Opened is a decrypted vault: the plaintext payload, plus everything
// needed to write it back with Save without re-deriving the key from
// the master password a second time.
type Opened struct {
	Plaintext []byte

	header Header
	key    []byte
}

// Open parses and decrypts a vault file's contents with password.
// A non-nil error from a bad password and one from a corrupted file
// are indistinguishable, per the threat model in SPECIFICATION.md §1.
func Open(fileBytes []byte, password string) (*Opened, error) {
	if len(fileBytes) < HeaderSize {
		return nil, ErrTruncated
	}
	h, err := ParseHeader(fileBytes[:HeaderSize])
	if err != nil {
		return nil, err
	}
	if len(fileBytes)-HeaderSize < crypto.TagSize {
		return nil, ErrCiphertextTooShort
	}
	key := crypto.DeriveKey(password, h.Salt[:], h.Params)

	plaintext, err := crypto.Open(key, h.Nonce[:], fileBytes[:HeaderSize], fileBytes[HeaderSize:])
	if err != nil {
		zero(key)
		return nil, err
	}
	return &Opened{Plaintext: plaintext, header: h, key: key}, nil
}

// Close zeroes the key material held by o. Callers should defer it
// after a successful Open.
func (o *Opened) Close() {
	zero(o.key)
}

// Save re-encrypts newPlaintext under the same key and KDF parameters
// o was opened with, using a freshly generated nonce, and returns the
// complete vault file contents. It does not re-derive the key from the
// password, so it is cheap relative to Open.
func (o *Opened) Save(newPlaintext []byte) ([]byte, error) {
	nonce, err := crypto.RandomBytes(crypto.NonceSize)
	if err != nil {
		return nil, err
	}
	copy(o.header.Nonce[:], nonce)
	return seal(o.header, o.key, newPlaintext)
}

// seal encodes h as AAD and encrypts plaintext under key and h.Nonce,
// returning header || ciphertext || tag.
func seal(h Header, key, plaintext []byte) ([]byte, error) {
	header := h.MarshalBinary()
	ct, err := crypto.Seal(key, h.Nonce[:], header, plaintext)
	if err != nil {
		return nil, err
	}
	return append(header, ct...), nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
