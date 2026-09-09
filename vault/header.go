// Package vault implements the passgo vault file format: a plaintext
// header followed by an AES-256-GCM ciphertext, per SPECIFICATION.md
// §3. It builds on the crypto package for key derivation and AEAD, and
// owns the file layout and the atomic-write behavior around it.
package vault

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/FormlessEvoker/passgo/crypto"
)

const (
	// Magic is the fixed ASCII prefix identifying a passgo vault file.
	Magic = "PASSGO"

	// FormatV1 is the only format version this package writes or reads.
	FormatV1 byte = 0x01

	// KDFArgon2id is the only KDF identifier this package writes or reads.
	KDFArgon2id byte = 0x01

	// HeaderSize is the fixed size in bytes of the plaintext header,
	// per the layout table in SPECIFICATION.md §3.1.
	HeaderSize = 46
)

var (
	ErrBadMagic          = errors.New("vault: not a passgo vault file")
	ErrUnsupportedFormat = errors.New("vault: unsupported format version")
	ErrUnsupportedKDF    = errors.New("vault: unsupported KDF identifier")
	ErrTruncated         = errors.New("vault: file too short to be a valid vault")
)

// Header is the plaintext prefix of a vault file. Its encoded form is
// also used verbatim as additional authenticated data (AAD) for the
// AEAD, so none of these fields can be tampered with independently of
// the ciphertext without invalidating the GCM tag.
type Header struct {
	Version byte
	KDFID   byte
	Params  crypto.Params
	Salt    [crypto.SaltSize]byte
	Nonce   [crypto.NonceSize]byte
}

// MarshalBinary encodes the header to its fixed HeaderSize on-disk form.
func (h Header) MarshalBinary() []byte {
	b := make([]byte, HeaderSize)
	copy(b[0:6], Magic)
	b[6] = h.Version
	b[7] = h.KDFID
	binary.BigEndian.PutUint32(b[8:12], h.Params.MemoryKiB)
	binary.BigEndian.PutUint32(b[12:16], h.Params.Iterations)
	b[16] = h.Params.Parallelism
	b[17] = 0x00 // reserved, MUST be 0x00
	copy(b[18:34], h.Salt[:])
	copy(b[34:46], h.Nonce[:])
	return b
}

// ParseHeader decodes and validates the HeaderSize-byte header prefix
// of b. It verifies the magic and format version, and enforces bounds
// on the KDF parameters before the caller can use them to derive a key
// — a hostile file must not be able to request unbounded memory.
func ParseHeader(b []byte) (Header, error) {
	var h Header
	if len(b) < HeaderSize {
		return h, ErrTruncated
	}
	if string(b[0:6]) != Magic {
		return h, ErrBadMagic
	}
	h.Version = b[6]
	if h.Version != FormatV1 {
		return h, fmt.Errorf("%w: %d", ErrUnsupportedFormat, h.Version)
	}
	h.KDFID = b[7]
	if h.KDFID != KDFArgon2id {
		return h, fmt.Errorf("%w: %d", ErrUnsupportedKDF, h.KDFID)
	}
	h.Params = crypto.Params{
		MemoryKiB:   binary.BigEndian.Uint32(b[8:12]),
		Iterations:  binary.BigEndian.Uint32(b[12:16]),
		Parallelism: b[16],
	}
	if err := h.Params.Validate(); err != nil {
		return Header{}, err
	}
	copy(h.Salt[:], b[18:34])
	copy(h.Nonce[:], b[34:46])
	return h, nil
}
