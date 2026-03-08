package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// hkdfSalt is the hardcoded HKDF salt per spec. DO NOT CHANGE.
	hkdfSalt = "envsh-v1"
	// hkdfInfo is the hardcoded HKDF info per spec. DO NOT CHANGE.
	hkdfInfo = "aes-key-wrap"
)

// DeriveAESKey derives a 32-byte AES-256 key from a shared secret using HKDF-SHA256.
//
// Salt and info are hardcoded per spec:
//   - salt = "envsh-v1"
//   - info = "aes-key-wrap"
//
// This function is deterministic: the same sharedSecret always produces the
// same derived key.
func DeriveAESKey(sharedSecret []byte) ([]byte, error) {
	if len(sharedSecret) == 0 {
		return nil, fmt.Errorf("shared secret must not be empty")
	}

	r := hkdf.New(sha256.New, sharedSecret, []byte(hkdfSalt), []byte(hkdfInfo))

	key := make([]byte, AESKeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("deriving AES key via HKDF: %w", err)
	}

	return key, nil
}
