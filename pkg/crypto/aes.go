package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

const (
	// AESKeySize is the required key size for AES-256.
	AESKeySize = 32
	// GCMNonceSize is the standard 12-byte nonce for AES-GCM.
	GCMNonceSize = 12
	// GCMTagSize is the standard 16-byte auth tag for AES-GCM.
	GCMTagSize = 16
)

// GenerateAESKey generates a fresh random 32-byte AES-256 key.
// Always use a new key for each push — never reuse keys.
func GenerateAESKey() ([]byte, error) {
	key := make([]byte, AESKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generating AES key: %w", err)
	}
	return key, nil
}

// Encrypt encrypts plaintext with AES-256-GCM.
//
// Returns (ciphertext, nonce, authTag, error).
// The nonce is always a fresh random 12 bytes — never counter-based.
// The authTag is 16 bytes and is separated from the ciphertext.
//
// key must be exactly 32 bytes (AES-256).
func Encrypt(key, plaintext []byte) (ciphertext, nonce, authTag []byte, err error) {
	if len(key) != AESKeySize {
		return nil, nil, nil, fmt.Errorf("AES key must be %d bytes, got %d", AESKeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating GCM: %w", err)
	}

	// Generate random 12-byte nonce — NEVER counter-based
	nonce = make([]byte, GCMNonceSize)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("generating nonce: %w", err)
	}

	// Seal produces ciphertext || authTag
	sealed := gcm.Seal(nil, nonce, plaintext, nil)

	// Split ciphertext and authTag
	tagOffset := len(sealed) - GCMTagSize
	ciphertext = sealed[:tagOffset]
	authTag = sealed[tagOffset:]

	return ciphertext, nonce, authTag, nil
}

// Decrypt decrypts ciphertext with AES-256-GCM.
//
// Returns plaintext or error (including auth tag mismatch).
// The auth tag is always verified — partial plaintext is never returned on failure.
//
// key must be exactly 32 bytes (AES-256).
func Decrypt(key, ciphertext, nonce, authTag []byte) ([]byte, error) {
	if len(key) != AESKeySize {
		return nil, fmt.Errorf("AES key must be %d bytes, got %d", AESKeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	// Reconstruct ciphertext || authTag for GCM.Open
	combined := make([]byte, len(ciphertext)+len(authTag))
	copy(combined, ciphertext)
	copy(combined[len(ciphertext):], authTag)

	plaintext, err := gcm.Open(nil, nonce, combined, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	return plaintext, nil
}
