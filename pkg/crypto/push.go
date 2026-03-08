package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

// RecipientKey represents a public key for a recipient who should be able
// to decrypt the secret.
type RecipientKey struct {
	// KeyFingerprint is the SHA-256 fingerprint of the public key (base64, no padding).
	KeyFingerprint string
	// KeyType is "ed25519" or "rsa4096".
	KeyType string
	// PublicKey is the raw public key bytes (32 bytes for Ed25519, DER for RSA).
	PublicKey []byte
}

// EncryptedRecipient holds the per-recipient encrypted AES key material.
type EncryptedRecipient struct {
	// KeyFingerprint identifies which recipient this entry is for.
	KeyFingerprint string
	// EncryptedAESKey is the AES key wrapped for this recipient.
	EncryptedAESKey []byte
	// EphemeralPublic is the X25519 ephemeral public key (only for ed25519 recipients).
	EphemeralPublic []byte
	// KeyNonce is the nonce used to AES-GCM wrap the AES key (only for ed25519 recipients).
	KeyNonce []byte
	// KeyAuthTag is the auth tag from AES-GCM wrapping (only for ed25519 recipients).
	KeyAuthTag []byte
}

// EncryptedBundle is the result of encrypting plaintext for a set of recipients.
// The bundle contains the ciphertext and per-recipient wrapped keys.
// Recipients can independently decrypt by finding their entry by fingerprint.
type EncryptedBundle struct {
	// Ciphertext is the AES-256-GCM encrypted plaintext.
	Ciphertext []byte
	// Nonce is the 12-byte nonce used for AES-256-GCM encryption.
	Nonce []byte
	// AuthTag is the 16-byte authentication tag from AES-256-GCM.
	AuthTag []byte
	// Checksum is the SHA-256 hash of the plaintext (hex-encoded).
	// Used for integrity verification after decryption.
	Checksum string
	// Recipients contains the per-recipient encrypted AES key entries.
	Recipients []EncryptedRecipient
}

// EncryptForRecipients encrypts plaintext for all given recipients.
//
// Algorithm:
//  1. Generate random 32-byte AES key
//  2. Encrypt plaintext with AES-256-GCM → ciphertext, nonce, authTag
//  3. Compute SHA-256(plaintext) → checksum
//  4. Zero plaintext from memory
//  5. For each recipient, wrap the AES key using their public key
//  6. Zero the AES key
//  7. Return bundle
//
// The AES key is zeroed before returning. The plaintext slice is also
// overwritten with zeros.
func EncryptForRecipients(plaintext []byte, recipients []RecipientKey) (*EncryptedBundle, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("at least one recipient is required")
	}

	// Step 1: Generate random AES-256 key
	aesKey, err := GenerateAESKey()
	if err != nil {
		return nil, fmt.Errorf("generating AES key: %w", err)
	}
	defer SecureZero(aesKey)

	// Step 2: Encrypt plaintext
	ciphertext, nonce, authTag, err := Encrypt(aesKey, plaintext)
	if err != nil {
		return nil, fmt.Errorf("encrypting plaintext: %w", err)
	}

	// Step 3: Compute checksum before zeroing plaintext
	checksumBytes := sha256.Sum256(plaintext)
	checksum := hex.EncodeToString(checksumBytes[:])

	// Step 4: Zero plaintext from memory
	SecureZero(plaintext)

	// Step 5: Wrap AES key for each recipient
	encRecipients := make([]EncryptedRecipient, 0, len(recipients))
	for _, r := range recipients {
		var encR EncryptedRecipient
		encR.KeyFingerprint = r.KeyFingerprint

		switch r.KeyType {
		case "ed25519":
			enc, err := wrapKeyForEd25519(r.PublicKey, aesKey)
			if err != nil {
				return nil, fmt.Errorf("wrapping key for ed25519 recipient %s: %w", r.KeyFingerprint, err)
			}
			encR.EphemeralPublic = enc.EphemeralPublic
			encR.EncryptedAESKey = enc.EncryptedAESKey
			encR.KeyNonce = enc.KeyNonce
			encR.KeyAuthTag = enc.KeyAuthTag

		case "rsa4096":
			rsaPub, err := parseRSAPublicKey(r.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("parsing RSA public key for recipient %s: %w", r.KeyFingerprint, err)
			}
			encAESKey, err := wrapKeyForRSA(rsaPub, aesKey)
			if err != nil {
				return nil, fmt.Errorf("wrapping key for RSA recipient %s: %w", r.KeyFingerprint, err)
			}
			encR.EncryptedAESKey = encAESKey

		default:
			return nil, fmt.Errorf("unsupported key type: %s", r.KeyType)
		}

		encRecipients = append(encRecipients, encR)
	}

	return &EncryptedBundle{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		AuthTag:    authTag,
		Checksum:   checksum,
		Recipients: encRecipients,
	}, nil
}

// wrapKeyForEd25519 wraps an AES key for an Ed25519 public key recipient using ECDH.
func wrapKeyForEd25519(edPub, aesKey []byte) (*EncryptedRecipient, error) {
	// Convert Ed25519 public key to X25519
	x25519RecipientPub, err := Ed25519ToX25519Public(edPub)
	if err != nil {
		return nil, fmt.Errorf("converting Ed25519 to X25519: %w", err)
	}

	// Generate ephemeral X25519 keypair
	ephPriv := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, ephPriv); err != nil {
		return nil, fmt.Errorf("generating ephemeral private key: %w", err)
	}
	defer SecureZero(ephPriv)

	// Clamp the ephemeral private key for X25519
	ephPriv[0] &= 248
	ephPriv[31] &= 127
	ephPriv[31] |= 64

	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("computing ephemeral public key: %w", err)
	}

	// Perform ECDH: ephPriv × recipientPub → shared secret
	sharedSecret, err := curve25519.X25519(ephPriv, x25519RecipientPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH key agreement: %w", err)
	}
	defer SecureZero(sharedSecret)

	// HKDF to derive wrapping key
	wrappingKey, err := DeriveAESKey(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("deriving wrapping key: %w", err)
	}
	defer SecureZero(wrappingKey)

	// AES-GCM wrap the AES key
	encAESKey, keyNonce, keyAuthTag, err := Encrypt(wrappingKey, aesKey)
	if err != nil {
		return nil, fmt.Errorf("wrapping AES key: %w", err)
	}

	return &EncryptedRecipient{
		EphemeralPublic: ephPub,
		EncryptedAESKey: encAESKey,
		KeyNonce:        keyNonce,
		KeyAuthTag:      keyAuthTag,
	}, nil
}
