package crypto

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// DecryptWithPrivateKey decrypts an EncryptedBundle using an Ed25519 private key.
//
// Algorithm:
//  1. Find the recipient entry matching the given fingerprint
//  2. Convert Ed25519 private key seed to X25519
//  3. Perform ECDH with the ephemeral public key
//  4. HKDF to derive wrapping key
//  5. AES-GCM decrypt the wrapped AES key
//  6. Decrypt the ciphertext with the AES key
//  7. Verify SHA-256(plaintext) == bundle.Checksum
//  8. Zero the AES key
//  9. Return plaintext
//
// privateKey must be the 32-byte Ed25519 private key seed (NOT the 64-byte expanded key).
// fingerprint is used to locate the correct recipient entry in the bundle.
func DecryptWithPrivateKey(bundle *EncryptedBundle, privateKey []byte, fingerprint string, keyType string) ([]byte, error) {
	// Step 1: Find recipient entry
	var recipient *EncryptedRecipient
	for i := range bundle.Recipients {
		if bundle.Recipients[i].KeyFingerprint == fingerprint {
			recipient = &bundle.Recipients[i]
			break
		}
	}
	if recipient == nil {
		return nil, ErrNoRecipient
	}

	switch keyType {
	case "ed25519":
		return decryptWithEd25519(bundle, recipient, privateKey)
	default:
		return nil, fmt.Errorf("unsupported key type for DecryptWithPrivateKey: %s (use DecryptWithRSAPrivateKey for RSA)", keyType)
	}
}

// decryptWithEd25519 performs the Ed25519/X25519 key unwrapping and decryption.
func decryptWithEd25519(bundle *EncryptedBundle, recipient *EncryptedRecipient, edPrivSeed []byte) ([]byte, error) {
	// Convert Ed25519 private key to X25519
	x25519Priv, err := Ed25519ToX25519Private(edPrivSeed)
	if err != nil {
		return nil, fmt.Errorf("%w: converting key: %v", ErrDecryptFailed, err)
	}
	defer SecureZero(x25519Priv)

	// ECDH: x25519Priv × EphemeralPublic → shared secret
	sharedSecret, err := curve25519.X25519(x25519Priv, recipient.EphemeralPublic)
	if err != nil {
		return nil, fmt.Errorf("%w: ECDH: %v", ErrDecryptFailed, err)
	}
	defer SecureZero(sharedSecret)

	// HKDF to derive wrapping key
	wrappingKey, err := DeriveAESKey(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("%w: deriving wrapping key: %v", ErrDecryptFailed, err)
	}
	defer SecureZero(wrappingKey)

	// AES-GCM decrypt the wrapped AES key
	aesKey, err := Decrypt(wrappingKey, recipient.EncryptedAESKey, recipient.KeyNonce, recipient.KeyAuthTag)
	if err != nil {
		return nil, fmt.Errorf("%w: unwrapping AES key: %v", ErrDecryptFailed, err)
	}
	defer SecureZero(aesKey)

	return decryptBundleWithAESKey(bundle, aesKey)
}

// DecryptWithRSAPrivateKey decrypts an EncryptedBundle using an RSA private key.
func DecryptWithRSAPrivateKey(bundle *EncryptedBundle, privateKey *rsa.PrivateKey, fingerprint string) ([]byte, error) {
	// Find recipient entry
	var recipient *EncryptedRecipient
	for i := range bundle.Recipients {
		if bundle.Recipients[i].KeyFingerprint == fingerprint {
			recipient = &bundle.Recipients[i]
			break
		}
	}
	if recipient == nil {
		return nil, ErrNoRecipient
	}

	// RSA-OAEP decrypt the AES key
	aesKey, err := unwrapKeyForRSA(privateKey, recipient.EncryptedAESKey)
	if err != nil {
		return nil, fmt.Errorf("%w: RSA unwrap: %v", ErrDecryptFailed, err)
	}
	defer SecureZero(aesKey)

	return decryptBundleWithAESKey(bundle, aesKey)
}

// decryptBundleWithAESKey decrypts the bundle ciphertext and verifies the checksum.
func decryptBundleWithAESKey(bundle *EncryptedBundle, aesKey []byte) ([]byte, error) {
	// Decrypt ciphertext
	plaintext, err := Decrypt(aesKey, bundle.Ciphertext, bundle.Nonce, bundle.AuthTag)
	if err != nil {
		return nil, fmt.Errorf("%w: decrypting ciphertext: %v", ErrDecryptFailed, err)
	}

	// Verify checksum
	checksumBytes := sha256.Sum256(plaintext)
	actualChecksum := hex.EncodeToString(checksumBytes[:])
	if actualChecksum != bundle.Checksum {
		// Zero any sensitive data before returning error
		SecureZero(plaintext)
		return nil, ErrChecksumMismatch
	}

	return plaintext, nil
}
