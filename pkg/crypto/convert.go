package crypto

import (
	"crypto/sha512"
	"fmt"

	"filippo.io/edwards25519"
)

// Ed25519ToX25519Public converts an Ed25519 public key to an X25519 public key
// for use in ECDH key agreement.
//
// Uses the Ristretto/Montgomery isomorphism described in RFC 7748 and
// RFC 8032 §5.1.5 via filippo.io/edwards25519.
//
// edPub must be exactly 32 bytes (Ed25519 compressed point).
func Ed25519ToX25519Public(edPub []byte) ([]byte, error) {
	if len(edPub) != 32 {
		return nil, fmt.Errorf("Ed25519 public key must be 32 bytes, got %d", len(edPub))
	}

	p, err := new(edwards25519.Point).SetBytes(edPub)
	if err != nil {
		return nil, fmt.Errorf("parsing Ed25519 public key: %w", err)
	}

	return p.BytesMontgomery(), nil
}

// Ed25519ToX25519Private converts an Ed25519 private key seed to an X25519 scalar.
//
// The conversion follows RFC 8032 §5.1.5:
//   - SHA-512 the 32-byte seed
//   - Clamp: bits[0] &= 248, bits[31] &= 127, bits[31] |= 64
//   - Return the first 32 bytes as the X25519 scalar
//
// edPriv must be exactly 32 bytes (Ed25519 seed, NOT the 64-byte expanded key).
func Ed25519ToX25519Private(edPriv []byte) ([]byte, error) {
	if len(edPriv) != 32 {
		return nil, fmt.Errorf("Ed25519 private key seed must be 32 bytes, got %d", len(edPriv))
	}

	// SHA-512 the seed
	h := sha512.Sum512(edPriv)

	// Clamp per RFC 8032 §5.1.5
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64

	// Return the first 32 bytes as the X25519 scalar
	scalar := make([]byte, 32)
	copy(scalar, h[:32])

	return scalar, nil
}
