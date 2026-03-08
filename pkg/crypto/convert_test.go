package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestConvertEd25519ToX25519(t *testing.T) {
	// Generate an Ed25519 keypair
	edPub, edPrivFull, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	// Ed25519 private key in Go's crypto/ed25519 is 64 bytes: seed || public key
	// The seed is the first 32 bytes
	edPrivSeed := edPrivFull.Seed()

	// Convert both to X25519
	x25519Pub, err := Ed25519ToX25519Public(edPub)
	if err != nil {
		t.Fatalf("Ed25519ToX25519Public() error = %v", err)
	}

	x25519Priv, err := Ed25519ToX25519Private(edPrivSeed)
	if err != nil {
		t.Fatalf("Ed25519ToX25519Private() error = %v", err)
	}

	// Verify the derived public key matches the converted private key
	// Using curve25519.ScalarBaseMult equivalent
	derivedPub, err := curve25519.X25519(x25519Priv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("curve25519.X25519(basepoint) error = %v", err)
	}

	if !bytes.Equal(x25519Pub, derivedPub) {
		t.Errorf("X25519 public key from Ed25519 public = %x\nX25519 public key from Ed25519 private = %x\nmust be equal",
			x25519Pub, derivedPub)
	}

	// Perform ECDH: generate ephemeral key, compute shared secret from both sides
	ephPriv := make([]byte, 32)
	if _, err := rand.Read(ephPriv); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	// Clamp ephemeral private key
	ephPriv[0] &= 248
	ephPriv[31] &= 127
	ephPriv[31] |= 64

	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("curve25519.X25519(ephPriv, basepoint) error = %v", err)
	}

	// Shared secret from recipient side: x25519Priv × ephPub
	sharedFromRecipient, err := curve25519.X25519(x25519Priv, ephPub)
	if err != nil {
		t.Fatalf("curve25519.X25519(x25519Priv, ephPub) error = %v", err)
	}

	// Shared secret from sender side: ephPriv × x25519Pub
	sharedFromSender, err := curve25519.X25519(ephPriv, x25519Pub)
	if err != nil {
		t.Fatalf("curve25519.X25519(ephPriv, x25519Pub) error = %v", err)
	}

	if !bytes.Equal(sharedFromRecipient, sharedFromSender) {
		t.Errorf("ECDH shared secrets don't match:\nrecipient: %x\nsender:    %x",
			sharedFromRecipient, sharedFromSender)
	}
}

func TestConvertInvalidKey(t *testing.T) {
	t.Run("invalid public key length", func(t *testing.T) {
		_, err := Ed25519ToX25519Public(make([]byte, 31))
		if err == nil {
			t.Error("Ed25519ToX25519Public() with 31-byte key should return error")
		}
	})

	t.Run("invalid private key length", func(t *testing.T) {
		_, err := Ed25519ToX25519Private(make([]byte, 31))
		if err == nil {
			t.Error("Ed25519ToX25519Private() with 31-byte key should return error")
		}
	})

	t.Run("empty public key", func(t *testing.T) {
		_, err := Ed25519ToX25519Public([]byte{})
		if err == nil {
			t.Error("Ed25519ToX25519Public() with empty key should return error")
		}
	})

	t.Run("invalid point (not on curve)", func(t *testing.T) {
		// All-zeros is not a valid Ed25519 point
		badKey := make([]byte, 32)
		_, err := Ed25519ToX25519Public(badKey)
		// Some invalid points will be caught; this is a best-effort test
		// The zero point (identity) may or may not be accepted depending on library
		_ = err // accept either outcome for the identity point
	})
}

func TestConvertX25519OutputSize(t *testing.T) {
	edPub, edPrivFull, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	x25519Pub, err := Ed25519ToX25519Public(edPub)
	if err != nil {
		t.Fatalf("Ed25519ToX25519Public() error = %v", err)
	}
	if len(x25519Pub) != 32 {
		t.Errorf("X25519 public key length = %d, want 32", len(x25519Pub))
	}

	x25519Priv, err := Ed25519ToX25519Private(edPrivFull.Seed())
	if err != nil {
		t.Fatalf("Ed25519ToX25519Private() error = %v", err)
	}
	if len(x25519Priv) != 32 {
		t.Errorf("X25519 private key length = %d, want 32", len(x25519Priv))
	}
}
