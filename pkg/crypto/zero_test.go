package crypto

import (
	"bytes"
	"runtime"
	"testing"
)

// TestSecureZero verifies that SecureZero overwrites the buffer with zeros.
func TestSecureZero(t *testing.T) {
	key := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
		0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
		0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00}

	SecureZero(key)

	for i, b := range key {
		if b != 0 {
			t.Errorf("SecureZero: byte at index %d is 0x%02X, want 0x00", i, b)
		}
	}
}

// TestSecureZeroAfterGC verifies the buffer is still zeroed after a GC cycle.
// This confirms the zeroing of the original slice header's backing array —
// though it cannot rule out the GC having copied the memory earlier.
func TestSecureZeroAfterGC(t *testing.T) {
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey() error = %v", err)
	}

	// Record a copy to prove the key had real data.
	original := make([]byte, len(key))
	copy(original, key)

	if bytes.Equal(key, make([]byte, len(key))) {
		t.Fatal("GenerateAESKey() returned all-zero key — key generation is broken")
	}

	SecureZero(key)

	// Force a GC cycle.
	runtime.GC()

	// The slice's backing array must be all zeros.
	for i, b := range key {
		if b != 0 {
			t.Errorf("SecureZero: byte at index %d = 0x%02X after GC, want 0x00", i, b)
		}
	}

	// Verify original did have key material.
	if bytes.Equal(original, make([]byte, len(original))) {
		t.Error("original copy was all zeros — key generation produced zero key")
	}
}

// TestEncryptForRecipients_ZeroesPlaintext verifies that EncryptForRecipients
// zeroes the caller's plaintext slice after encrypting.
func TestEncryptForRecipients_ZeroesPlaintext(t *testing.T) {
	// Generate a real Ed25519 key pair for the recipient.
	pubKeyLine := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBKpCDdnnqZZnGOXp95lCFP8cSJJPcYBGSwFjjqgD1EP test@zeroing"
	_, pubKey, fp, err := ParseSSHPublicKey(pubKeyLine)
	if err != nil {
		t.Fatalf("ParseSSHPublicKey error: %v", err)
	}

	plaintext := []byte("SECRET_KEY=hunter2\nDB_PASS=hunter3")
	// Keep a copy to verify the original had content.
	original := make([]byte, len(plaintext))
	copy(original, plaintext)

	recipients := []RecipientKey{{
		KeyFingerprint: fp,
		KeyType:        "ed25519",
		PublicKey:      pubKey,
	}}

	_, err = EncryptForRecipients(plaintext, recipients)
	if err != nil {
		t.Fatalf("EncryptForRecipients() error = %v", err)
	}

	// After encryption, the plaintext slice must be all zeros.
	for i, b := range plaintext {
		if b != 0 {
			t.Errorf("plaintext[%d] = 0x%02X after EncryptForRecipients, want 0x00", i, b)
		}
	}

	// Confirm original had real data.
	if bytes.Equal(original, make([]byte, len(original))) {
		t.Error("original plaintext was all-zero — test is ineffective")
	}
}

// TestSecureZeroEmpty verifies SecureZero handles empty slices without panic.
func TestSecureZeroEmpty(t *testing.T) {
	SecureZero(nil)
	SecureZero([]byte{})
}
