package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"testing"
)

func makeEd25519RecipientKey(t *testing.T) (RecipientKey, ed25519.PrivateKey) {
	t.Helper()
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	fp := ComputeFingerprint(edPub)
	return RecipientKey{
		KeyFingerprint: fp,
		KeyType:        "ed25519",
		PublicKey:      edPub,
	}, edPriv
}

func makeRSARecipientKey(t *testing.T) (RecipientKey, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	fp := ComputeFingerprint(der)
	return RecipientKey{
		KeyFingerprint: fp,
		KeyType:        "rsa4096",
		PublicKey:      der,
	}, priv
}

func TestEncryptSingleRecipient(t *testing.T) {
	recipient, _ := makeEd25519RecipientKey(t)
	plaintext := []byte("API_KEY=secret123\nDB_URL=postgres://localhost/app")

	bundle, err := EncryptForRecipients(plaintext, []RecipientKey{recipient})
	if err != nil {
		t.Fatalf("EncryptForRecipients() error = %v", err)
	}

	if len(bundle.Ciphertext) == 0 {
		t.Error("bundle.Ciphertext is empty")
	}
	if len(bundle.Nonce) != GCMNonceSize {
		t.Errorf("bundle.Nonce length = %d, want %d", len(bundle.Nonce), GCMNonceSize)
	}
	if len(bundle.AuthTag) != GCMTagSize {
		t.Errorf("bundle.AuthTag length = %d, want %d", len(bundle.AuthTag), GCMTagSize)
	}
	if bundle.Checksum == "" {
		t.Error("bundle.Checksum is empty")
	}
	if len(bundle.Recipients) != 1 {
		t.Errorf("bundle.Recipients length = %d, want 1", len(bundle.Recipients))
	}
	if bundle.Recipients[0].KeyFingerprint != recipient.KeyFingerprint {
		t.Errorf("recipient fingerprint = %s, want %s",
			bundle.Recipients[0].KeyFingerprint, recipient.KeyFingerprint)
	}
	if len(bundle.Recipients[0].EphemeralPublic) != 32 {
		t.Errorf("EphemeralPublic length = %d, want 32", len(bundle.Recipients[0].EphemeralPublic))
	}

}

func TestEncryptMultipleRecipients(t *testing.T) {
	originalPlaintext := []byte("SECRET=value\nANOTHER=secret")
	// Make a copy since EncryptForRecipients zeroes the plaintext
	plaintextCopy := make([]byte, len(originalPlaintext))
	copy(plaintextCopy, originalPlaintext)

	recipient1, priv1 := makeEd25519RecipientKey(t)
	recipient2, priv2 := makeEd25519RecipientKey(t)
	recipient3, priv3 := makeEd25519RecipientKey(t)

	bundle, err := EncryptForRecipients(plaintextCopy, []RecipientKey{recipient1, recipient2, recipient3})
	if err != nil {
		t.Fatalf("EncryptForRecipients() error = %v", err)
	}

	if len(bundle.Recipients) != 3 {
		t.Fatalf("bundle.Recipients length = %d, want 3", len(bundle.Recipients))
	}

	// Each recipient should be able to decrypt independently
	for i, priv := range []ed25519.PrivateKey{priv1, priv2, priv3} {
		decrypted, err := DecryptWithPrivateKey(bundle, priv.Seed(), bundle.Recipients[i].KeyFingerprint, "ed25519")
		if err != nil {
			t.Errorf("recipient %d DecryptWithPrivateKey() error = %v", i+1, err)
			continue
		}
		if !bytes.Equal(decrypted, originalPlaintext) {
			t.Errorf("recipient %d decrypted = %q, want %q", i+1, decrypted, originalPlaintext)
		}
	}
}

func TestEncryptRSARecipient(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping RSA-4096 test in short mode (key generation is slow)")
	}

	recipient, rsaPriv := makeRSARecipientKey(t)
	originalPlaintext := []byte("RSA_SECRET=test_value")

	// Make a copy since EncryptForRecipients zeros plaintext
	plaintextCopy := make([]byte, len(originalPlaintext))
	copy(plaintextCopy, originalPlaintext)

	bundle, err := EncryptForRecipients(plaintextCopy, []RecipientKey{recipient})
	if err != nil {
		t.Fatalf("EncryptForRecipients() error = %v", err)
	}

	if len(bundle.Recipients) != 1 {
		t.Fatalf("bundle.Recipients length = %d, want 1", len(bundle.Recipients))
	}

	// RSA recipients should not have EphemeralPublic
	if len(bundle.Recipients[0].EphemeralPublic) != 0 {
		t.Error("RSA recipient should not have EphemeralPublic set")
	}
	if len(bundle.Recipients[0].EncryptedAESKey) == 0 {
		t.Error("RSA recipient should have EncryptedAESKey set")
	}

	// Decrypt with RSA private key
	decrypted, err := DecryptWithRSAPrivateKey(bundle, rsaPriv, bundle.Recipients[0].KeyFingerprint)
	if err != nil {
		t.Fatalf("DecryptWithRSAPrivateKey() error = %v", err)
	}

	if !bytes.Equal(decrypted, originalPlaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, originalPlaintext)
	}
}

func TestEncryptChecksumFormat(t *testing.T) {
	recipient, _ := makeEd25519RecipientKey(t)
	plaintext := []byte("TEST=value")

	bundle, err := EncryptForRecipients(plaintext, []RecipientKey{recipient})
	if err != nil {
		t.Fatalf("EncryptForRecipients() error = %v", err)
	}

	// Checksum should be 64-character hex string (SHA-256)
	if len(bundle.Checksum) != 64 {
		t.Errorf("Checksum length = %d, want 64 (hex SHA-256)", len(bundle.Checksum))
	}

	// Should be valid hex
	if _, err := hex.DecodeString(bundle.Checksum); err != nil {
		t.Errorf("Checksum is not valid hex: %v", err)
	}
}

func TestEncryptNoRecipients(t *testing.T) {
	_, err := EncryptForRecipients([]byte("secret"), []RecipientKey{})
	if err == nil {
		t.Error("EncryptForRecipients() with no recipients should return error")
	}
}
