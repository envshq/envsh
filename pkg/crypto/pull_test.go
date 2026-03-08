package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestDecryptRoundTrip(t *testing.T) {
	// Generate Ed25519 keypair
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	fp := ComputeFingerprint(edPub)
	recipient := RecipientKey{
		KeyFingerprint: fp,
		KeyType:        "ed25519",
		PublicKey:      edPub,
	}

	originalPlaintext := []byte("API_KEY=super_secret_value\nDB_PASSWORD=hunter2")

	// Make a copy since EncryptForRecipients zeroes plaintext
	plaintextCopy := make([]byte, len(originalPlaintext))
	copy(plaintextCopy, originalPlaintext)

	bundle, err := EncryptForRecipients(plaintextCopy, []RecipientKey{recipient})
	if err != nil {
		t.Fatalf("EncryptForRecipients() error = %v", err)
	}

	decrypted, err := DecryptWithPrivateKey(bundle, edPriv.Seed(), fp, "ed25519")
	if err != nil {
		t.Fatalf("DecryptWithPrivateKey() error = %v", err)
	}

	if !bytes.Equal(decrypted, originalPlaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, originalPlaintext)
	}
}

func TestDecryptWrongRecipient(t *testing.T) {
	// Generate two Ed25519 keypairs
	edPub1, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	_, edPriv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	fp1 := ComputeFingerprint(edPub1)
	recipient1 := RecipientKey{
		KeyFingerprint: fp1,
		KeyType:        "ed25519",
		PublicKey:      edPub1,
	}

	bundle, err := EncryptForRecipients([]byte("secret"), []RecipientKey{recipient1})
	if err != nil {
		t.Fatalf("EncryptForRecipients() error = %v", err)
	}

	// Try to decrypt with recipient2's key using recipient2's fingerprint
	// (which is not in the bundle)
	edPub2 := edPriv2.Public().(ed25519.PublicKey)
	fp2 := ComputeFingerprint(edPub2)
	_, err = DecryptWithPrivateKey(bundle, edPriv2.Seed(), fp2, "ed25519")
	if !errors.Is(err, ErrNoRecipient) {
		t.Errorf("DecryptWithPrivateKey() with wrong recipient fingerprint: err = %v, want ErrNoRecipient", err)
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	fp := ComputeFingerprint(edPub)
	recipient := RecipientKey{
		KeyFingerprint: fp,
		KeyType:        "ed25519",
		PublicKey:      edPub,
	}

	bundle, err := EncryptForRecipients([]byte("secret data"), []RecipientKey{recipient})
	if err != nil {
		t.Fatalf("EncryptForRecipients() error = %v", err)
	}

	// Tamper with the ciphertext
	if len(bundle.Ciphertext) > 0 {
		bundle.Ciphertext[0] ^= 0xFF
	}

	_, err = DecryptWithPrivateKey(bundle, edPriv.Seed(), fp, "ed25519")
	if err == nil {
		t.Error("DecryptWithPrivateKey() with tampered ciphertext should return error")
	}
}

func TestDecryptChecksumMismatch(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	fp := ComputeFingerprint(edPub)
	recipient := RecipientKey{
		KeyFingerprint: fp,
		KeyType:        "ed25519",
		PublicKey:      edPub,
	}

	bundle, err := EncryptForRecipients([]byte("original"), []RecipientKey{recipient})
	if err != nil {
		t.Fatalf("EncryptForRecipients() error = %v", err)
	}

	// Corrupt the checksum
	bundle.Checksum = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

	_, err = DecryptWithPrivateKey(bundle, edPriv.Seed(), fp, "ed25519")
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Errorf("DecryptWithPrivateKey() with wrong checksum: err = %v, want ErrChecksumMismatch", err)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	// Encrypt for recipient1 but try to decrypt with recipient2's key
	// using recipient1's fingerprint (the entry exists, but wrong key)
	edPub1, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	_, edPriv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	fp1 := ComputeFingerprint(edPub1)
	recipient1 := RecipientKey{
		KeyFingerprint: fp1,
		KeyType:        "ed25519",
		PublicKey:      edPub1,
	}

	bundle, err := EncryptForRecipients([]byte("secret"), []RecipientKey{recipient1})
	if err != nil {
		t.Fatalf("EncryptForRecipients() error = %v", err)
	}

	// Try to decrypt the entry for recipient1 using recipient2's private key
	// This should fail because the ECDH shared secret will be different
	_, err = DecryptWithPrivateKey(bundle, edPriv2.Seed(), fp1, "ed25519")
	if err == nil {
		t.Error("DecryptWithPrivateKey() with wrong key should return error")
	}
}

func TestDecryptMultipleRecipientsEachDecrypts(t *testing.T) {
	const numRecipients = 3
	keys := make([]ed25519.PrivateKey, numRecipients)
	recipients := make([]RecipientKey, numRecipients)
	fingerprints := make([]string, numRecipients)

	for i := 0; i < numRecipients; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519.GenerateKey() error = %v", err)
		}
		keys[i] = priv
		fp := ComputeFingerprint(pub)
		fingerprints[i] = fp
		recipients[i] = RecipientKey{
			KeyFingerprint: fp,
			KeyType:        "ed25519",
			PublicKey:      pub,
		}
	}

	originalPlaintext := []byte("SHARED_SECRET=xyz789")

	// Make a copy for comparison after encryption zeros the original
	plaintextCopy := make([]byte, len(originalPlaintext))
	copy(plaintextCopy, originalPlaintext)

	bundle, err := EncryptForRecipients(plaintextCopy, recipients)
	if err != nil {
		t.Fatalf("EncryptForRecipients() error = %v", err)
	}

	for i, priv := range keys {
		decrypted, err := DecryptWithPrivateKey(bundle, priv.Seed(), fingerprints[i], "ed25519")
		if err != nil {
			t.Errorf("recipient %d DecryptWithPrivateKey() error = %v", i, err)
			continue
		}
		if !bytes.Equal(decrypted, originalPlaintext) {
			t.Errorf("recipient %d: decrypted = %q, want %q", i, decrypted, originalPlaintext)
		}
	}
}
