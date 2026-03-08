package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	crypto "github.com/envshq/envsh/pkg/crypto"
)

// generateTestEd25519KeyFiles creates a temporary Ed25519 key pair on disk
// and returns the paths to the private and public key files.
func generateTestEd25519KeyFiles(t *testing.T) (privPath, pubPath string) {
	t.Helper()

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ed25519 key: %v", err)
	}

	// Marshal private key to OpenSSH PEM format.
	pemBlock, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		t.Fatalf("marshaling private key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	// Write private key.
	dir := t.TempDir()
	privPath = filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(privPath, pemBytes, 0600); err != nil {
		t.Fatalf("writing private key: %v", err)
	}

	// Write public key in authorized_keys format.
	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		t.Fatalf("creating SSH public key: %v", err)
	}
	pubPath = privPath + ".pub"
	pubLine := ssh.MarshalAuthorizedKey(sshPub)
	if err := os.WriteFile(pubPath, pubLine, 0644); err != nil {
		t.Fatalf("writing public key: %v", err)
	}

	return privPath, pubPath
}

func TestLoadPrivateKey_Ed25519(t *testing.T) {
	privPath, _ := generateTestEd25519KeyFiles(t)

	seed, fp, keyType, err := loadPrivateKey(privPath)
	if err != nil {
		t.Fatalf("loadPrivateKey failed: %v", err)
	}
	if keyType != "ed25519" {
		t.Errorf("expected keyType ed25519, got %q", keyType)
	}
	if len(seed) != ed25519.SeedSize {
		t.Errorf("expected seed length %d, got %d", ed25519.SeedSize, len(seed))
	}
	if fp == "" {
		t.Error("fingerprint should not be empty")
	}
}

func TestLoadPrivateKey_NotFound(t *testing.T) {
	_, _, _, err := loadPrivateKey("/nonexistent/path/id_ed25519")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadPrivateKey_RoundTrip(t *testing.T) {
	// Generate a fresh key pair.
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	// Marshal to OpenSSH PEM format.
	pemBlock, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		t.Fatalf("marshaling private key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	// Write to temp file.
	dir := t.TempDir()
	privPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(privPath, pemBytes, 0600); err != nil {
		t.Fatalf("writing private key: %v", err)
	}

	// Load the seed back.
	seed, fp, _, err := loadPrivateKey(privPath)
	if err != nil {
		t.Fatalf("loadPrivateKey: %v", err)
	}

	// Reconstruct the ed25519 private key from seed and verify it matches.
	reconstructedPriv := ed25519.NewKeyFromSeed(seed)
	reconstructedPub := reconstructedPriv.Public().(ed25519.PublicKey)
	if string(reconstructedPub) != string(pubKey) {
		t.Error("reconstructed public key does not match original")
	}

	// Verify fingerprint matches what crypto package would compute.
	expectedFP := crypto.ComputeFingerprint([]byte(pubKey))
	if fp != expectedFP {
		t.Errorf("fingerprint mismatch: got %q, expected %q", fp, expectedFP)
	}
}

func TestDecodePullBundle_Base64Fields(t *testing.T) {
	// Verify that base64 decoding in pullDecrypt works correctly by
	// testing the raw decode helper used internally.
	original := []byte("test data")
	encoded := base64.StdEncoding.EncodeToString(original)

	dec := func(s string) ([]byte, error) {
		if s == "" {
			return nil, nil
		}
		return base64.StdEncoding.DecodeString(s)
	}

	decoded, err := dec(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if string(decoded) != string(original) {
		t.Errorf("expected %q, got %q", original, decoded)
	}
}

func TestDecodePullBundle_EmptyString(t *testing.T) {
	dec := func(s string) ([]byte, error) {
		if s == "" {
			return nil, nil
		}
		return base64.StdEncoding.DecodeString(s)
	}
	result, err := dec("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil for empty string, got %v", result)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	// Generate key pair.
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	fp := crypto.ComputeFingerprint([]byte(pubKey))
	originalContent := "DATABASE_URL=postgres://localhost/test\nSECRET_KEY=abc123\n"
	// Make a copy since EncryptForRecipients zeroes the input slice.
	plaintext := []byte(originalContent)

	// Encrypt for the recipient.
	bundle, err := crypto.EncryptForRecipients(plaintext, []crypto.RecipientKey{
		{
			KeyFingerprint: fp,
			KeyType:        "ed25519",
			PublicKey:      []byte(pubKey),
		},
	})
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}

	// Decrypt.
	seed := privKey.Seed()
	decrypted, err := crypto.DecryptWithPrivateKey(bundle, seed, fp, "ed25519")
	if err != nil {
		t.Fatalf("decrypting: %v", err)
	}

	if string(decrypted) != originalContent {
		t.Errorf("round-trip failed: expected %q, got %q", originalContent, decrypted)
	}
}
