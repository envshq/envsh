package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// generateTestEd25519AuthorizedKeyLine generates a fresh Ed25519 key and returns
// the authorized_keys format string and the private key.
func generateTestEd25519AuthorizedKeyLine(t *testing.T, label string) (string, ed25519.PrivateKey) {
	t.Helper()
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	sshPub, err := ssh.NewPublicKey(edPub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey() error = %v", err)
	}
	authorizedLine := string(ssh.MarshalAuthorizedKey(sshPub))
	// Add label
	authorizedLine = strings.TrimSpace(authorizedLine) + " " + label
	return authorizedLine, edPriv
}

func TestParseSSHPublicKey_Ed25519(t *testing.T) {
	authLine, edPriv := generateTestEd25519AuthorizedKeyLine(t, "test-key")

	keyType, pubKey, fingerprint, err := ParseSSHPublicKey(authLine)
	if err != nil {
		t.Fatalf("ParseSSHPublicKey() error = %v", err)
	}

	if keyType != "ed25519" {
		t.Errorf("keyType = %q, want %q", keyType, "ed25519")
	}
	if len(pubKey) != ed25519.PublicKeySize {
		t.Errorf("pubKey length = %d, want %d", len(pubKey), ed25519.PublicKeySize)
	}
	if fingerprint == "" {
		t.Error("fingerprint is empty")
	}

	// Verify the public key matches the private key
	expectedPub := edPriv.Public().(ed25519.PublicKey)
	if !bytes.Equal(pubKey, expectedPub) {
		t.Error("parsed public key does not match the expected public key")
	}
}

func TestParseSSHPublicKey_RSA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping RSA-4096 key generation test in short mode")
	}

	// Generate RSA-4096 key
	rsaKey, err := generateTestRSA4096Key(t)
	if err != nil {
		t.Fatalf("generateTestRSA4096Key() error = %v", err)
	}

	sshPub, err := ssh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey() error = %v", err)
	}
	authLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " test-rsa"

	keyType, pubKey, fingerprint, err := ParseSSHPublicKey(authLine)
	if err != nil {
		t.Fatalf("ParseSSHPublicKey() error = %v", err)
	}

	if keyType != "rsa4096" {
		t.Errorf("keyType = %q, want %q", keyType, "rsa4096")
	}
	if len(pubKey) == 0 {
		t.Error("pubKey is empty")
	}
	if fingerprint == "" {
		t.Error("fingerprint is empty")
	}
}

func TestMachineKeyRoundTrip(t *testing.T) {
	privateKeyString, publicKey, fingerprint, err := GenerateMachineKey()
	if err != nil {
		t.Fatalf("GenerateMachineKey() error = %v", err)
	}

	if !strings.HasPrefix(privateKeyString, "envsh-machine-v1:") {
		t.Errorf("private key string format wrong: %q", privateKeyString)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		t.Errorf("public key length = %d, want %d", len(publicKey), ed25519.PublicKeySize)
	}
	if fingerprint == "" {
		t.Error("fingerprint is empty")
	}

	// Parse back
	seed, err := ParseMachineKey(privateKeyString)
	if err != nil {
		t.Fatalf("ParseMachineKey() error = %v", err)
	}

	if len(seed) != ed25519.SeedSize {
		t.Errorf("seed length = %d, want %d", len(seed), ed25519.SeedSize)
	}

	// Reconstruct the private key from seed and verify the public key matches
	reconstructedPriv := ed25519.NewKeyFromSeed(seed)
	reconstructedPub := reconstructedPriv.Public().(ed25519.PublicKey)

	if !bytes.Equal(reconstructedPub, publicKey) {
		t.Error("reconstructed public key does not match original")
	}

	// Verify fingerprint is consistent
	reconstructedFP := ComputeFingerprint(reconstructedPub)
	if reconstructedFP != fingerprint {
		t.Errorf("fingerprint mismatch: got %q, want %q", reconstructedFP, fingerprint)
	}
}

func TestFingerprintConsistency(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	// Same key always gives same fingerprint
	fp1 := ComputeFingerprint(edPub)
	fp2 := ComputeFingerprint(edPub)
	fp3 := ComputeFingerprint(edPub)

	if fp1 != fp2 || fp2 != fp3 {
		t.Errorf("fingerprints not consistent: %q, %q, %q", fp1, fp2, fp3)
	}

	// Different key gives different fingerprint
	edPub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() second error = %v", err)
	}

	fp4 := ComputeFingerprint(edPub2)
	if fp1 == fp4 {
		t.Error("different keys produced same fingerprint")
	}
}

func TestParseMachineKey_InvalidFormat(t *testing.T) {
	cases := []struct {
		name string
		key  string
	}{
		{"no prefix", "aGVsbG8="},
		{"wrong prefix", "envsh-v1:aGVsbG8="},
		{"invalid base64", "envsh-machine-v1:not-valid-base64!"},
		{"empty", ""},
		{"too short seed", "envsh-machine-v1:aGVsbG8="},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseMachineKey(tc.key)
			if err == nil {
				t.Errorf("ParseMachineKey(%q) should return error", tc.key)
			}
		})
	}
}

func TestParseSSHPublicKey_InvalidKey(t *testing.T) {
	cases := []struct {
		name string
		key  string
	}{
		{"empty", ""},
		{"garbage", "not a valid key"},
		{"partial", "ssh-ed25519"},
		{"unsupported type", "ssh-dss AAAA comment"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := ParseSSHPublicKey(tc.key)
			if err == nil {
				t.Errorf("ParseSSHPublicKey(%q) should return error", tc.key)
			}
		})
	}
}

func TestFingerprintLength(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	fp := ComputeFingerprint(edPub)

	// SHA-256 is 32 bytes = 43 base64 characters (no padding)
	if len(fp) == 0 {
		t.Error("fingerprint is empty")
	}
	// base64 without padding of 32 bytes = ceil(32*4/3) = 43 chars
	if len(fp) != 43 {
		t.Errorf("fingerprint length = %d, want 43", len(fp))
	}
}
