package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// generateTestRSA4096Key generates a fresh RSA-4096 key for testing.
// Note: This is slow (~2s). Use testing.Short() to skip when speed matters.
func generateTestRSA4096Key(t *testing.T) (*rsa.PrivateKey, error) {
	t.Helper()
	return rsa.GenerateKey(rand.Reader, 4096)
}
