package crypto

import (
	"bytes"
	"testing"
)

func TestKDFDeterministic(t *testing.T) {
	sharedSecret := []byte("this-is-a-32-byte-shared-secret!")

	key1, err := DeriveAESKey(sharedSecret)
	if err != nil {
		t.Fatalf("DeriveAESKey() first call error = %v", err)
	}

	key2, err := DeriveAESKey(sharedSecret)
	if err != nil {
		t.Fatalf("DeriveAESKey() second call error = %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Error("DeriveAESKey() is not deterministic: same input produced different output")
	}
}

func TestKDFDifferentInput(t *testing.T) {
	secret1 := []byte("shared-secret-one-32-bytes-exact")
	secret2 := []byte("shared-secret-two-32-bytes-exact")

	key1, err := DeriveAESKey(secret1)
	if err != nil {
		t.Fatalf("DeriveAESKey(secret1) error = %v", err)
	}

	key2, err := DeriveAESKey(secret2)
	if err != nil {
		t.Fatalf("DeriveAESKey(secret2) error = %v", err)
	}

	if bytes.Equal(key1, key2) {
		t.Error("DeriveAESKey() with different inputs produced same output")
	}
}

func TestKDFOutputLength(t *testing.T) {
	sharedSecret := []byte("any-shared-secret-value-here")

	key, err := DeriveAESKey(sharedSecret)
	if err != nil {
		t.Fatalf("DeriveAESKey() error = %v", err)
	}

	if len(key) != AESKeySize {
		t.Errorf("DeriveAESKey() output length = %d, want %d", len(key), AESKeySize)
	}
}

func TestKDFEmptySecret(t *testing.T) {
	_, err := DeriveAESKey([]byte{})
	if err == nil {
		t.Error("DeriveAESKey() with empty secret should return error")
	}
}

func TestKDFNotAllZeros(t *testing.T) {
	sharedSecret := []byte("test-shared-secret")

	key, err := DeriveAESKey(sharedSecret)
	if err != nil {
		t.Fatalf("DeriveAESKey() error = %v", err)
	}

	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("DeriveAESKey() produced all-zero key")
	}
}
