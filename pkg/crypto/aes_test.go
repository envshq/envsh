package crypto

import (
	"bytes"
	"testing"
)

func TestAESEncryptDecrypt(t *testing.T) {
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey() error = %v", err)
	}
	defer SecureZero(key)

	plaintext := []byte("DATABASE_URL=postgres://user:pass@localhost/envsh\nREDIS_URL=redis://localhost:6379")

	ciphertext, nonce, authTag, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if len(ciphertext) == 0 {
		t.Error("Encrypt() returned empty ciphertext")
	}
	if len(nonce) != GCMNonceSize {
		t.Errorf("nonce length = %d, want %d", len(nonce), GCMNonceSize)
	}
	if len(authTag) != GCMTagSize {
		t.Errorf("authTag length = %d, want %d", len(authTag), GCMTagSize)
	}

	decrypted, err := Decrypt(key, ciphertext, nonce, authTag)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypt() = %q, want %q", decrypted, plaintext)
	}
}

func TestAESTamperedAuthTag(t *testing.T) {
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey() error = %v", err)
	}
	defer SecureZero(key)

	ciphertext, nonce, authTag, err := Encrypt(key, []byte("secret data"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Tamper with the auth tag
	tampered := make([]byte, len(authTag))
	copy(tampered, authTag)
	tampered[0] ^= 0xFF

	_, err = Decrypt(key, ciphertext, nonce, tampered)
	if err == nil {
		t.Error("Decrypt() with tampered auth tag should return error, got nil")
	}
}

func TestAESTamperedCiphertext(t *testing.T) {
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey() error = %v", err)
	}
	defer SecureZero(key)

	plaintext := []byte("secret data")
	ciphertext, nonce, authTag, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Tamper with the ciphertext
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[0] ^= 0xFF

	_, err = Decrypt(key, tampered, nonce, authTag)
	if err == nil {
		t.Error("Decrypt() with tampered ciphertext should return error, got nil")
	}
}

func TestAESEmptyPlaintext(t *testing.T) {
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey() error = %v", err)
	}
	defer SecureZero(key)

	// Zero-length plaintext must work
	ciphertext, nonce, authTag, err := Encrypt(key, []byte{})
	if err != nil {
		t.Fatalf("Encrypt() with empty plaintext error = %v", err)
	}

	decrypted, err := Decrypt(key, ciphertext, nonce, authTag)
	if err != nil {
		t.Fatalf("Decrypt() with empty plaintext error = %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("Decrypt() of empty plaintext = %v, want empty", decrypted)
	}
}

func TestAESWrongKeySize(t *testing.T) {
	// Non-32-byte key must return error
	cases := []struct {
		name string
		key  []byte
	}{
		{"16-byte key", make([]byte, 16)},
		{"24-byte key", make([]byte, 24)},
		{"31-byte key", make([]byte, 31)},
		{"33-byte key", make([]byte, 33)},
		{"empty key", []byte{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := Encrypt(tc.key, []byte("test"))
			if err == nil {
				t.Errorf("Encrypt() with %s should return error, got nil", tc.name)
			}

			// Also test decrypt with wrong key size
			_, err = Decrypt(tc.key, []byte("ciphertext"), make([]byte, 12), make([]byte, 16))
			if err == nil {
				t.Errorf("Decrypt() with %s should return error, got nil", tc.name)
			}
		})
	}
}

func TestAESNonceIsRandom(t *testing.T) {
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey() error = %v", err)
	}
	defer SecureZero(key)

	plaintext := []byte("test")

	// Encrypt same plaintext twice — nonces must differ
	_, nonce1, _, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("first Encrypt() error = %v", err)
	}

	_, nonce2, _, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("second Encrypt() error = %v", err)
	}

	if bytes.Equal(nonce1, nonce2) {
		t.Error("two encryptions produced the same nonce — nonces must be random")
	}
}

func TestAESWrongKey(t *testing.T) {
	key1, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey() error = %v", err)
	}
	defer SecureZero(key1)

	key2, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey() error = %v", err)
	}
	defer SecureZero(key2)

	ciphertext, nonce, authTag, err := Encrypt(key1, []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	_, err = Decrypt(key2, ciphertext, nonce, authTag)
	if err == nil {
		t.Error("Decrypt() with wrong key should return error, got nil")
	}
}

func TestGenerateAESKey(t *testing.T) {
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey() error = %v", err)
	}

	if len(key) != AESKeySize {
		t.Errorf("GenerateAESKey() length = %d, want %d", len(key), AESKeySize)
	}

	// Two keys must not be equal (astronomically unlikely)
	key2, _ := GenerateAESKey()
	if bytes.Equal(key, key2) {
		t.Error("two generated AES keys are identical — should be random")
	}
}
