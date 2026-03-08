package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

// wrapKeyForRSA encrypts an AES key using RSA-OAEP-SHA256.
func wrapKeyForRSA(pub *rsa.PublicKey, aesKey []byte) ([]byte, error) {
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP encrypt: %w", err)
	}
	return encrypted, nil
}

// unwrapKeyForRSA decrypts an RSA-OAEP encrypted AES key.
func unwrapKeyForRSA(priv *rsa.PrivateKey, encryptedKey []byte) ([]byte, error) {
	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP decrypt: %w", err)
	}
	return key, nil
}
