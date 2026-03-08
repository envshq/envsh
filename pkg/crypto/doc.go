// Package crypto provides zero-knowledge cryptographic primitives for envsh.
//
// All cryptographic operations happen client-side. The server never sees
// plaintext secrets, private keys, or AES keys.
//
// Key operations:
//   - AES-256-GCM encrypt/decrypt with random 12-byte nonces
//   - Ed25519 to X25519 conversion for ECDH key agreement
//   - HKDF-SHA256 key derivation (salt="envsh-v1", info="aes-key-wrap")
//   - Hybrid encryption for each recipient (Ed25519 or RSA-4096)
//   - SSH public key parsing and fingerprinting
//   - Machine key generation and parsing ("envsh-machine-v1:<base64>")
//
// This package is open source (MIT) and serves as the auditable trust anchor
// for envsh's zero-knowledge security model.
package crypto
