# pkg/crypto — Cryptographic Library

Zero-knowledge encryption for envsh. All encryption and decryption happens on the client. The server stores only ciphertext and never has access to keys or plaintext.

## Algorithm Summary

### Push (Encrypt for Recipients)

```
1. Generate random 32-byte AES-256 key  (fresh per push, never reused)
2. Encrypt plaintext with AES-256-GCM   (random 12-byte nonce)
3. Compute SHA-256(plaintext)           (checksum for integrity)
4. Zero plaintext from memory
5. For each recipient SSH public key:
     a. Convert Ed25519 public key → X25519
     b. Generate ephemeral X25519 keypair
     c. ECDH(ephemeral_priv, recipient_x25519_pub) → shared_secret
     d. HKDF-SHA256(shared_secret, salt="envsh-v1", info="aes-key-wrap") → wrapping_key
     e. AES-256-GCM(wrapping_key, aes_key) → encrypted_aes_key
     f. Zero shared_secret and wrapping_key
6. Zero the AES key
7. Upload: ciphertext + nonce + auth_tag + checksum + per-recipient encrypted keys
```

### Pull (Decrypt)

```
1. Download encrypted bundle
2. Find own entry by SSH key fingerprint
3. Convert Ed25519 private key → X25519
4. ECDH(own_x25519_priv, ephemeral_pub) → shared_secret
5. HKDF-SHA256(shared_secret, ...) → wrapping_key
6. AES-256-GCM-decrypt(wrapping_key, encrypted_aes_key) → aes_key
7. Zero shared_secret and wrapping_key
8. AES-256-GCM-decrypt(aes_key, ciphertext) → plaintext
9. Verify SHA-256(plaintext) == checksum
10. Zero aes_key
11. Return plaintext
```

## Key Derivation

HKDF parameters are hardcoded and must never be made configurable:
- **Salt:** `"envsh-v1"` (ASCII bytes)
- **Info:** `"aes-key-wrap"` (ASCII bytes)
- **Output length:** 32 bytes
- **Hash:** SHA-256

## Key Formats

| Key type | Format | Notes |
|----------|--------|-------|
| SSH Ed25519 | OpenSSH `authorized_keys` format | `ssh-ed25519 AAAA... comment` |
| SSH RSA | OpenSSH `authorized_keys` format | `ssh-rsa AAAA... comment` |
| Machine key | `envsh-machine-v1:<base64(32-byte-seed)>` | Ed25519 seed |
| Fingerprint | SHA-256 of raw public key bytes, base64 (no padding) | Used for recipient lookup |

## Memory Safety

Sensitive key material is zeroed after use via `SecureZero`:

- AES-256 keys: zeroed immediately after encryption and decryption
- X25519 private keys and shared secrets: zeroed after ECDH
- HKDF-derived wrapping keys: zeroed after use
- Plaintext: zeroed by `EncryptForRecipients` after the checksum is computed

### Limitations

Go's garbage collector may **copy** heap memory before the slice is zeroed. This means key material could theoretically persist in GC-moved memory regions. Mitigations:

1. Key material is short-lived — typically lives only for the duration of a single push or pull operation
2. `defer SecureZero(key)` is used consistently so zeroing happens even on early returns
3. For deployments requiring OS-level memory locking (e.g., defense against cold-boot attacks), consider wrapping keys in `memguard.LockedBuffer` before passing to these functions

For most threat models (network attackers, server compromise, file-system access), the current zeroing approach is sufficient since:
- No key material is ever written to disk
- Keys are only in RAM for milliseconds
- The server never receives keys in any form

## Constants

| Constant | Value | Meaning |
|----------|-------|---------|
| `AESKeySize` | 32 | bytes — AES-256 |
| `GCMNonceSize` | 12 | bytes — GCM nonce |
| `GCMTagSize` | 16 | bytes — GCM auth tag |

## Errors

| Error | Meaning |
|-------|---------|
| `ErrNoRecipient` | No entry in bundle matches this key fingerprint |
| `ErrChecksumMismatch` | Decryption succeeded but plaintext is corrupted |
| `ErrDecryptFailed` | AES-GCM decryption or key unwrapping failed |

## License

MIT — see root LICENSE file.
