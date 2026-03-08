package crypto

import "errors"

// ErrNoRecipient is returned when no recipient entry is found for the given key fingerprint.
var ErrNoRecipient = errors.New("no recipient entry for this key")

// ErrChecksumMismatch is returned when the decrypted plaintext's SHA-256 checksum
// does not match the stored checksum. This indicates data corruption.
var ErrChecksumMismatch = errors.New("checksum mismatch: data may be corrupted")

// ErrDecryptFailed is returned when decryption fails (wrong key, corrupted data, etc.).
var ErrDecryptFailed = errors.New("decryption failed")
