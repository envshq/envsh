package crypto

// SecureZero overwrites b with zeros to remove sensitive key material from memory.
//
// Note: Go's garbage collector may have already copied the memory to other locations.
// This is best-effort memory safety. For stronger guarantees, use a memory-locked
// allocator (e.g., memguard) in security-critical deployments.
//
// Always call SecureZero on AES keys, shared secrets, and private key material
// after use.
func SecureZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
