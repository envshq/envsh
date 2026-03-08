package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	// machineKeyPrefix is the prefix for the machine key format.
	machineKeyPrefix = "envsh-machine-v1:"
)

// ParseSSHPublicKey parses an SSH public key string in authorized_keys format
// (e.g., "ssh-ed25519 AAAA... label").
//
// Returns:
//   - keyType: "ed25519" or "rsa4096"
//   - pubKey: raw public key bytes (Ed25519: 32 bytes; RSA: DER-encoded PKIX)
//   - fingerprint: SHA-256 fingerprint (base64, no padding)
//   - err: non-nil if the key cannot be parsed or has an unsupported type
func ParseSSHPublicKey(authorizedKeyLine string) (keyType string, pubKey []byte, fingerprint string, err error) {
	pubKeySSH, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKeyLine))
	if err != nil {
		return "", nil, "", fmt.Errorf("parsing SSH public key: %w", err)
	}

	switch pubKeySSH.Type() {
	case "ssh-ed25519":
		// Extract raw Ed25519 public key bytes from the SSH wire format
		cryptoPub, ok := pubKeySSH.(ssh.CryptoPublicKey)
		if !ok {
			return "", nil, "", fmt.Errorf("SSH key does not implement CryptoPublicKey")
		}
		edPub, ok := cryptoPub.CryptoPublicKey().(ed25519.PublicKey)
		if !ok {
			return "", nil, "", fmt.Errorf("expected Ed25519 public key, got unexpected type")
		}
		rawPub := []byte(edPub)
		fp := ComputeFingerprint(rawPub)
		return "ed25519", rawPub, fp, nil

	case "ssh-rsa":
		// For RSA keys, return DER-encoded PKIX public key
		cryptoPub, ok := pubKeySSH.(ssh.CryptoPublicKey)
		if !ok {
			return "", nil, "", fmt.Errorf("SSH key does not implement CryptoPublicKey")
		}
		rsaPub, ok := cryptoPub.CryptoPublicKey().(*rsa.PublicKey)
		if !ok {
			return "", nil, "", fmt.Errorf("expected RSA public key")
		}

		// Marshal to DER format for consistent handling
		der, err := marshalRSAPublicKeyDER(rsaPub)
		if err != nil {
			return "", nil, "", fmt.Errorf("marshaling RSA public key: %w", err)
		}
		fp := ComputeFingerprint(der)
		return "rsa4096", der, fp, nil

	default:
		return "", nil, "", fmt.Errorf("unsupported key type: %s (supported: ed25519, rsa4096)", pubKeySSH.Type())
	}
}

// ComputeFingerprint returns the SHA-256 fingerprint of raw public key bytes.
// The result is base64-encoded (standard encoding, no padding).
func ComputeFingerprint(pubKey []byte) string {
	hash := sha256.Sum256(pubKey)
	return base64.RawStdEncoding.EncodeToString(hash[:])
}

// GenerateMachineKey generates a new Ed25519 keypair for machine authentication.
//
// Returns:
//   - privateKeyString: formatted as "envsh-machine-v1:<base64(seed)>"
//   - publicKey: raw 32-byte Ed25519 public key
//   - fingerprint: SHA-256 fingerprint of the public key
//   - err: non-nil if key generation fails
func GenerateMachineKey() (privateKeyString string, publicKey []byte, fingerprint string, err error) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, "", fmt.Errorf("generating Ed25519 key: %w", err)
	}

	seed := edPriv.Seed()
	encodedSeed := base64.StdEncoding.EncodeToString(seed)
	privateKeyString = machineKeyPrefix + encodedSeed

	publicKey = []byte(edPub)
	fingerprint = ComputeFingerprint(publicKey)

	return privateKeyString, publicKey, fingerprint, nil
}

// ParseMachineKey extracts the Ed25519 private key seed from a machine key string.
//
// The format is "envsh-machine-v1:<base64(seed)>".
// Returns the 32-byte Ed25519 private key seed.
func ParseMachineKey(keyString string) (privateKey []byte, err error) {
	if !strings.HasPrefix(keyString, machineKeyPrefix) {
		return nil, fmt.Errorf("invalid machine key format: must start with %q", machineKeyPrefix)
	}

	encoded := strings.TrimPrefix(keyString, machineKeyPrefix)
	seed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decoding machine key: %w", err)
	}

	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid machine key: seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}

	return seed, nil
}
