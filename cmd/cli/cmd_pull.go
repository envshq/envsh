package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	crypto "github.com/envshq/envsh/pkg/crypto"
)

var pullCmd = &cobra.Command{
	Use:   "pull ENV",
	Short: "Pull and decrypt secrets from envsh",
	Args:  cobra.ExactArgs(1),
	RunE:  runPull,
}

var (
	pullProject string
	pullOutput  string
	pullFormat  string
	pullStdout  bool
	pullKeyPath string
)

func init() {
	pullCmd.Flags().StringVar(&pullProject, "project", "", "project slug (required)")
	pullCmd.Flags().StringVar(&pullOutput, "output", ".env", "output file path")
	pullCmd.Flags().StringVar(&pullFormat, "format", "env", "output format: env, export, json")
	pullCmd.Flags().BoolVar(&pullStdout, "stdout", false, "print to stdout instead of writing a file")
	pullCmd.Flags().StringVar(&pullKeyPath, "key", "", "path to SSH private key (default: ~/.ssh/id_ed25519)")
	_ = pullCmd.MarkFlagRequired("project")
	rootCmd.AddCommand(pullCmd)
}

func runPull(cmd *cobra.Command, args []string) error {
	environment := args[0]

	token, err := getToken()
	if err != nil {
		return err
	}

	plaintext, version, err := pullDecrypt(token, pullProject, environment, pullKeyPath)
	if err != nil {
		return err
	}

	if pullStdout {
		output, err := formatPlaintext(plaintext, pullFormat)
		if err != nil {
			return err
		}
		_, _ = fmt.Print(output)
		return nil
	}

	if err := os.WriteFile(pullOutput, plaintext, 0600); err != nil {
		return fmt.Errorf("writing output file: %w", err)
	}
	PrintSuccess(fmt.Sprintf("Pulled v%d from %s/%s → %s", version, pullProject, environment, pullOutput))
	return nil
}

// formatPlaintext formats the plaintext env file according to the requested format.
func formatPlaintext(plaintext []byte, format string) (string, error) {
	switch format {
	case "env", "":
		return string(plaintext), nil
	case "export":
		// Prepend "export " to each KEY=VALUE line.
		result := ""
		for _, line := range splitLines(string(plaintext)) {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				result += line + "\n"
				continue
			}
			if strings.Contains(trimmed, "=") && !strings.HasPrefix(trimmed, "export ") {
				result += "export " + trimmed + "\n"
			} else {
				result += line + "\n"
			}
		}
		return result, nil
	case "json":
		env := parseEnvFile(plaintext)
		b, err := json.MarshalIndent(env, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshaling to JSON: %w", err)
		}
		return string(b) + "\n", nil
	default:
		return "", fmt.Errorf("unsupported format %q: use env, export, or json", format)
	}
}

// splitLines splits a string into lines (without trailing newline on each line).
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// pullDecrypt fetches and decrypts the secret bundle for the given project/environment.
// It returns the plaintext and the version number.
func pullDecrypt(token, project, environment, keyPath string) (plaintext []byte, version int, err error) {
	// Resolve project ID.
	// Machine tokens contain project_id in claims — extract directly since
	// machines can't access the human-only GET /projects endpoint.
	var projectID string
	if os.Getenv("ENVSH_MACHINE_KEY") != "" {
		pid, err := extractProjectIDFromToken(token)
		if err != nil {
			return nil, 0, fmt.Errorf("extracting project from machine token: %w", err)
		}
		projectID = pid
	} else {
		pid, err := resolveProjectID(token, project)
		if err != nil {
			return nil, 0, err
		}
		projectID = pid
	}

	// GET /secrets/pull
	path := fmt.Sprintf("/secrets/pull?project_id=%s&environment=%s", projectID, environment)
	resp, err := apiRequest("GET", path, nil, token)
	if err != nil {
		return nil, 0, fmt.Errorf("pulling: %w", err)
	}
	defer resp.Body.Close()
	if err := checkAPIError(resp); err != nil {
		return nil, 0, err
	}

	// Decode JSON response into a structured type.
	type pullResponseRecipient struct {
		KeyFingerprint  string `json:"key_fingerprint"`
		EncryptedAESKey string `json:"encrypted_aes_key"`
		EphemeralPublic string `json:"ephemeral_public"`
		KeyNonce        string `json:"key_nonce"`
		KeyAuthTag      string `json:"key_auth_tag"`
	}
	var bundle struct {
		ID         string                  `json:"id"`
		Version    int                     `json:"version"`
		Ciphertext string                  `json:"ciphertext"`
		Nonce      string                  `json:"nonce"`
		AuthTag    string                  `json:"auth_tag"`
		Checksum   string                  `json:"checksum"`
		Recipients []pullResponseRecipient `json:"recipients"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return nil, 0, fmt.Errorf("decoding response: %w", err)
	}

	// Decode base64 fields.
	dec := func(s string) ([]byte, error) {
		if s == "" {
			return nil, nil
		}
		return base64.StdEncoding.DecodeString(s)
	}
	ct, err := dec(bundle.Ciphertext)
	if err != nil {
		return nil, 0, fmt.Errorf("decoding ciphertext: %w", err)
	}
	nonce, err := dec(bundle.Nonce)
	if err != nil {
		return nil, 0, fmt.Errorf("decoding nonce: %w", err)
	}
	tag, err := dec(bundle.AuthTag)
	if err != nil {
		return nil, 0, fmt.Errorf("decoding auth_tag: %w", err)
	}

	encRecipients := make([]crypto.EncryptedRecipient, len(bundle.Recipients))
	for i, r := range bundle.Recipients {
		encKey, err := dec(r.EncryptedAESKey)
		if err != nil {
			return nil, 0, fmt.Errorf("decoding encrypted_aes_key: %w", err)
		}
		ephPub, err := dec(r.EphemeralPublic)
		if err != nil {
			return nil, 0, fmt.Errorf("decoding ephemeral_public: %w", err)
		}
		kNonce, err := dec(r.KeyNonce)
		if err != nil {
			return nil, 0, fmt.Errorf("decoding key_nonce: %w", err)
		}
		kTag, err := dec(r.KeyAuthTag)
		if err != nil {
			return nil, 0, fmt.Errorf("decoding key_auth_tag: %w", err)
		}
		encRecipients[i] = crypto.EncryptedRecipient{
			KeyFingerprint:  r.KeyFingerprint,
			EncryptedAESKey: encKey,
			EphemeralPublic: ephPub,
			KeyNonce:        kNonce,
			KeyAuthTag:      kTag,
		}
	}

	encBundle := &crypto.EncryptedBundle{
		Ciphertext: ct,
		Nonce:      nonce,
		AuthTag:    tag,
		Checksum:   bundle.Checksum,
		Recipients: encRecipients,
	}

	// Load private key.
	privKeySeed, fingerprint, keyType, err := loadPrivateKey(keyPath)
	if err != nil {
		return nil, 0, fmt.Errorf("loading private key: %w", err)
	}

	// Decrypt.
	pt, err := crypto.DecryptWithPrivateKey(encBundle, privKeySeed, fingerprint, keyType)
	if err != nil {
		return nil, 0, fmt.Errorf("decrypting: %w\n\nhint: ensure your SSH key is registered with: envsh keys list", err)
	}

	return pt, bundle.Version, nil
}

// extractProjectIDFromToken decodes a JWT payload (without verification) to extract the project_id claim.
// Machine tokens embed project_id in their claims, so we can skip the /projects API call.
func extractProjectIDFromToken(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decoding token payload: %w", err)
	}
	var claims struct {
		ProjectID string `json:"project_id"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("parsing token claims: %w", err)
	}
	if claims.ProjectID == "" {
		return "", fmt.Errorf("no project_id in token claims")
	}
	return claims.ProjectID, nil
}

// loadPrivateKey loads an Ed25519 private key seed.
// If ENVSH_MACHINE_KEY is set, uses that. Otherwise reads from keyPath (or default ~/.ssh/id_ed25519).
// Returns the 32-byte seed, the fingerprint, and the key type.
func loadPrivateKey(keyPath string) (seed []byte, fingerprint string, keyType string, err error) {
	// Machine key takes precedence.
	if machineKey := os.Getenv("ENVSH_MACHINE_KEY"); machineKey != "" {
		s, parseErr := crypto.ParseMachineKey(machineKey)
		if parseErr != nil {
			return nil, "", "", fmt.Errorf("parsing machine key: %w", parseErr)
		}
		privKey := ed25519.NewKeyFromSeed(s)
		pubKey := privKey.Public().(ed25519.PublicKey)
		fp := crypto.ComputeFingerprint([]byte(pubKey))
		return s, fp, "ed25519", nil
	}

	if keyPath == "" {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return nil, "", "", fmt.Errorf("finding home directory: %w", homeErr)
		}
		keyPath = filepath.Join(home, ".ssh", "id_ed25519")
	}
	pemData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, "", "", fmt.Errorf("reading key %s: %w", keyPath, err)
	}

	// ParseRawPrivateKey returns the underlying crypto.PrivateKey directly.
	rawKey, err := ssh.ParseRawPrivateKey(pemData)
	if err != nil {
		return nil, "", "", fmt.Errorf("parsing private key: %w", err)
	}

	edPrivPtr, ok := rawKey.(*ed25519.PrivateKey)
	if !ok {
		return nil, "", "", fmt.Errorf("only Ed25519 private keys are supported for pull; got %T", rawKey)
	}

	s := edPrivPtr.Seed() // 32 bytes
	fp := crypto.ComputeFingerprint([]byte(edPrivPtr.Public().(ed25519.PublicKey)))
	return s, fp, "ed25519", nil
}
