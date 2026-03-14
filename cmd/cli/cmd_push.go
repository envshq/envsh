package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	crypto "github.com/envshq/envsh/pkg/crypto"
)

var pushCmd = &cobra.Command{
	Use:   "push FILE",
	Short: "Encrypt and push a .env file to envsh",
	Args:  cobra.ExactArgs(1),
	RunE:  runPush,
}

var (
	pushProject string
	pushEnv     string
	pushMessage string
)

func init() {
	pushCmd.Flags().StringVar(&pushProject, "project", "", "project slug (required)")
	pushCmd.Flags().StringVar(&pushEnv, "env", "", "environment name (required)")
	pushCmd.Flags().StringVar(&pushMessage, "message", "", "push message")
	_ = pushCmd.MarkFlagRequired("project")
	_ = pushCmd.MarkFlagRequired("env")
	rootCmd.AddCommand(pushCmd)
}

func runPush(cmd *cobra.Command, args []string) error {
	file := args[0]

	token, err := getToken()
	if err != nil {
		return err
	}

	// Read plaintext.
	plaintext, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("reading file %s: %w", file, err)
	}
	if len(plaintext) > 1024*1024 {
		return fmt.Errorf("file too large: max 1MB")
	}

	// Get workspace members' public keys (recipients).
	recipients, err := fetchRecipientKeys(token)
	if err != nil {
		return fmt.Errorf("fetching recipients: %w", err)
	}
	if len(recipients) == 0 {
		return fmt.Errorf("no registered SSH keys found for workspace members — register a key with: envsh keys add ~/.ssh/id_ed25519.pub")
	}

	// Encrypt.
	bundle, err := crypto.EncryptForRecipients(plaintext, recipients)
	if err != nil {
		return fmt.Errorf("encrypting: %w", err)
	}

	// Resolve project ID.
	projectID, err := resolveProjectID(token, pushProject)
	if err != nil {
		return err
	}

	// Build push request.
	pushReq := buildPushRequest(projectID, pushEnv, bundle, pushMessage)

	// POST /secrets/push.
	resp, err := apiRequest("POST", "/secrets/push", pushReq, token)
	if err != nil {
		return fmt.Errorf("pushing: %w", err)
	}
	defer resp.Body.Close()
	if err := checkAPIError(resp); err != nil {
		return err
	}

	var result struct {
		Version int    `json:"version"`
		ID      string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	PrintSuccess(fmt.Sprintf("Pushed v%d → %s/%s", result.Version, pushProject, pushEnv))
	return nil
}

// getToken returns the active access token or an error if not logged in.
// If ENVSH_MACHINE_KEY is set, performs machine challenge-response auth instead.
func getToken() (string, error) {
	machineKey := os.Getenv("ENVSH_MACHINE_KEY")
	if machineKey != "" {
		return getMachineToken(machineKey)
	}
	td, err := GetActiveToken()
	if err != nil {
		return "", fmt.Errorf("not logged in — run: envsh login")
	}
	return td.AccessToken, nil
}

// fetchRecipientKeys fetches all registered SSH public keys for all workspace members.
func fetchRecipientKeys(token string) ([]crypto.RecipientKey, error) {
	resp, err := apiRequest("GET", "/keys/workspace", nil, token)
	if err != nil {
		return nil, fmt.Errorf("fetching keys: %w", err)
	}
	defer resp.Body.Close()
	if err := checkAPIError(resp); err != nil {
		return nil, err
	}
	var result struct {
		Keys []struct {
			ID          string `json:"id"`
			PublicKey   string `json:"public_key"`
			KeyType     string `json:"key_type"`
			Fingerprint string `json:"fingerprint"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding keys response: %w", err)
	}
	recipients := make([]crypto.RecipientKey, 0, len(result.Keys))
	for _, k := range result.Keys {
		keyType, pubKeyBytes, fp, err := crypto.ParseSSHPublicKey(k.PublicKey)
		if err != nil {
			// Skip keys that cannot be parsed.
			continue
		}
		recipients = append(recipients, crypto.RecipientKey{
			KeyFingerprint: fp,
			KeyType:        keyType,
			PublicKey:      pubKeyBytes,
		})
	}
	return recipients, nil
}

// resolveProjectID fetches the list of projects and returns the ID for the given slug.
func resolveProjectID(token, slug string) (string, error) {
	resp, err := apiRequest("GET", "/projects", nil, token)
	if err != nil {
		return "", fmt.Errorf("fetching projects: %w", err)
	}
	defer resp.Body.Close()
	if err := checkAPIError(resp); err != nil {
		return "", err
	}
	var result struct {
		Projects []struct {
			ID   string `json:"id"`
			Slug string `json:"slug"`
		} `json:"projects"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decoding projects response: %w", err)
	}
	for _, p := range result.Projects {
		if p.Slug == slug {
			return p.ID, nil
		}
	}
	return "", fmt.Errorf("project %q not found — list projects with: envsh project list", slug)
}

// buildPushRequest converts an EncryptedBundle to the API push request body.
func buildPushRequest(projectID, environment string, bundle *crypto.EncryptedBundle, message string) map[string]any {
	recipientsPayload := make([]map[string]any, len(bundle.Recipients))
	for i, r := range bundle.Recipients {
		rec := map[string]any{
			"key_fingerprint":   r.KeyFingerprint,
			"identity_type":     "user",
			"encrypted_aes_key": base64.StdEncoding.EncodeToString(r.EncryptedAESKey),
		}
		if len(r.EphemeralPublic) > 0 {
			rec["ephemeral_public"] = base64.StdEncoding.EncodeToString(r.EphemeralPublic)
			rec["key_nonce"] = base64.StdEncoding.EncodeToString(r.KeyNonce)
			rec["key_auth_tag"] = base64.StdEncoding.EncodeToString(r.KeyAuthTag)
		}
		recipientsPayload[i] = rec
	}
	req := map[string]any{
		"project_id":  projectID,
		"environment": environment,
		"ciphertext":  base64.StdEncoding.EncodeToString(bundle.Ciphertext),
		"nonce":       base64.StdEncoding.EncodeToString(bundle.Nonce),
		"auth_tag":    base64.StdEncoding.EncodeToString(bundle.AuthTag),
		"checksum":    bundle.Checksum,
		"recipients":  recipientsPayload,
	}
	if message != "" {
		req["message"] = message
	}
	return req
}
