package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	crypto "github.com/envshq/envsh/pkg/crypto"
)

var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Manage SSH keys",
}

var keysAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Register an SSH public key",
	RunE:  runKeysAdd,
}

var keysListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered SSH keys",
	RunE:  runKeysList,
}

var keysRevokeCmd = &cobra.Command{
	Use:   "revoke FINGERPRINT_OR_ID",
	Short: "Revoke an SSH key",
	Args:  cobra.ExactArgs(1),
	RunE:  runKeysRevoke,
}

var (
	keysAddFile  string
	keysAddLabel string
)

func init() {
	keysAddCmd.Flags().StringVar(&keysAddFile, "file", "", "path to SSH public key file (default: ~/.ssh/id_ed25519.pub)")
	keysAddCmd.Flags().StringVar(&keysAddLabel, "name", "", "label for this key")

	keysCmd.AddCommand(keysAddCmd, keysListCmd, keysRevokeCmd)
	rootCmd.AddCommand(keysCmd)
}

func runKeysAdd(cmd *cobra.Command, args []string) error {
	token, err := getToken()
	if err != nil {
		return err
	}

	keyPath := keysAddFile
	if keyPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("finding home directory: %w", err)
		}
		// Try ed25519 first, then RSA.
		candidates := []string{
			home + "/.ssh/id_ed25519.pub",
			home + "/.ssh/id_rsa.pub",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				keyPath = c
				break
			}
		}
	}
	if keyPath == "" {
		return fmt.Errorf("no SSH public key found — specify one with: --file ~/.ssh/id_ed25519.pub")
	}

	data, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("reading key file %s: %w", keyPath, err)
	}

	pubKeyStr := strings.TrimSpace(string(data))

	keyType, _, fingerprint, err := crypto.ParseSSHPublicKey(pubKeyStr)
	if err != nil {
		return fmt.Errorf("parsing SSH key: %w", err)
	}

	label := keysAddLabel
	if label == "" {
		label = keyPath
	}

	resp, err := apiRequest("POST", "/keys", map[string]string{
		"public_key":  pubKeyStr,
		"fingerprint": fingerprint,
		"key_type":    keyType,
		"label":       label,
	}, token)
	if err != nil {
		return fmt.Errorf("registering key: %w", err)
	}
	defer resp.Body.Close()
	if err := checkAPIError(resp); err != nil {
		return err
	}

	var result struct {
		ID          string `json:"id"`
		Fingerprint string `json:"fingerprint"`
		Label       string `json:"label"`
		KeyType     string `json:"key_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	PrintSuccess(fmt.Sprintf("Registered %s key %s (fingerprint: %s)", result.KeyType, result.Label, result.Fingerprint))
	return nil
}

func runKeysList(cmd *cobra.Command, args []string) error {
	token, err := getToken()
	if err != nil {
		return err
	}
	resp, err := apiRequest("GET", "/keys", nil, token)
	if err != nil {
		return fmt.Errorf("fetching keys: %w", err)
	}
	defer resp.Body.Close()
	if err := checkAPIError(resp); err != nil {
		return err
	}
	var result struct {
		Keys []struct {
			ID          string `json:"id"`
			Label       string `json:"label"`
			KeyType     string `json:"key_type"`
			Fingerprint string `json:"fingerprint"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	rows := make([][]string, len(result.Keys))
	for i, k := range result.Keys {
		rows[i] = []string{k.Label, k.KeyType, k.Fingerprint, k.ID}
	}
	PrintTable([]string{"LABEL", "TYPE", "FINGERPRINT", "ID"}, rows)
	return nil
}

func runKeysRevoke(cmd *cobra.Command, args []string) error {
	fingerprintOrID := args[0]
	token, err := getToken()
	if err != nil {
		return err
	}

	// Resolve to key ID by fetching the list.
	keyID, err := resolveKeyID(token, fingerprintOrID)
	if err != nil {
		return err
	}

	resp, err := apiRequest("DELETE", "/keys/"+keyID, nil, token)
	if err != nil {
		return fmt.Errorf("revoking key: %w", err)
	}
	defer resp.Body.Close()
	if err := checkAPIError(resp); err != nil {
		return err
	}
	PrintSuccess(fmt.Sprintf("Revoked key %s", fingerprintOrID))
	return nil
}

// resolveKeyID returns the key ID for a given fingerprint or ID.
func resolveKeyID(token, fingerprintOrID string) (string, error) {
	resp, err := apiRequest("GET", "/keys", nil, token)
	if err != nil {
		return "", fmt.Errorf("fetching keys: %w", err)
	}
	defer resp.Body.Close()
	if err := checkAPIError(resp); err != nil {
		return "", err
	}
	var result struct {
		Keys []struct {
			ID          string `json:"id"`
			Fingerprint string `json:"fingerprint"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decoding response: %w", err)
	}
	for _, k := range result.Keys {
		if k.Fingerprint == fingerprintOrID || k.ID == fingerprintOrID {
			return k.ID, nil
		}
	}
	return "", fmt.Errorf("key %q not found — list keys with: envsh keys list", fingerprintOrID)
}
