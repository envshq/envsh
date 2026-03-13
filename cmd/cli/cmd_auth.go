package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	crypto "github.com/envshq/envsh/pkg/crypto"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Log in to envsh with your email",
	RunE:  runLogin,
}

var loginEmail string

func init() {
	loginCmd.Flags().StringVar(&loginEmail, "email", "", "email address")
	rootCmd.AddCommand(loginCmd)
}

func runLogin(cmd *cobra.Command, args []string) error {
	// 1. Get email.
	email := loginEmail
	if email == "" {
		_, _ = fmt.Print("Email: ")
		if _, err := fmt.Scanln(&email); err != nil {
			return fmt.Errorf("reading email: %w", err)
		}
	}
	if email == "" {
		return fmt.Errorf("email is required")
	}

	// 2. Request code.
	resp, err := apiRequest("POST", "/auth/email-login", map[string]string{"email": email}, "")
	if err != nil {
		return fmt.Errorf("requesting code: %w", err)
	}
	defer resp.Body.Close()
	if err := checkAPIError(resp); err != nil {
		return err
	}
	_, _ = fmt.Println("Code sent to your email.")

	// 3. Read code.
	var code string
	_, _ = fmt.Print("Code: ")
	if _, err := fmt.Scanln(&code); err != nil {
		return fmt.Errorf("reading code: %w", err)
	}
	if code == "" {
		return fmt.Errorf("code is required")
	}

	// 4. Verify code.
	var verifyResp struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
		User         struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"user"`
		Workspace struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Slug string `json:"slug"`
		} `json:"workspace"`
	}
	resp2, err := apiRequest("POST", "/auth/email-verify", map[string]string{
		"email": email,
		"code":  code,
	}, "")
	if err != nil {
		return fmt.Errorf("verifying code: %w", err)
	}
	defer resp2.Body.Close()
	if err := checkAPIError(resp2); err != nil {
		return err
	}
	if err := json.NewDecoder(resp2.Body).Decode(&verifyResp); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	// 5. Save credentials.
	creds, err := LoadCredentials()
	if err != nil {
		creds = &Credentials{Tokens: make(map[string]*TokenData)}
	}
	wsID := verifyResp.Workspace.ID
	creds.Tokens[wsID] = &TokenData{
		AccessToken:  verifyResp.Token,
		RefreshToken: verifyResp.RefreshToken,
		Email:        verifyResp.User.Email,
		WorkspaceID:  wsID,
	}
	if err := SaveCredentials(creds); err != nil {
		return fmt.Errorf("saving credentials: %w", err)
	}

	// 6. Save active workspace to config.
	cfg, err := LoadConfig()
	if err != nil {
		cfg = DefaultConfig()
	}
	cfg.ActiveWorkspace = wsID
	_ = SaveConfig(cfg)

	PrintSuccess(fmt.Sprintf("Logged in as %s", verifyResp.User.Email))

	// 7. Register SSH key (best-effort — don't fail login if this fails).
	_ = registerDefaultSSHKey(verifyResp.Token)

	return nil
}

// registerDefaultSSHKey auto-detects and registers the user's SSH public key.
func registerDefaultSSHKey(token string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("finding home directory: %w", err)
	}
	candidates := []string{
		filepath.Join(home, ".ssh", "id_ed25519.pub"),
		filepath.Join(home, ".ssh", "id_rsa.pub"),
	}
	for _, keyPath := range candidates {
		data, err := os.ReadFile(keyPath)
		if err != nil {
			continue
		}
		pubKeyStr := strings.TrimSpace(string(data))
		keyType, _, fingerprint, err := crypto.ParseSSHPublicKey(pubKeyStr)
		if err != nil {
			continue
		}
		resp, err := apiRequest("POST", "/keys", map[string]string{
			"public_key":  pubKeyStr,
			"fingerprint": fingerprint,
			"key_type":    keyType,
			"label":       "default",
		}, token)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode < 400 {
			PrintSuccess(fmt.Sprintf("SSH key registered from %s", keyPath))
		}
		return nil
	}
	PrintHint("No SSH key found. Register one with: envsh keys add ~/.ssh/id_ed25519.pub")
	return nil
}

// logoutCmd revokes the refresh token and clears local credentials.
var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Log out of envsh",
	RunE:  runLogout,
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}

func runLogout(cmd *cobra.Command, args []string) error {
	td, err := GetActiveToken()
	if err != nil {
		return fmt.Errorf("not logged in — run: envsh login")
	}

	// Attempt to revoke refresh token on server (best-effort).
	resp, err := apiRequest("POST", "/auth/logout", map[string]string{
		"refresh_token": td.RefreshToken,
	}, td.AccessToken)
	if err == nil {
		_ = resp.Body.Close()
	}

	// Clear local credentials.
	cfg, err := LoadConfig()
	if err != nil {
		cfg = DefaultConfig()
	}
	wsID := cfg.ActiveWorkspace
	creds, err := LoadCredentials()
	if err != nil {
		creds = &Credentials{Tokens: make(map[string]*TokenData)}
	}
	if wsID != "" {
		delete(creds.Tokens, wsID)
	}
	if err := SaveCredentials(creds); err != nil {
		return fmt.Errorf("clearing credentials: %w", err)
	}
	cfg.ActiveWorkspace = ""
	_ = SaveConfig(cfg)

	PrintSuccess("Logged out")
	return nil
}
