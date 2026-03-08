package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Credentials stores auth tokens. The file is chmod 600.
type Credentials struct {
	// Tokens is a map of workspace_id → token data.
	Tokens map[string]*TokenData `json:"tokens"`
}

// TokenData holds the access and refresh tokens for a workspace.
type TokenData struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Email        string `json:"email,omitempty"`
	WorkspaceID  string `json:"workspace_id,omitempty"`
}

// credentialsPath returns ~/.envsh/credentials.
func credentialsPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "credentials"), nil
}

// LoadCredentials reads the credentials file.
// Returns empty Credentials if the file doesn't exist.
func LoadCredentials() (*Credentials, error) {
	path, err := credentialsPath()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return &Credentials{Tokens: make(map[string]*TokenData)}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("opening credentials: %w", err)
	}
	defer f.Close()

	var creds Credentials
	if err := json.NewDecoder(f).Decode(&creds); err != nil {
		return nil, fmt.Errorf("decoding credentials: %w", err)
	}
	if creds.Tokens == nil {
		creds.Tokens = make(map[string]*TokenData)
	}
	return &creds, nil
}

// SaveCredentials writes the credentials file with chmod 600.
func SaveCredentials(creds *Credentials) error {
	path, err := credentialsPath()
	if err != nil {
		return err
	}
	// Write to temp file first, then rename (atomic).
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("creating credentials file: %w", err)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if encErr := enc.Encode(creds); encErr != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("encoding credentials: %w", encErr)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("closing credentials file: %w", err)
	}
	return os.Rename(tmp, path)
}

// GetActiveToken returns the active token, preferring workspace_id from config.
// Falls back to the first token if only one exists.
func GetActiveToken() (*TokenData, error) {
	creds, err := LoadCredentials()
	if err != nil {
		return nil, err
	}
	if len(creds.Tokens) == 0 {
		return nil, fmt.Errorf("not logged in — run: envsh login")
	}
	// Try to get from config's active workspace.
	cfg, err := LoadConfig()
	if err == nil && cfg.ActiveWorkspace != "" {
		if t, ok := creds.Tokens[cfg.ActiveWorkspace]; ok {
			return t, nil
		}
	}
	// Fall back: return the first token.
	for _, t := range creds.Tokens {
		return t, nil
	}
	return nil, fmt.Errorf("not logged in — run: envsh login")
}
