package main

import (
	"os"
	"testing"
)

func TestLoadCredentials_Empty(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	creds, err := LoadCredentials()
	if err != nil {
		t.Fatalf("LoadCredentials() error = %v", err)
	}
	if len(creds.Tokens) != 0 {
		t.Errorf("expected empty credentials, got %d tokens", len(creds.Tokens))
	}
}

func TestSaveAndLoadCredentials(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	creds := &Credentials{
		Tokens: map[string]*TokenData{
			"ws-123": {
				AccessToken:  "test-token",
				RefreshToken: "test-refresh",
				Email:        "test@example.com",
				WorkspaceID:  "ws-123",
			},
		},
	}
	if err := SaveCredentials(creds); err != nil {
		t.Fatalf("SaveCredentials() error = %v", err)
	}

	// Verify chmod 600.
	path, err := credentialsPath()
	if err != nil {
		t.Fatalf("credentialsPath() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat() error = %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("credentials mode = %o, want 0600", info.Mode().Perm())
	}

	loaded, err := LoadCredentials()
	if err != nil {
		t.Fatalf("LoadCredentials() error = %v", err)
	}
	token := loaded.Tokens["ws-123"]
	if token == nil {
		t.Fatal("expected token ws-123 to be present")
	}
	if token.AccessToken != "test-token" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "test-token")
	}
	if token.RefreshToken != "test-refresh" {
		t.Errorf("RefreshToken = %q, want %q", token.RefreshToken, "test-refresh")
	}
	if token.Email != "test@example.com" {
		t.Errorf("Email = %q, want %q", token.Email, "test@example.com")
	}
}

func TestGetActiveToken_NoCredentials(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	_, err := GetActiveToken()
	if err == nil {
		t.Error("GetActiveToken() should return error when not logged in")
	}
}

func TestGetActiveToken_WithActiveWorkspace(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	// Save config with active workspace.
	cfg := &Config{
		ServerURL:       "https://api.envsh.dev",
		ActiveWorkspace: "ws-456",
		OutputFormat:    "table",
	}
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}

	// Save credentials with two workspaces.
	creds := &Credentials{
		Tokens: map[string]*TokenData{
			"ws-123": {
				AccessToken: "token-123",
				WorkspaceID: "ws-123",
			},
			"ws-456": {
				AccessToken: "token-456",
				WorkspaceID: "ws-456",
			},
		},
	}
	if err := SaveCredentials(creds); err != nil {
		t.Fatalf("SaveCredentials() error = %v", err)
	}

	token, err := GetActiveToken()
	if err != nil {
		t.Fatalf("GetActiveToken() error = %v", err)
	}
	if token.AccessToken != "token-456" {
		t.Errorf("expected active workspace token, got %q", token.AccessToken)
	}
}

func TestGetActiveToken_FallbackToFirst(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	creds := &Credentials{
		Tokens: map[string]*TokenData{
			"ws-999": {
				AccessToken: "token-999",
				WorkspaceID: "ws-999",
			},
		},
	}
	if err := SaveCredentials(creds); err != nil {
		t.Fatalf("SaveCredentials() error = %v", err)
	}

	token, err := GetActiveToken()
	if err != nil {
		t.Fatalf("GetActiveToken() error = %v", err)
	}
	if token.AccessToken != "token-999" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "token-999")
	}
}

func TestSaveCredentials_AtomicWrite(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	creds := &Credentials{
		Tokens: map[string]*TokenData{
			"ws-1": {AccessToken: "tok1"},
		},
	}
	// Write twice to ensure the atomic rename doesn't leave temp files.
	if err := SaveCredentials(creds); err != nil {
		t.Fatalf("first SaveCredentials() error = %v", err)
	}
	creds.Tokens["ws-2"] = &TokenData{AccessToken: "tok2"}
	if err := SaveCredentials(creds); err != nil {
		t.Fatalf("second SaveCredentials() error = %v", err)
	}

	// Temp file should not exist.
	path, _ := credentialsPath()
	tmpPath := path + ".tmp"
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Errorf("temp file %q should not exist after atomic write", tmpPath)
	}

	loaded, err := LoadCredentials()
	if err != nil {
		t.Fatalf("LoadCredentials() error = %v", err)
	}
	if len(loaded.Tokens) != 2 {
		t.Errorf("expected 2 tokens, got %d", len(loaded.Tokens))
	}
}
