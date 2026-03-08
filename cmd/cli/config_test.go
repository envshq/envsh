package main

import (
	"testing"
)

func TestLoadConfig_Defaults(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if cfg.ServerURL != "https://api.envsh.dev" {
		t.Errorf("ServerURL = %q, want default %q", cfg.ServerURL, "https://api.envsh.dev")
	}
	if cfg.OutputFormat != "table" {
		t.Errorf("OutputFormat = %q, want %q", cfg.OutputFormat, "table")
	}
}

func TestSaveAndLoadConfig(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	cfg := &Config{
		ServerURL:    "https://custom.server.dev",
		OutputFormat: "json",
	}
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}

	loaded, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if loaded.ServerURL != cfg.ServerURL {
		t.Errorf("ServerURL = %q, want %q", loaded.ServerURL, cfg.ServerURL)
	}
	if loaded.OutputFormat != cfg.OutputFormat {
		t.Errorf("OutputFormat = %q, want %q", loaded.OutputFormat, cfg.OutputFormat)
	}
}

func TestSaveAndLoadConfig_ActiveWorkspace(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	cfg := &Config{
		ServerURL:       "https://api.envsh.dev",
		ActiveWorkspace: "ws-abc123",
		OutputFormat:    "table",
	}
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}

	loaded, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if loaded.ActiveWorkspace != "ws-abc123" {
		t.Errorf("ActiveWorkspace = %q, want %q", loaded.ActiveWorkspace, "ws-abc123")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ServerURL == "" {
		t.Error("DefaultConfig().ServerURL should not be empty")
	}
	if cfg.OutputFormat == "" {
		t.Error("DefaultConfig().OutputFormat should not be empty")
	}
}
