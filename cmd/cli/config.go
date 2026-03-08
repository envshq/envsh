package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config holds CLI configuration persisted to ~/.envsh/config.json.
type Config struct {
	ServerURL       string `json:"server_url"`
	ActiveWorkspace string `json:"active_workspace,omitempty"`
	OutputFormat    string `json:"output_format,omitempty"` // "table", "json", "plain"
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		ServerURL:    "https://api.envsh.dev",
		OutputFormat: "table",
	}
}

// configDir returns ~/.envsh, creating it if needed.
func configDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("finding home directory: %w", err)
	}
	dir := filepath.Join(home, ".envsh")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("creating config directory: %w", err)
	}
	return dir, nil
}

// configPath returns the path to config.json.
func configPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// LoadConfig reads the config file. Returns defaults if the file doesn't exist.
func LoadConfig() (*Config, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return DefaultConfig(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("opening config: %w", err)
	}
	defer f.Close()

	var cfg Config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decoding config: %w", err)
	}
	return &cfg, nil
}

// SaveConfig writes the config file.
func SaveConfig(cfg *Config) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating config file: %w", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(cfg)
}
