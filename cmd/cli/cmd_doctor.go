package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	crypto "github.com/envshq/envsh/pkg/crypto"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check your envsh setup",
	RunE:  runDoctor,
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}

func runDoctor(cmd *cobra.Command, args []string) error {
	allOK := true

	check := func(name string, ok bool, hint string) {
		if ok {
			_, _ = fmt.Printf("  ok  %s\n", name)
		} else {
			_, _ = fmt.Printf("  !!  %s\n", name)
			if hint != "" {
				PrintHint(hint)
			}
			allOK = false
		}
	}

	_, _ = fmt.Println("envsh doctor")
	_, _ = fmt.Println()

	// 1. SSH key exists.
	home, homeErr := os.UserHomeDir()
	sshKeyOK := false
	keyPath := ""
	if homeErr == nil {
		keyPath = filepath.Join(home, ".ssh", "id_ed25519.pub")
		if _, err := os.Stat(keyPath); err == nil {
			sshKeyOK = true
		}
	}
	check(
		"SSH key at ~/.ssh/id_ed25519.pub",
		sshKeyOK,
		"Generate one with: ssh-keygen -t ed25519",
	)

	// 2. Credentials file exists.
	credsOK := false
	credsPath, cpErr := credentialsPath()
	if cpErr == nil {
		if _, err := os.Stat(credsPath); err == nil {
			credsOK = true
		}
	}
	check(
		"Credentials file exists",
		credsOK,
		"Log in with: envsh login",
	)

	// 3. Active session token.
	td, tokenErr := GetActiveToken()
	check(
		"Active session token",
		tokenErr == nil,
		"Log in with: envsh login",
	)

	// 4. Server reachable.
	cfg, cfgErr := LoadConfig()
	displayServerURL := "https://api.envsh.dev"
	if cfgErr == nil && cfg.ServerURL != "" {
		displayServerURL = cfg.ServerURL
	}
	serverOK := false
	healthResp, healthErr := http.Get(displayServerURL + "/health")
	if healthErr == nil {
		_ = healthResp.Body.Close()
		serverOK = healthResp.StatusCode == 200
	}
	check(
		"Server reachable at "+displayServerURL,
		serverOK,
		"Check your network or server URL in ~/.envsh/config.json",
	)

	// 5. SSH key registered on server.
	keyRegistered := false
	if tokenErr == nil && sshKeyOK && td != nil {
		pubData, readErr := os.ReadFile(keyPath)
		if readErr == nil {
			_, _, fp, parseErr := crypto.ParseSSHPublicKey(strings.TrimSpace(string(pubData)))
			if parseErr == nil {
				keysResp, keysErr := apiRequest("GET", "/keys", nil, td.AccessToken)
				if keysErr == nil {
					defer keysResp.Body.Close()
					var result struct {
						Keys []struct {
							Fingerprint string `json:"fingerprint"`
						} `json:"keys"`
					}
					if jsonErr := json.NewDecoder(keysResp.Body).Decode(&result); jsonErr == nil {
						for _, k := range result.Keys {
							if k.Fingerprint == fp {
								keyRegistered = true
								break
							}
						}
					}
				}
			}
		}
	}
	check(
		"SSH key registered on server",
		keyRegistered,
		"Register with: envsh keys add ~/.ssh/id_ed25519.pub",
	)

	_, _ = fmt.Println()
	if allOK {
		PrintSuccess("All checks passed")
		return nil
	}
	return fmt.Errorf("some checks failed — see hints above")
}
