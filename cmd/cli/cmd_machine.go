package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	crypto "github.com/envshq/envsh/pkg/crypto"
)

var machineCmd = &cobra.Command{
	Use:   "machine",
	Short: "Manage machine identities",
}

var machineCreateCmd = &cobra.Command{
	Use:   "create NAME",
	Short: "Create a new machine identity and save its key locally",
	Args:  cobra.ExactArgs(1),
	RunE:  runMachineCreate,
}

var machineListCmd = &cobra.Command{
	Use:   "list",
	Short: "List machines in the workspace",
	RunE:  runMachineList,
}

var machineRevokeCmd = &cobra.Command{
	Use:   "revoke NAME_OR_ID",
	Short: "Revoke a machine identity",
	Args:  cobra.ExactArgs(1),
	RunE:  runMachineRevoke,
}

var (
	machineCreateProject string
	machineCreateEnv     string
)

func init() {
	machineCreateCmd.Flags().StringVar(&machineCreateProject, "project", "", "project slug (required)")
	machineCreateCmd.Flags().StringVar(&machineCreateEnv, "env", "", "environment name (required)")
	_ = machineCreateCmd.MarkFlagRequired("project")
	_ = machineCreateCmd.MarkFlagRequired("env")

	machineCmd.AddCommand(machineCreateCmd, machineListCmd, machineRevokeCmd)
	rootCmd.AddCommand(machineCmd)
}

func runMachineCreate(cmd *cobra.Command, args []string) error {
	name := args[0]

	token, err := getToken()
	if err != nil {
		return err
	}

	// Resolve project ID.
	projectID, err := resolveProjectID(token, machineCreateProject)
	if err != nil {
		return err
	}

	// Generate machine keypair.
	privateKeyStr, publicKey, fingerprint, err := crypto.GenerateMachineKey()
	if err != nil {
		return fmt.Errorf("generating machine key: %w", err)
	}

	// Register the machine on the server.
	resp, err := apiRequest("POST", "/machines", map[string]any{
		"name":            name,
		"project_id":      projectID,
		"environment":     machineCreateEnv,
		"public_key":      base64.StdEncoding.EncodeToString(publicKey),
		"key_fingerprint": fingerprint,
	}, token)
	if err != nil {
		return fmt.Errorf("creating machine: %w", err)
	}
	defer resp.Body.Close()
	if err := checkAPIError(resp); err != nil {
		return err
	}

	var result struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	// Save the private key locally with chmod 600.
	if err := saveMachineKey(name, privateKeyStr); err != nil {
		return fmt.Errorf("saving machine key: %w", err)
	}

	keyPath, keyPathErr := machineKeyPath(name)
	if keyPathErr != nil {
		keyPath = "~/.envsh/machines/" + name
	}
	PrintSuccess(fmt.Sprintf("Created machine %s (ID: %s)", result.Name, result.ID))
	PrintSuccess(fmt.Sprintf("Private key saved to %s", keyPath))
	_, _ = fmt.Printf("\nTo use this machine, set:\n  ENVSH_MACHINE_KEY=%s\n\n", privateKeyStr)
	return nil
}

func runMachineList(cmd *cobra.Command, args []string) error {
	token, err := getToken()
	if err != nil {
		return err
	}
	resp, err := apiRequest("GET", "/machines", nil, token)
	if err != nil {
		return fmt.Errorf("fetching machines: %w", err)
	}
	defer resp.Body.Close()
	if err := checkAPIError(resp); err != nil {
		return err
	}
	var result struct {
		Machines []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Environment string `json:"environment"`
			Status      string `json:"status"`
		} `json:"machines"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	rows := make([][]string, len(result.Machines))
	for i, m := range result.Machines {
		rows[i] = []string{m.Name, m.Environment, m.Status, m.ID}
	}
	PrintTable([]string{"NAME", "ENV", "STATUS", "ID"}, rows)
	return nil
}

func runMachineRevoke(cmd *cobra.Command, args []string) error {
	nameOrID := args[0]
	token, err := getToken()
	if err != nil {
		return err
	}

	// Resolve to machine ID by fetching the list.
	machineID, err := resolveMachineID(token, nameOrID)
	if err != nil {
		return err
	}

	resp, err := apiRequest("DELETE", "/machines/"+machineID, nil, token)
	if err != nil {
		return fmt.Errorf("revoking machine: %w", err)
	}
	defer resp.Body.Close()
	if err := checkAPIError(resp); err != nil {
		return err
	}
	PrintSuccess(fmt.Sprintf("Revoked machine %s", nameOrID))
	return nil
}

// resolveMachineID looks up a machine by name or returns the input if it looks like an ID.
func resolveMachineID(token, nameOrID string) (string, error) {
	resp, err := apiRequest("GET", "/machines", nil, token)
	if err != nil {
		return "", fmt.Errorf("fetching machines: %w", err)
	}
	defer resp.Body.Close()
	if err := checkAPIError(resp); err != nil {
		return "", err
	}
	var result struct {
		Machines []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"machines"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decoding response: %w", err)
	}
	for _, m := range result.Machines {
		if m.Name == nameOrID || m.ID == nameOrID {
			return m.ID, nil
		}
	}
	return "", fmt.Errorf("machine %q not found — list machines with: envsh machine list", nameOrID)
}

// machineKeyPath returns ~/.envsh/machines/{name}.
func machineKeyPath(name string) (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	machinesDir := filepath.Join(dir, "machines")
	if err := os.MkdirAll(machinesDir, 0700); err != nil {
		return "", fmt.Errorf("creating machines directory: %w", err)
	}
	return filepath.Join(machinesDir, name), nil
}

// saveMachineKey writes the machine private key string to ~/.envsh/machines/{name} with chmod 600.
func saveMachineKey(name, privateKeyStr string) error {
	path, err := machineKeyPath(name)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(privateKeyStr+"\n"), 0600)
}
