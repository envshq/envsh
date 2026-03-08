package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "View the workspace audit log",
	RunE:  runAudit,
}

var auditLimit int

func init() {
	auditCmd.Flags().IntVar(&auditLimit, "limit", 50, "maximum number of audit entries to show")
	rootCmd.AddCommand(auditCmd)
}

func runAudit(cmd *cobra.Command, args []string) error {
	token, err := getToken()
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/audit?limit=%d", auditLimit)
	resp, err := apiRequest("GET", path, nil, token)
	if err != nil {
		return fmt.Errorf("fetching audit log: %w", err)
	}
	defer resp.Body.Close()
	if err := checkAPIError(resp); err != nil {
		return err
	}
	var result struct {
		Entries []struct {
			ID         string `json:"id"`
			ActorType  string `json:"actor_type"`
			ActorID    string `json:"actor_id"`
			Action     string `json:"action"`
			IPAddress  string `json:"ip_address"`
			CreatedAt  string `json:"created_at"`
		} `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	rows := make([][]string, len(result.Entries))
	for i, e := range result.Entries {
		rows[i] = []string{e.CreatedAt, e.Action, e.ActorType, e.ActorID, e.IPAddress}
	}
	PrintTable([]string{"TIME", "ACTION", "ACTOR_TYPE", "ACTOR_ID", "IP"}, rows)
	return nil
}

// versionsCmd shows version history for an environment.
var versionsCmd = &cobra.Command{
	Use:   "versions ENV",
	Short: "Show version history for a project environment",
	Args:  cobra.ExactArgs(1),
	RunE:  runVersions,
}

var (
	versionsProject string
	versionsLimit   int
)

func init() {
	versionsCmd.Flags().StringVar(&versionsProject, "project", "", "project slug (required)")
	versionsCmd.Flags().IntVar(&versionsLimit, "limit", 20, "maximum number of versions to show")
	_ = versionsCmd.MarkFlagRequired("project")
	rootCmd.AddCommand(versionsCmd)
}

func runVersions(cmd *cobra.Command, args []string) error {
	environment := args[0]
	token, err := getToken()
	if err != nil {
		return err
	}

	projectID, err := resolveProjectID(token, versionsProject)
	if err != nil {
		return err
	}

	path := fmt.Sprintf("/secrets/list?project_id=%s&environment=%s&limit=%d",
		projectID, environment, versionsLimit)
	resp, err := apiRequest("GET", path, nil, token)
	if err != nil {
		return fmt.Errorf("fetching versions: %w", err)
	}
	defer resp.Body.Close()
	if err := checkAPIError(resp); err != nil {
		return err
	}
	var result struct {
		Versions []struct {
			ID          string `json:"id"`
			Version     int    `json:"version"`
			PushMessage string `json:"push_message"`
			PushedBy    string `json:"pushed_by"`
			CreatedAt   string `json:"created_at"`
		} `json:"versions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	rows := make([][]string, len(result.Versions))
	for i, v := range result.Versions {
		rows[i] = []string{
			fmt.Sprintf("v%d", v.Version),
			v.CreatedAt,
			v.PushMessage,
			v.PushedBy,
		}
	}
	PrintTable([]string{"VERSION", "CREATED", "MESSAGE", "PUSHED_BY"}, rows)
	return nil
}
