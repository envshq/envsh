package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

// workspaceCmd shows workspace information.
var workspaceCmd = &cobra.Command{
	Use:   "workspace",
	Short: "Show workspace information",
	RunE:  runWorkspace,
}

// inviteCmd invites a team member.
var inviteCmd = &cobra.Command{
	Use:   "invite EMAIL",
	Short: "Invite a team member to the workspace",
	Args:  cobra.ExactArgs(1),
	RunE:  runInvite,
}

// membersCmd lists workspace members.
var membersCmd = &cobra.Command{
	Use:   "members",
	Short: "List workspace members",
	RunE:  runMembers,
}

// removeCmd removes a team member.
var removeCmd = &cobra.Command{
	Use:   "remove EMAIL",
	Short: "Remove a team member from the workspace",
	Args:  cobra.ExactArgs(1),
	RunE:  runRemoveMember,
}

var inviteRole string

func init() {
	inviteCmd.Flags().StringVar(&inviteRole, "role", "member", "role: admin or member")
	rootCmd.AddCommand(workspaceCmd, inviteCmd, membersCmd, removeCmd)
}

func runWorkspace(cmd *cobra.Command, args []string) error {
	token, err := getToken()
	if err != nil {
		return err
	}
	resp, err := apiRequest("GET", "/workspace", nil, token)
	if err != nil {
		return fmt.Errorf("fetching workspace: %w", err)
	}
	defer resp.Body.Close()
	if err := checkAPIError(resp); err != nil {
		return err
	}
	var ws map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&ws); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	return PrintJSON(ws)
}

func runInvite(cmd *cobra.Command, args []string) error {
	email := args[0]
	token, err := getToken()
	if err != nil {
		return err
	}
	resp, err := apiRequest("POST", "/workspace/members/invite", map[string]string{
		"email": email,
		"role":  inviteRole,
	}, token)
	if err != nil {
		return fmt.Errorf("sending invite: %w", err)
	}
	defer resp.Body.Close()
	if err := checkAPIError(resp); err != nil {
		return err
	}
	PrintSuccess(fmt.Sprintf("Invited %s as %s", email, inviteRole))
	return nil
}

func runMembers(cmd *cobra.Command, args []string) error {
	token, err := getToken()
	if err != nil {
		return err
	}
	resp, err := apiRequest("GET", "/workspace/members", nil, token)
	if err != nil {
		return fmt.Errorf("fetching members: %w", err)
	}
	defer resp.Body.Close()
	if err := checkAPIError(resp); err != nil {
		return err
	}
	var result struct {
		Members []struct {
			ID    string `json:"id"`
			Email string `json:"email"`
			Role  string `json:"role"`
		} `json:"members"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	rows := make([][]string, len(result.Members))
	for i, m := range result.Members {
		rows[i] = []string{m.Email, m.Role, m.ID}
	}
	PrintTable([]string{"EMAIL", "ROLE", "ID"}, rows)
	return nil
}

func runRemoveMember(cmd *cobra.Command, args []string) error {
	email := args[0]
	token, err := getToken()
	if err != nil {
		return err
	}

	// Fetch members to resolve email → user ID.
	resp, err := apiRequest("GET", "/workspace/members", nil, token)
	if err != nil {
		return fmt.Errorf("fetching members: %w", err)
	}
	defer resp.Body.Close()
	if err := checkAPIError(resp); err != nil {
		return err
	}
	var result struct {
		Members []struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"members"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	var userID string
	for _, m := range result.Members {
		if m.Email == email {
			userID = m.ID
			break
		}
	}
	if userID == "" {
		return fmt.Errorf("member %s not found in workspace", email)
	}

	resp2, err := apiRequest("DELETE", "/workspace/members/"+userID, nil, token)
	if err != nil {
		return fmt.Errorf("removing member: %w", err)
	}
	defer resp2.Body.Close()
	if err := checkAPIError(resp2); err != nil {
		return err
	}
	PrintSuccess(fmt.Sprintf("Removed %s from workspace", email))
	return nil
}

// projectCmd groups project management subcommands.
var projectCmd = &cobra.Command{
	Use:   "project",
	Short: "Manage projects",
}

var projectListCmd = &cobra.Command{
	Use:   "list",
	Short: "List projects in the workspace",
	RunE:  runProjectList,
}

var projectCreateCmd = &cobra.Command{
	Use:   "create NAME SLUG",
	Short: "Create a new project",
	Args:  cobra.ExactArgs(2),
	RunE:  runProjectCreate,
}

var projectDeleteCmd = &cobra.Command{
	Use:   "delete PROJECT_ID",
	Short: "Delete a project",
	Args:  cobra.ExactArgs(1),
	RunE:  runProjectDelete,
}

func init() {
	projectCmd.AddCommand(projectListCmd, projectCreateCmd, projectDeleteCmd)
	rootCmd.AddCommand(projectCmd)
}

func runProjectList(cmd *cobra.Command, args []string) error {
	token, err := getToken()
	if err != nil {
		return err
	}
	resp, err := apiRequest("GET", "/projects", nil, token)
	if err != nil {
		return fmt.Errorf("fetching projects: %w", err)
	}
	defer resp.Body.Close()
	if err := checkAPIError(resp); err != nil {
		return err
	}
	var result struct {
		Projects []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Slug string `json:"slug"`
		} `json:"projects"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	rows := make([][]string, len(result.Projects))
	for i, p := range result.Projects {
		rows[i] = []string{p.Name, p.Slug, p.ID}
	}
	PrintTable([]string{"NAME", "SLUG", "ID"}, rows)
	return nil
}

func runProjectCreate(cmd *cobra.Command, args []string) error {
	name, slug := args[0], args[1]
	token, err := getToken()
	if err != nil {
		return err
	}
	resp, err := apiRequest("POST", "/projects", map[string]string{
		"name": name,
		"slug": slug,
	}, token)
	if err != nil {
		return fmt.Errorf("creating project: %w", err)
	}
	defer resp.Body.Close()
	if err := checkAPIError(resp); err != nil {
		return err
	}
	var result struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	PrintSuccess(fmt.Sprintf("Created project %s (slug: %s)", result.Name, result.Slug))
	return nil
}

func runProjectDelete(cmd *cobra.Command, args []string) error {
	projectID := args[0]
	token, err := getToken()
	if err != nil {
		return err
	}
	resp, err := apiRequest("DELETE", "/projects/"+projectID, nil, token)
	if err != nil {
		return fmt.Errorf("deleting project: %w", err)
	}
	defer resp.Body.Close()
	if err := checkAPIError(resp); err != nil {
		return err
	}
	PrintSuccess(fmt.Sprintf("Deleted project %s", projectID))
	return nil
}
