package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run ENV -- COMMAND [ARGS...]",
	Short: "Pull secrets and run a command with them as environment variables",
	Long: `Pull and decrypt secrets for the given project/environment, then execute
a command with those secrets injected as environment variables.

Example:
  envsh run prod --project api -- ./deploy.sh
  envsh run staging --project api -- npm start`,
	Args: cobra.MinimumNArgs(2),
	RunE: runRun,
}

var (
	runProject string
	runKeyPath string
)

func init() {
	runCmd.Flags().StringVar(&runProject, "project", "", "project slug (required)")
	runCmd.Flags().StringVar(&runKeyPath, "key", "", "path to SSH private key")
	_ = runCmd.MarkFlagRequired("project")
	// Stop flag parsing at -- so arguments after -- are passed to the subprocess.
	runCmd.Flags().SetInterspersed(false)
	rootCmd.AddCommand(runCmd)
}

func runRun(cmd *cobra.Command, args []string) error {
	// args[0] is the environment; args[1:] is the command.
	environment := args[0]
	cmdArgs := args[1:]
	if len(cmdArgs) == 0 {
		return fmt.Errorf("usage: envsh run ENV --project SLUG -- COMMAND [ARGS...]")
	}

	token, err := getToken()
	if err != nil {
		return err
	}

	// Pull and decrypt secrets.
	plaintext, _, err := pullDecrypt(token, runProject, environment, runKeyPath)
	if err != nil {
		return err
	}

	// Parse KEY=VALUE pairs from the plaintext.
	secretEnv := parseEnvFile(plaintext)

	// Build the subprocess environment: start with the current process env,
	// then overlay the secret env vars.
	env := os.Environ()
	for k, v := range secretEnv {
		env = append(env, k+"="+v)
	}

	// Execute the command.
	c := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	c.Env = env
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	if err := c.Run(); err != nil {
		// If the command exited with a non-zero status, exit with the same code.
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("running command: %w", err)
	}
	return nil
}

// parseEnvFile parses a .env file and returns a map of KEY → value.
// Supports:
//   - KEY=VALUE
//   - export KEY=VALUE
//   - # comment lines
//   - blank lines
//   - quoted values: KEY="value with spaces" or KEY='value'
func parseEnvFile(data []byte) map[string]string {
	result := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip blank lines and comments.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip "export " prefix.
		line = strings.TrimPrefix(line, "export ")
		// Split on the first =.
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := line[idx+1:]
		// Strip surrounding quotes.
		value = stripQuotes(value)
		if key != "" {
			result[key] = value
		}
	}
	return result
}

// stripQuotes removes surrounding single or double quotes from a string.
func stripQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
