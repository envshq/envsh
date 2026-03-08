package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

// PrintTable prints rows as an aligned table.
// headers is a slice of column names.
// rows is a slice of rows; each row is a slice of string values.
func PrintTable(headers []string, rows [][]string) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, strings.Join(headers, "\t"))
	// Print a separator line.
	seps := make([]string, len(headers))
	for i, h := range headers {
		seps[i] = strings.Repeat("-", len(h))
	}
	_, _ = fmt.Fprintln(w, strings.Join(seps, "\t"))
	for _, row := range rows {
		_, _ = fmt.Fprintln(w, strings.Join(row, "\t"))
	}
	_ = w.Flush()
}

// PrintJSON prints v as indented JSON.
func PrintJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// PrintSuccess prints a success message.
func PrintSuccess(msg string) {
	_, _ = fmt.Printf("ok: %s\n", msg)
}

// PrintError prints an error to stderr.
func PrintError(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "error: %s\n", err.Error())
}

// PrintHint prints an actionable hint to stderr.
func PrintHint(hint string) {
	_, _ = fmt.Fprintf(os.Stderr, "hint: %s\n", hint)
}
