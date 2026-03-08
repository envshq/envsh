package main

import (
	"strings"
	"testing"
)

func TestFormatPlaintext_EnvFormat(t *testing.T) {
	input := []byte("KEY=value\nOTHER=hello\n")
	out, err := formatPlaintext(input, "env")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != string(input) {
		t.Errorf("expected unchanged output for env format")
	}
}

func TestFormatPlaintext_EmptyFormat(t *testing.T) {
	input := []byte("KEY=value\n")
	out, err := formatPlaintext(input, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != string(input) {
		t.Errorf("expected unchanged output for empty format")
	}
}

func TestFormatPlaintext_ExportFormat(t *testing.T) {
	input := []byte("KEY=value\nOTHER=hello\n")
	out, err := formatPlaintext(input, "export")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "export KEY=value") {
		t.Errorf("expected 'export KEY=value' in output, got: %q", out)
	}
	if !strings.Contains(out, "export OTHER=hello") {
		t.Errorf("expected 'export OTHER=hello' in output, got: %q", out)
	}
}

func TestFormatPlaintext_ExportFormat_PreservesComments(t *testing.T) {
	input := []byte("# comment\nKEY=value\n")
	out, err := formatPlaintext(input, "export")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "# comment") {
		t.Errorf("expected comment to be preserved")
	}
	if !strings.Contains(out, "export KEY=value") {
		t.Errorf("expected 'export KEY=value'")
	}
}

func TestFormatPlaintext_JSONFormat(t *testing.T) {
	input := []byte("KEY=value\nOTHER=hello\n")
	out, err := formatPlaintext(input, "json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, `"KEY"`) {
		t.Errorf("expected KEY in JSON output, got: %q", out)
	}
	if !strings.Contains(out, `"value"`) {
		t.Errorf("expected 'value' in JSON output, got: %q", out)
	}
}

func TestFormatPlaintext_InvalidFormat(t *testing.T) {
	input := []byte("KEY=value\n")
	_, err := formatPlaintext(input, "invalid")
	if err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestSplitLines_Basic(t *testing.T) {
	lines := splitLines("a\nb\nc")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	if lines[0] != "a" || lines[1] != "b" || lines[2] != "c" {
		t.Errorf("unexpected lines: %v", lines)
	}
}

func TestSplitLines_Empty(t *testing.T) {
	lines := splitLines("")
	if len(lines) != 0 {
		t.Errorf("expected 0 lines for empty string, got %d", len(lines))
	}
}

func TestSplitLines_TrailingNewline(t *testing.T) {
	lines := splitLines("a\nb\n")
	// Trailing newline creates an empty last segment which we should not include.
	// Our implementation: after the last \n, start=len(s), so start < len(s) is false.
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %v", len(lines), lines)
	}
}
