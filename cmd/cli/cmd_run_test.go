package main

import (
	"testing"
)

func TestParseEnvFile_BasicKeyValue(t *testing.T) {
	input := []byte("KEY=value\nANOTHER=123\n")
	got := parseEnvFile(input)
	if got["KEY"] != "value" {
		t.Errorf("expected KEY=value, got %q", got["KEY"])
	}
	if got["ANOTHER"] != "123" {
		t.Errorf("expected ANOTHER=123, got %q", got["ANOTHER"])
	}
}

func TestParseEnvFile_CommentsAndBlankLines(t *testing.T) {
	input := []byte("# This is a comment\n\nKEY=value\n\n# Another comment\nOTHER=hello\n")
	got := parseEnvFile(input)
	if _, ok := got["# This is a comment"]; ok {
		t.Error("comment line should not be parsed as key")
	}
	if got["KEY"] != "value" {
		t.Errorf("expected KEY=value, got %q", got["KEY"])
	}
	if got["OTHER"] != "hello" {
		t.Errorf("expected OTHER=hello, got %q", got["OTHER"])
	}
}

func TestParseEnvFile_ExportPrefix(t *testing.T) {
	input := []byte("export DATABASE_URL=postgres://localhost/mydb\nexport PORT=5432\n")
	got := parseEnvFile(input)
	if got["DATABASE_URL"] != "postgres://localhost/mydb" {
		t.Errorf("unexpected value for DATABASE_URL: %q", got["DATABASE_URL"])
	}
	if got["PORT"] != "5432" {
		t.Errorf("unexpected value for PORT: %q", got["PORT"])
	}
}

func TestParseEnvFile_QuotedValues(t *testing.T) {
	input := []byte(`KEY="hello world"
OTHER='single quoted'
`)
	got := parseEnvFile(input)
	if got["KEY"] != "hello world" {
		t.Errorf("expected 'hello world', got %q", got["KEY"])
	}
	if got["OTHER"] != "single quoted" {
		t.Errorf("expected 'single quoted', got %q", got["OTHER"])
	}
}

func TestParseEnvFile_EmptyValue(t *testing.T) {
	input := []byte("EMPTY=\n")
	got := parseEnvFile(input)
	if v, ok := got["EMPTY"]; !ok {
		t.Error("EMPTY key should be present")
	} else if v != "" {
		t.Errorf("expected empty value, got %q", v)
	}
}

func TestParseEnvFile_ValueWithEquals(t *testing.T) {
	input := []byte("URL=postgres://user:pass@host/db?sslmode=disable\n")
	got := parseEnvFile(input)
	if got["URL"] != "postgres://user:pass@host/db?sslmode=disable" {
		t.Errorf("unexpected value: %q", got["URL"])
	}
}

func TestStripQuotes_DoubleQuotes(t *testing.T) {
	if got := stripQuotes(`"hello"`); got != "hello" {
		t.Errorf("expected 'hello', got %q", got)
	}
}

func TestStripQuotes_SingleQuotes(t *testing.T) {
	if got := stripQuotes(`'world'`); got != "world" {
		t.Errorf("expected 'world', got %q", got)
	}
}

func TestStripQuotes_NoQuotes(t *testing.T) {
	if got := stripQuotes("plain"); got != "plain" {
		t.Errorf("expected 'plain', got %q", got)
	}
}

func TestStripQuotes_MismatchedQuotes(t *testing.T) {
	// Mismatched quotes should not be stripped.
	if got := stripQuotes(`"hello'`); got != `"hello'` {
		t.Errorf("expected unchanged, got %q", got)
	}
}

func TestStripQuotes_Empty(t *testing.T) {
	if got := stripQuotes(""); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestStripQuotes_SingleChar(t *testing.T) {
	if got := stripQuotes("x"); got != "x" {
		t.Errorf("expected 'x', got %q", got)
	}
}
