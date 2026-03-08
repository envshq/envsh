package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckAPIError_Success(t *testing.T) {
	resp := &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok": true}`))}
	if err := checkAPIError(resp); err != nil {
		t.Errorf("expected no error for 200, got %v", err)
	}
}

func TestCheckAPIError_404WithBody(t *testing.T) {
	body := `{"error":{"code":"NOT_FOUND","message":"resource not found"}}`
	resp := &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader(body))}
	err := checkAPIError(resp)
	if err == nil {
		t.Fatal("expected error for 404")
	}
	if !strings.Contains(err.Error(), "NOT_FOUND") {
		t.Errorf("expected error to contain NOT_FOUND, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "resource not found") {
		t.Errorf("expected error to contain message, got %q", err.Error())
	}
}

func TestCheckAPIError_500WithBadJSON(t *testing.T) {
	resp := &http.Response{StatusCode: 500, Body: io.NopCloser(strings.NewReader("not json"))}
	err := checkAPIError(resp)
	if err == nil {
		t.Fatal("expected error for 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("expected error to contain HTTP 500, got %q", err.Error())
	}
}

func TestAPIRequest_SetsAuthHeader(t *testing.T) {
	var capturedToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedToken = r.Header.Get("Authorization")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	// Override the serverURL global so apiRequest uses our test server.
	serverURL = server.URL

	resp, err := apiRequest("GET", "/test", nil, "mytoken")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = resp.Body.Close()

	if capturedToken != "Bearer mytoken" {
		t.Errorf("expected 'Bearer mytoken', got %q", capturedToken)
	}

	// Reset.
	serverURL = ""
}

func TestAPIRequest_SetsContentTypeForBody(t *testing.T) {
	var capturedContentType string
	var capturedBody map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedContentType = r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&capturedBody); err != nil {
			t.Errorf("decoding body: %v", err)
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	serverURL = server.URL
	defer func() { serverURL = "" }()

	payload := map[string]string{"key": "value"}
	resp, err := apiRequest("POST", "/test", payload, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = resp.Body.Close()

	if capturedContentType != "application/json" {
		t.Errorf("expected application/json, got %q", capturedContentType)
	}
	if capturedBody["key"] != "value" {
		t.Errorf("unexpected body: %v", capturedBody)
	}
}

func TestAPIRequest_NoAuthHeaderWhenEmptyToken(t *testing.T) {
	var capturedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	serverURL = server.URL
	defer func() { serverURL = "" }()

	resp, err := apiRequest("GET", "/test", nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = resp.Body.Close()

	if capturedAuth != "" {
		t.Errorf("expected no Authorization header, got %q", capturedAuth)
	}
}
