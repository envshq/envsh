package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRunProjectList_ParsesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/keys":
			// Login token lookup — not called here.
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"keys":[]}`))
		case "/projects":
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"projects":[{"id":"p1","name":"My App","slug":"my-app"}]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	// Inject a fake token.
	serverURL = server.URL
	defer func() { serverURL = "" }()

	// Patch GetActiveToken by writing temporary credentials.
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	// Use apiRequest directly to test project list parsing.
	resp, err := apiRequest("GET", "/projects", nil, "fake-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	var result struct {
		Projects []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Slug string `json:"slug"`
		} `json:"projects"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(result.Projects) != 1 {
		t.Fatalf("expected 1 project, got %d", len(result.Projects))
	}
	if result.Projects[0].Slug != "my-app" {
		t.Errorf("unexpected slug: %q", result.Projects[0].Slug)
	}
}

func TestResolveProjectID_Found(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"projects":[{"id":"proj-123","slug":"api"},{"id":"proj-456","slug":"web"}]}`))
	}))
	defer server.Close()

	serverURL = server.URL
	defer func() { serverURL = "" }()

	id, err := resolveProjectID("token", "api")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "proj-123" {
		t.Errorf("expected 'proj-123', got %q", id)
	}
}

func TestResolveProjectID_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"projects":[{"id":"proj-123","slug":"api"}]}`))
	}))
	defer server.Close()

	serverURL = server.URL
	defer func() { serverURL = "" }()

	_, err := resolveProjectID("token", "nonexistent")
	if err == nil {
		t.Error("expected error for missing project")
	}
}

func TestResolveProjectID_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error":{"code":"UNAUTHORIZED","message":"not authenticated"}}`))
	}))
	defer server.Close()

	serverURL = server.URL
	defer func() { serverURL = "" }()

	_, err := resolveProjectID("bad-token", "api")
	if err == nil {
		t.Error("expected error for 401 response")
	}
}
