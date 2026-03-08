package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

// apiRequest makes an authenticated JSON request to the envsh API.
func apiRequest(method, path string, body any, token string) (*http.Response, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	// Allow server URL override from persistent flag.
	base := cfg.ServerURL
	if serverURL != "" {
		base = serverURL
	}
	url := base + path

	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshaling request: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	return resp, nil
}

// apiErrorResponse represents an API error response body.
type apiErrorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// checkAPIError reads the response body if status >= 400 and returns an error.
// The response body is consumed on error.
func checkAPIError(resp *http.Response) error {
	if resp.StatusCode < 400 {
		return nil
	}
	var ae apiErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&ae); err != nil {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if ae.Error.Code != "" {
		return fmt.Errorf("%s: %s", ae.Error.Code, ae.Error.Message)
	}
	return fmt.Errorf("HTTP %d", resp.StatusCode)
}
