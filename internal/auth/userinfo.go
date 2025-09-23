package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// UserInfo represents the user information from Auth0's userinfo endpoint
type UserInfo struct {
	Sub   string `json:"sub"`
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`
}

// FetchUserInfo retrieves user information using an access token
func FetchUserInfo(ctx context.Context, domain, accessToken string) (*UserInfo, error) {
	// Build userinfo endpoint URL - preserve protocol if already specified
	var userinfoURL string
	if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
		userinfoURL = fmt.Sprintf("%s/userinfo", strings.TrimSuffix(domain, "/"))
	} else {
		userinfoURL = fmt.Sprintf("https://%s/userinfo", domain)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating userinfo request: %w", err)
	}

	// Add authorization header
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	// Execute request with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading userinfo response: %w", err)
	}

	// Handle non-200 responses
	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return nil, fmt.Errorf("invalid or expired access token")
		case http.StatusForbidden:
			return nil, fmt.Errorf("insufficient permissions to access userinfo")
		default:
			return nil, fmt.Errorf("userinfo request failed with status %d", resp.StatusCode)
		}
	}

	// Parse successful response
	var userInfo UserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("parsing userinfo response: %w", err)
	}

	// Validate response has required fields
	if userInfo.Sub == "" {
		return nil, fmt.Errorf("invalid userinfo response: missing sub claim")
	}

	return &userInfo, nil
}