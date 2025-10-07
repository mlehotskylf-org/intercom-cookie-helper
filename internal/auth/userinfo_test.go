package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchUserInfo(t *testing.T) {
	tests := []struct {
		name            string
		serverResponse  interface{}
		serverStatus    int
		accessToken     string
		expectedError   string
		validateRequest func(t *testing.T, r *http.Request)
	}{
		{
			name: "successful userinfo fetch",
			serverResponse: UserInfo{
				Email: "user@example.com",
				Name:  "John Doe",
			},
			serverStatus: http.StatusOK,
			accessToken:  "test-access-token",
			validateRequest: func(t *testing.T, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET request, got %s", r.Method)
				}

				// Validate authorization header
				authHeader := r.Header.Get("Authorization")
				expectedAuth := "Bearer test-access-token"
				if authHeader != expectedAuth {
					t.Errorf("expected Authorization header %q, got %q", expectedAuth, authHeader)
				}
			},
		},
		{
			name: "successful userinfo with minimal fields",
			serverResponse: UserInfo{
				Email: "minimal@example.com",
			},
			serverStatus: http.StatusOK,
			accessToken:  "minimal-token",
			validateRequest: func(t *testing.T, r *http.Request) {
				authHeader := r.Header.Get("Authorization")
				if authHeader != "Bearer minimal-token" {
					t.Errorf("unexpected Authorization header: %s", authHeader)
				}
			},
		},
		{
			name: "unauthorized - invalid token",
			serverResponse: map[string]string{
				"error":             "invalid_token",
				"error_description": "The access token is invalid",
			},
			serverStatus:  http.StatusUnauthorized,
			accessToken:   "invalid-token",
			expectedError: "invalid or expired access token",
		},
		{
			name: "forbidden - insufficient permissions",
			serverResponse: map[string]string{
				"error":             "insufficient_scope",
				"error_description": "The access token does not have the required scope",
			},
			serverStatus:  http.StatusForbidden,
			accessToken:   "limited-token",
			expectedError: "insufficient permissions to access userinfo",
		},
		{
			name: "internal server error",
			serverResponse: map[string]string{
				"error": "internal_error",
			},
			serverStatus:  http.StatusInternalServerError,
			accessToken:   "test-token",
			expectedError: "userinfo request failed with status 500",
		},
		{
			name:           "invalid json response",
			serverResponse: "not a json response",
			serverStatus:   http.StatusOK,
			accessToken:    "test-token",
			expectedError:  "parsing userinfo response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Validate request if validator provided
				if tt.validateRequest != nil {
					tt.validateRequest(t, r)
				}

				// Check path
				if r.URL.Path != "/userinfo" {
					t.Errorf("expected path /userinfo, got %s", r.URL.Path)
				}

				// Set response status
				w.WriteHeader(tt.serverStatus)

				// Write response based on type
				switch v := tt.serverResponse.(type) {
				case string:
					w.Write([]byte(v))
				default:
					json.NewEncoder(w).Encode(v)
				}
			}))
			defer server.Close()

			// Call FetchUserInfo
			userInfo, err := FetchUserInfo(
				context.Background(),
				server.URL,
				tt.accessToken,
			)

			// Check error expectations
			if tt.expectedError != "" {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.expectedError)
				} else if !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("expected error containing %q, got %q", tt.expectedError, err.Error())
				}
				return
			}

			// Check success expectations
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if userInfo == nil {
				t.Error("expected non-nil userinfo")
				return
			}
		})
	}
}

func TestFetchUserInfo_ContextCancellation(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This handler will never complete before context cancellation
		<-r.Context().Done()
	}))
	defer server.Close()

	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Call FetchUserInfo with cancelled context
	_, err := FetchUserInfo(ctx, server.URL, "test-token")

	if err == nil {
		t.Error("expected error for cancelled context, got nil")
	}

	if !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("expected context cancelled error, got: %v", err)
	}
}
