package httpx

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/config"
)

func TestMetricsSnapshot(t *testing.T) {
	// Reset metrics to known state
	m := &Metrics{}

	// Verify initial state is zero
	snapshot := m.Snapshot()
	if snapshot.Login.Start != 0 {
		t.Errorf("Expected login.start to be 0, got %d", snapshot.Login.Start)
	}

	// Increment some counters
	m.LoginStart.Add(5)
	m.LoginBadReturn.Add(2)
	m.CbStart.Add(3)
	m.CbOK.Add(1)

	// Take snapshot
	snapshot = m.Snapshot()

	// Verify values
	tests := []struct {
		name     string
		got      uint64
		expected uint64
	}{
		{"login.start", snapshot.Login.Start, 5},
		{"login.bad_return", snapshot.Login.BadReturn, 2},
		{"login.ok", snapshot.Login.OK, 0},
		{"callback.start", snapshot.Callback.Start, 3},
		{"callback.ok", snapshot.Callback.OK, 1},
	}

	for _, tt := range tests {
		if tt.got != tt.expected {
			t.Errorf("%s: expected %d, got %d", tt.name, tt.expected, tt.got)
		}
	}
}

func TestMetricsHandler_DevEnvironment(t *testing.T) {
	cfg := config.Config{
		Env:                "dev",
		AllowedReturnHosts: []string{"example.com"},
	}

	// Reset global metrics for clean test
	oldMetrics := metrics
	metrics = &Metrics{}
	defer func() { metrics = oldMetrics }()

	// Add some test data
	metrics.LoginStart.Add(10)
	metrics.LoginBadReturn.Add(3)
	metrics.CbOK.Add(7)

	req := httptest.NewRequest("GET", "/metrics/dev", nil)
	rec := httptest.NewRecorder()

	// Add config to context
	ctx := req.Context()
	ctx = contextWithConfig(ctx, cfg)
	req = req.WithContext(ctx)

	metricsHandler(rec, req)

	// Check status code
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	// Check content type
	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json; charset=utf-8" {
		t.Errorf("expected Content-Type 'application/json', got '%s'", contentType)
	}

	// Parse response
	var snapshot MetricsSnapshot
	if err := json.NewDecoder(rec.Body).Decode(&snapshot); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify values
	if snapshot.Login.Start != 10 {
		t.Errorf("expected login.start=10, got %d", snapshot.Login.Start)
	}
	if snapshot.Login.BadReturn != 3 {
		t.Errorf("expected login.bad_return=3, got %d", snapshot.Login.BadReturn)
	}
	if snapshot.Callback.OK != 7 {
		t.Errorf("expected callback.ok=7, got %d", snapshot.Callback.OK)
	}
}

func TestMetricsHandler_ProductionEnvironment(t *testing.T) {
	cfg := config.Config{
		Env:                "prod",
		AllowedReturnHosts: []string{"example.com"},
	}

	req := httptest.NewRequest("GET", "/metrics/dev", nil)
	rec := httptest.NewRecorder()

	// Add config to context
	ctx := req.Context()
	ctx = contextWithConfig(ctx, cfg)
	req = req.WithContext(ctx)

	metricsHandler(rec, req)

	// Should return 404 in production
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404 in production, got %d", rec.Code)
	}
}

func TestMetricsHandler_NoConfig(t *testing.T) {
	req := httptest.NewRequest("GET", "/metrics/dev", nil)
	rec := httptest.NewRecorder()

	// No config in context
	metricsHandler(rec, req)

	// Should return 500 when config is missing
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500 when config missing, got %d", rec.Code)
	}
}

func TestMetrics_AtomicIncrements(t *testing.T) {
	// Test that atomic operations work correctly
	m := &Metrics{}

	// Multiple increments
	for i := 0; i < 100; i++ {
		m.LoginStart.Add(1)
	}

	snapshot := m.Snapshot()
	if snapshot.Login.Start != 100 {
		t.Errorf("expected 100 increments, got %d", snapshot.Login.Start)
	}

	// Add larger value
	m.CbOK.Add(50)
	snapshot = m.Snapshot()
	if snapshot.Callback.OK != 50 {
		t.Errorf("expected 50, got %d", snapshot.Callback.OK)
	}
}

func TestMetricsJSON_Structure(t *testing.T) {
	m := &Metrics{}
	m.LoginStart.Add(5)
	m.LoginBadReferer.Add(2)
	m.LoginBadReturn.Add(1)
	m.CbStart.Add(3)
	m.CbStateMismatch.Add(1)

	snapshot := m.Snapshot()
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("failed to marshal snapshot: %v", err)
	}

	// Parse back to verify structure
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	// Verify top-level keys
	if _, ok := parsed["login"]; !ok {
		t.Error("missing 'login' key in JSON")
	}
	if _, ok := parsed["callback"]; !ok {
		t.Error("missing 'callback' key in JSON")
	}

	// Verify nested structure
	login := parsed["login"].(map[string]interface{})
	if login["start"] != float64(5) {
		t.Errorf("expected login.start=5, got %v", login["start"])
	}
	if login["bad_referer"] != float64(2) {
		t.Errorf("expected login.bad_referer=2, got %v", login["bad_referer"])
	}

	callback := parsed["callback"].(map[string]interface{})
	if callback["state_mismatch"] != float64(1) {
		t.Errorf("expected callback.state_mismatch=1, got %v", callback["state_mismatch"])
	}
}

// Helper to add config to context
func contextWithConfig(ctx context.Context, cfg config.Config) context.Context {
	return context.WithValue(ctx, ConfigContextKey, cfg)
}
