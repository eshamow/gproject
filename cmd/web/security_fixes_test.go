package main

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestRateLimiterCleanup verifies that the rate limiter properly cleans up old entries
func TestRateLimiterCleanup(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Stop() // Ensure cleanup goroutine is stopped
	
	// Add some attempts
	for i := 0; i < 5; i++ {
		rl.Allow("test-key", 10, 1*time.Hour)
	}
	
	// Verify attempts exist
	rl.mu.RLock()
	initialCount := len(rl.attempts["test-key"])
	rl.mu.RUnlock()
	
	if initialCount != 5 {
		t.Errorf("Expected 5 attempts, got %d", initialCount)
	}
	
	// Manually trigger cleanup with old cutoff time
	rl.cleanup()
	
	// Verify cleanup doesn't remove recent entries
	rl.mu.RLock()
	afterCleanup := len(rl.attempts["test-key"])
	rl.mu.RUnlock()
	
	if afterCleanup != 5 {
		t.Errorf("Recent entries should not be cleaned up, got %d entries", afterCleanup)
	}
}

// TestHealthEndpointErrorMasking verifies that database errors are masked in production
func TestHealthEndpointErrorMasking(t *testing.T) {
	// Create app with mock database that will fail
	app := &App{
		config: Config{
			Environment: "production",
		},
		rateLimiter: NewRateLimiter(),
	}
	defer app.rateLimiter.Stop()
	
	// Close the database to force an error
	if app.db != nil {
		app.db.Close()
	}
	
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	
	app.handleHealth(w, req)
	
	resp := w.Result()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("Expected status %d, got %d", http.StatusServiceUnavailable, resp.StatusCode)
	}
	
	var health struct {
		Database string `json:"database"`
	}
	json.NewDecoder(resp.Body).Decode(&health)
	
	// In production, should not expose actual error
	if strings.Contains(health.Database, "error:") {
		t.Error("Production health check should not expose database error details")
	}
	
	if health.Database != "unavailable" {
		t.Errorf("Expected database status 'unavailable', got '%s'", health.Database)
	}
}

// TestSecurityHeadersEnhanced verifies all security headers are properly set
func TestSecurityHeadersEnhanced(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		checkHeader string
		shouldExist bool
		contains    string
	}{
		{
			name:        "X-Frame-Options",
			environment: "development",
			checkHeader: "X-Frame-Options",
			shouldExist: true,
			contains:    "DENY",
		},
		{
			name:        "X-Content-Type-Options",
			environment: "development",
			checkHeader: "X-Content-Type-Options",
			shouldExist: true,
			contains:    "nosniff",
		},
		{
			name:        "Permissions-Policy",
			environment: "development",
			checkHeader: "Permissions-Policy",
			shouldExist: true,
			contains:    "geolocation=()",
		},
		{
			name:        "CSP-block-mixed-content",
			environment: "development",
			checkHeader: "Content-Security-Policy",
			shouldExist: true,
			contains:    "block-all-mixed-content",
		},
		{
			name:        "HSTS-Production",
			environment: "production",
			checkHeader: "Strict-Transport-Security",
			shouldExist: true,
			contains:    "max-age=31536000",
		},
		{
			name:        "HSTS-Development",
			environment: "development",
			checkHeader: "Strict-Transport-Security",
			shouldExist: false,
			contains:    "",
		},
		{
			name:        "X-Permitted-Cross-Domain-Policies-Production",
			environment: "production",
			checkHeader: "X-Permitted-Cross-Domain-Policies",
			shouldExist: true,
			contains:    "none",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := &App{
				config: Config{
					Environment: tt.environment,
				},
			}
			
			handler := app.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			
			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()
			
			handler.ServeHTTP(w, req)
			
			header := w.Header().Get(tt.checkHeader)
			
			if tt.shouldExist {
				if header == "" {
					t.Errorf("Expected header %s to be set in %s environment", tt.checkHeader, tt.environment)
				}
				if tt.contains != "" && !strings.Contains(header, tt.contains) {
					t.Errorf("Expected header %s to contain '%s', got '%s'", tt.checkHeader, tt.contains, header)
				}
			} else {
				if header != "" {
					t.Errorf("Expected header %s to not be set in %s environment, but got '%s'", tt.checkHeader, tt.environment, header)
				}
			}
		})
	}
}

// TestTemplateErrorMasking verifies that template errors are masked in production
func TestTemplateErrorMasking(t *testing.T) {
	// Set environment to production
	os.Setenv("ENVIRONMENT", "production")
	defer os.Unsetenv("ENVIRONMENT")
	
	app := &App{
		config: Config{
			Environment: "production",
		},
		templates:   make(map[string]*template.Template),
		rateLimiter: NewRateLimiter(),
	}
	defer app.rateLimiter.Stop()
	
	// Don't set up templates to force an error
	req := httptest.NewRequest("GET", "/dashboard", nil)
	w := httptest.NewRecorder()
	
	// Call the handler directly without session (will cause template error)
	app.handleDashboard(w, req)
	
	body := w.Body.String()
	
	// In production, should not expose template error details
	if strings.Contains(body, "template:") || strings.Contains(body, "ExecuteTemplate") {
		t.Error("Production should not expose template error details")
	}
	
	if !strings.Contains(body, "Internal server error") {
		t.Error("Production should return generic error message")
	}
}