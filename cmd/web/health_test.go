package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHealthEndpoint(t *testing.T) {
	// Set up test app
	app := setupTestApp(t)
	defer app.db.Close()

	tests := []struct {
		name           string
		method         string
		expectedStatus int
		checkResponse  func(t *testing.T, body []byte)
	}{
		{
			name:           "GET returns 200 OK",
			method:         http.MethodGet,
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body []byte) {
				var health struct {
					Status   string    `json:"status"`
					Database string    `json:"database"`
					Version  string    `json:"version"`
					Time     time.Time `json:"time"`
				}

				if err := json.Unmarshal(body, &health); err != nil {
					t.Fatalf("Failed to unmarshal response: %v", err)
				}

				if health.Status != "ok" {
					t.Errorf("Expected status 'ok', got '%s'", health.Status)
				}

				if health.Database != "ok" {
					t.Errorf("Expected database 'ok', got '%s'", health.Database)
				}

				if health.Version == "" {
					t.Error("Version should not be empty")
				}

				if health.Time.IsZero() {
					t.Error("Time should not be zero")
				}
			},
		},
		{
			name:           "POST returns 405 Method Not Allowed",
			method:         http.MethodPost,
			expectedStatus: http.StatusMethodNotAllowed,
			checkResponse:  func(t *testing.T, body []byte) {},
		},
		{
			name:           "PUT returns 405 Method Not Allowed",
			method:         http.MethodPut,
			expectedStatus: http.StatusMethodNotAllowed,
			checkResponse:  func(t *testing.T, body []byte) {},
		},
		{
			name:           "DELETE returns 405 Method Not Allowed",
			method:         http.MethodDelete,
			expectedStatus: http.StatusMethodNotAllowed,
			checkResponse:  func(t *testing.T, body []byte) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, "/health", nil)
			if err != nil {
				t.Fatal(err)
			}

			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(app.handleHealth)
			handler.ServeHTTP(rr, req)

			if status := rr.Code; status != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, status)
			}

			if tt.expectedStatus == http.StatusOK {
				// Check Content-Type header
				contentType := rr.Header().Get("Content-Type")
				if contentType != "application/json" {
					t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
				}
			}

			tt.checkResponse(t, rr.Body.Bytes())
		})
	}
}

func TestHealthEndpointDatabaseFailure(t *testing.T) {
	// Set up test app
	app := setupTestApp(t)

	// Close the database to simulate failure
	app.db.Close()

	req, err := http.NewRequest(http.MethodGet, "/health", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(app.handleHealth)
	handler.ServeHTTP(rr, req)

	// Should return 503 Service Unavailable when database is down
	if status := rr.Code; status != http.StatusServiceUnavailable {
		t.Errorf("Expected status %d when database is down, got %d", http.StatusServiceUnavailable, status)
	}

	var health struct {
		Status   string `json:"status"`
		Database string `json:"database"`
	}

	if err := json.Unmarshal(rr.Body.Bytes(), &health); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if health.Status != "degraded" {
		t.Errorf("Expected status 'degraded' when database is down, got '%s'", health.Status)
	}

	if !contains(health.Database, "error:") {
		t.Errorf("Expected database field to contain 'error:', got '%s'", health.Database)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr
}
