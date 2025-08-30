package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// TestDashboardAutoRefresh tests that the dashboard has auto-refresh functionality  
func TestDashboardAutoRefresh(t *testing.T) {
	// This test verifies that the dashboard template includes auto-refresh functionality
	// We check for the presence of HTMX polling attributes for auto-refresh
	
	// Read the dashboard template directly
	templatePath := "templates/dashboard.html"
	content, err := os.ReadFile(templatePath)
	if err != nil {
		t.Skipf("Skipping test - cannot read template file: %v", err)
		return
	}
	
	templateContent := string(content)

	// Verify auto-refresh functionality is present (using HTMX)
	checks := []struct {
		name     string
		contains string
	}{
		{"Has HTMX polling trigger", "hx-trigger=\"load, every 30s\""},
		{"Has sync status target", "hx-target=\"#last-sync-info\""},
		{"Has sync-status element", "id=\"sync-status\""},
		{"Has API endpoint for sync", "hx-get=\"/api/sync/status\""},
	}

	for _, check := range checks {
		if !strings.Contains(templateContent, check.contains) {
			t.Errorf("%s: expected to find '%s' in dashboard HTML", check.name, check.contains)
		}
	}
}

// TestAPISyncStatusEndpoint tests the sync status API endpoint
func TestAPISyncStatusEndpoint(t *testing.T) {
	// Setup test database
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	defer db.Close()

	// Initialize schema with repositories table
	_, err = db.Exec(`
		CREATE TABLE repositories (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			owner TEXT NOT NULL,
			name TEXT NOT NULL,
			synced_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(owner, name)
		);
		CREATE TABLE issues (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			github_id INTEGER UNIQUE NOT NULL,
			number INTEGER NOT NULL,
			title TEXT NOT NULL,
			state TEXT NOT NULL,
			synced_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		INSERT INTO repositories (owner, name, synced_at) 
		VALUES ('testowner', 'testrepo', datetime('now', '-5 minutes'));
		INSERT INTO issues (github_id, number, title, state) 
		VALUES (1, 1, 'Test Issue 1', 'open');
		INSERT INTO issues (github_id, number, title, state) 
		VALUES (2, 2, 'Test Issue 2', 'closed');
		INSERT INTO issues (github_id, number, title, state) 
		VALUES (3, 3, 'Test Issue 3', 'open');
	`)
	if err != nil {
		t.Fatalf("Failed to create test tables: %v", err)
	}

	app := &App{
		db: db,
		config: Config{
			GitHubRepoOwner: "testowner",
			GitHubRepoName:  "testrepo",
		},
		syncStatus: &SyncStatus{
			LastSyncAt:   time.Now().Add(-5 * time.Minute),
			IssuesSynced: 3,
			Error:        "",
			InProgress:   false,
		},
	}
	// No rate limiter created, so no cleanup needed

	req := httptest.NewRequest("GET", "/api/sync-status", nil)
	w := httptest.NewRecorder()

	app.handleAPISyncStatus(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Check Content-Type
	contentType := w.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("Expected Content-Type to be application/json, got %s", contentType)
	}

	// Verify JSON response contains expected fields
	body := w.Body.String()
	expectedFields := []string{
		`"owner":"testowner"`,
		`"name":"testrepo"`,
		`"total":3`,
		`"open":2`,
		`"closed":1`,
		`"last_sync"`,
	}

	for _, field := range expectedFields {
		if !strings.Contains(body, field) {
			t.Errorf("Expected response to contain %s, got: %s", field, body)
		}
	}
}

// TestNoSSEReferences tests that SSE code has been properly removed/deferred
func TestNoSSEReferences(t *testing.T) {
	// This test ensures we're not accidentally using SSE in the template when it's deferred
	// We check the template content directly to avoid needing full handler setup
	
	// Read the dashboard template directly
	templatePath := "templates/dashboard.html"
	content, err := os.ReadFile(templatePath)
	if err != nil {
		t.Skipf("Skipping test - cannot read template file: %v", err)
		return
	}
	
	templateContent := string(content)

	// Verify no EventSource or SSE references in dashboard
	sseIndicators := []string{
		"EventSource",
		"new EventSource",
		"eventsource",
	}

	for _, indicator := range sseIndicators {
		if strings.Contains(strings.ToLower(templateContent), strings.ToLower(indicator)) {
			t.Errorf("Found SSE reference '%s' in dashboard template when SSE is deferred", indicator)
		}
	}

	// Verify HTMX polling is used instead
	if !strings.Contains(templateContent, "hx-trigger") || !strings.Contains(templateContent, "every") {
		t.Error("Expected to find HTMX polling (hx-trigger with 'every') in template, but it's missing")
	}
	
	// Verify HTMX GET is used for polling
	if !strings.Contains(templateContent, "hx-get=\"/api/sync/status\"") {
		t.Error("Expected to find HTMX GET call for sync status polling")
	}
}

// Helper function to initialize test database
func initTestDB(db *sql.DB) error {
	schema := `
	CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		github_id INTEGER UNIQUE NOT NULL,
		username TEXT NOT NULL,
		name TEXT,
		email TEXT,
		access_token TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE sessions (
		id TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		expires_at DATETIME NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);

	CREATE TABLE issues (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		github_id INTEGER UNIQUE NOT NULL,
		number INTEGER NOT NULL,
		title TEXT NOT NULL,
		body TEXT,
		state TEXT NOT NULL,
		author TEXT,
		assignee TEXT,
		labels TEXT,
		created_at DATETIME,
		updated_at DATETIME,
		closed_at DATETIME,
		synced_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	INSERT INTO users (id, github_id, username, name, access_token) 
	VALUES (1, 12345, 'testuser', 'Test User', 'encrypted_token');
	`

	_, err := db.Exec(schema)
	return err
}
