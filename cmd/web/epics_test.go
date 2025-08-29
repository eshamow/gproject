package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Helper function to create an authenticated test user and session
func createTestUserSession(t *testing.T, app *App) (userID int64, sessionID string, csrfToken string) {
	// Generate unique IDs to avoid conflicts
	githubID := time.Now().UnixNano() % 1000000
	email := fmt.Sprintf("test%d@example.com", githubID)
	login := fmt.Sprintf("testuser%d", githubID)
	
	encryptedToken, _ := app.encryptToken("test-token")
	
	// Create test user (let database auto-generate ID)
	result, err := app.db.Exec(`
		INSERT INTO users (github_id, github_login, email, name, avatar_url, access_token)
		VALUES (?, ?, ?, ?, ?, ?)`,
		githubID, login, email, "Test User", "http://avatar.url", encryptedToken)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	
	userID, err = result.LastInsertId()
	if err != nil {
		t.Fatalf("Failed to get user ID: %v", err)
	}
	
	// Create session
	sessionID = generateRandomString(32)
	expiresAt := time.Now().Add(24 * time.Hour)
	_, err = app.db.Exec(`
		INSERT INTO sessions (id, user_id, expires_at, created_at)
		VALUES (?, ?, ?, ?)`,
		sessionID, userID, expiresAt, time.Now())
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	
	// Create CSRF token
	csrfToken = generateRandomString(32)
	_, err = app.db.Exec(`
		INSERT INTO csrf_tokens (session_id, token, expires_at)
		VALUES (?, ?, ?)`,
		sessionID, csrfToken, expiresAt)
	if err != nil {
		t.Fatalf("Failed to create CSRF token: %v", err)
	}
	
	return userID, sessionID, csrfToken
}

// Helper function to add authentication to a request
func addAuthToRequest(req *http.Request, sessionID string, csrfToken string) {
	// Add session cookie
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: sessionID,
	})
	
	// Add CSRF token header
	req.Header.Set("X-CSRF-Token", csrfToken)
}

func TestEpicsCRUD(t *testing.T) {
	// Setup test database
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	
	// Run migrations
	runMigrations(db)
	
	// Create test app with required config
	app := &App{
		db:          db,
		rateLimiter: NewRateLimiter(),
		config: Config{
			SessionSecret: "test-secret-key-for-testing-only",
		},
	}
	
	// Create authenticated test user
	_, sessionID, csrfToken := createTestUserSession(t, app)
	
	// Test creating an epic
	t.Run("CreateEpic", func(t *testing.T) {
		body := `{"title":"Test Epic","description":"Test Description","color":"#FF0000","owner":"testuser","status":"active"}`
		req := httptest.NewRequest("POST", "/api/epics", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		addAuthToRequest(req, sessionID, csrfToken)
		w := httptest.NewRecorder()
		
		app.handleAPIEpics(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
		}
		
		var response map[string]interface{}
		json.NewDecoder(w.Body).Decode(&response)
		
		if response["id"] == nil {
			t.Error("Expected epic ID in response")
		}
	})
	
	// Test getting epics  
	t.Run("GetEpics", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/epics", nil)
		addAuthToRequest(req, sessionID, csrfToken)
		w := httptest.NewRecorder()
		
		app.handleAPIEpics(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
		
		var epics []map[string]interface{}
		json.NewDecoder(w.Body).Decode(&epics)
		
		if len(epics) != 1 {
			t.Errorf("Expected 1 epic, got %d", len(epics))
		}
	})
}

func TestThemesCRUD(t *testing.T) {
	// Setup test database
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	
	// Run migrations
	runMigrations(db)
	
	// Create test app with required config
	app := &App{
		db:          db,
		rateLimiter: NewRateLimiter(),
		config: Config{
			SessionSecret: "test-secret-key-for-testing-only",
		},
	}
	
	// Create authenticated test user
	_, sessionID, csrfToken := createTestUserSession(t, app)
	
	// Test creating a theme
	t.Run("CreateTheme", func(t *testing.T) {
		body := `{"name":"Q1 Goals","description":"First quarter objectives","quarter":"2025-Q1","status":"planned"}`
		req := httptest.NewRequest("POST", "/api/themes", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		addAuthToRequest(req, sessionID, csrfToken)
		w := httptest.NewRecorder()
		
		app.handleAPIThemes(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
		}
		
		var response map[string]interface{}
		json.NewDecoder(w.Body).Decode(&response)
		
		if response["id"] == nil {
			t.Error("Expected theme ID in response")
		}
	})
	
	// Test getting themes
	t.Run("GetThemes", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/themes", nil)
		addAuthToRequest(req, sessionID, csrfToken)
		w := httptest.NewRecorder()
		
		app.handleAPIThemes(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
		
		var themes []map[string]interface{}
		json.NewDecoder(w.Body).Decode(&themes)
		
		if len(themes) != 1 {
			t.Errorf("Expected 1 theme, got %d", len(themes))
		}
	})
}

func TestReportsSummary(t *testing.T) {
	// Setup test database
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	
	// Run migrations
	runMigrations(db)
	
	// Create test app
	app := &App{
		db:          db,
		rateLimiter: NewRateLimiter(),
	}
	
	// Add some test data
	db.Exec(`INSERT INTO issues (github_id, number, title, state) VALUES (1, 1, 'Test Issue 1', 'open')`)
	db.Exec(`INSERT INTO issues (github_id, number, title, state) VALUES (2, 2, 'Test Issue 2', 'closed')`)
	db.Exec(`INSERT INTO epics (title, status) VALUES ('Test Epic', 'active')`)
	db.Exec(`INSERT INTO themes (name, status) VALUES ('Test Theme', 'planned')`)
	
	// Test getting report summary
	t.Run("GetReportSummary", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/reports?type=summary", nil)
		w := httptest.NewRecorder()
		
		app.handleAPIReports(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
		
		var response map[string]interface{}
		json.NewDecoder(w.Body).Decode(&response)
		
		summary, ok := response["summary"].(map[string]interface{})
		if !ok {
			t.Fatal("Expected summary in response")
		}
		
		if summary["total_issues"].(float64) != 2 {
			t.Errorf("Expected 2 total issues, got %v", summary["total_issues"])
		}
		
		if summary["open_issues"].(float64) != 1 {
			t.Errorf("Expected 1 open issue, got %v", summary["open_issues"])
		}
		
		if summary["closed_issues"].(float64) != 1 {
			t.Errorf("Expected 1 closed issue, got %v", summary["closed_issues"])
		}
	})
}