package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEpicsCRUD(t *testing.T) {
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
	
	// Test creating an epic
	t.Run("CreateEpic", func(t *testing.T) {
		body := `{"title":"Test Epic","description":"Test Description","color":"#FF0000","owner":"testuser","status":"active"}`
		req := httptest.NewRequest("POST", "/api/epics", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		
		app.handleAPIEpics(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
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
	
	// Create test app
	app := &App{
		db:          db,
		rateLimiter: NewRateLimiter(),
	}
	
	// Test creating a theme
	t.Run("CreateTheme", func(t *testing.T) {
		body := `{"name":"Q1 Goals","description":"First quarter objectives","quarter":"2025-Q1","status":"planned"}`
		req := httptest.NewRequest("POST", "/api/themes", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
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