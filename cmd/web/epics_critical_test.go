package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestEpicAccessControl verifies that users can only access their own epics
func TestEpicAccessControl(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	
	runMigrations(db)
	
	app := &App{
		db:          db,
		rateLimiter: NewRateLimiter(),
		config: Config{
			SessionSecret: "test-secret-key-for-testing-only",
		},
	}
	
	// Create two users with sessions
	user1ID, session1ID, csrf1Token := createTestUserSession(t, app)
	user2ID, session2ID, csrf2Token := createTestUserSession(t, app)
	
	// User 1 creates an epic
	var epic1ID int64
	t.Run("User1CreatesEpic", func(t *testing.T) {
		body := `{"title":"User1 Epic","description":"Private","status":"active"}`
		req := httptest.NewRequest("POST", "/api/epics", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		addAuthToRequest(req, session1ID, csrf1Token)
		w := httptest.NewRecorder()
		
		app.handleAPIEpics(w, req)
		
		if w.Code != http.StatusOK {
			t.Fatalf("Failed to create epic: %d - %s", w.Code, w.Body.String())
		}
		
		var response map[string]interface{}
		json.NewDecoder(w.Body).Decode(&response)
		epic1ID = int64(response["id"].(float64))
	})
	
	// User 2 tries to update User 1's epic - should fail
	t.Run("User2CannotUpdateUser1Epic", func(t *testing.T) {
		body := `{"title":"Hacked Title","description":"Should not work"}`
		req := httptest.NewRequest("PUT", fmt.Sprintf("/api/epics/%d", epic1ID), strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		addAuthToRequest(req, session2ID, csrf2Token)
		w := httptest.NewRecorder()
		
		app.handleAPIEpic(w, req)
		
		// Should either get 404 (not found) or no changes
		if w.Code == http.StatusOK {
			// Verify the epic wasn't actually changed
			var title string
			var ownerID int64
			err := app.db.QueryRow("SELECT title, user_id FROM epics WHERE id = ?", epic1ID).Scan(&title, &ownerID)
			if err != nil {
				t.Fatal(err)
			}
			if title == "Hacked Title" {
				t.Error("User 2 was able to modify User 1's epic!")
			}
			if ownerID != user1ID {
				t.Errorf("Epic owner changed from %d to %d", user1ID, ownerID)
			}
		}
	})
	
	// User 2 tries to delete User 1's epic - should fail
	t.Run("User2CannotDeleteUser1Epic", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", fmt.Sprintf("/api/epics/%d", epic1ID), nil)
		addAuthToRequest(req, session2ID, csrf2Token)
		w := httptest.NewRecorder()
		
		app.handleAPIEpic(w, req)
		
		// Verify epic still exists
		var count int
		err := app.db.QueryRow("SELECT COUNT(*) FROM epics WHERE id = ?", epic1ID).Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		if count == 0 {
			t.Error("User 2 was able to delete User 1's epic!")
		}
	})
	
	// User 2 cannot see User 1's epics in listing
	t.Run("User2CannotSeeUser1Epics", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/epics", nil)
		addAuthToRequest(req, session2ID, csrf2Token)
		w := httptest.NewRecorder()
		
		app.handleAPIEpics(w, req)
		
		if w.Code != http.StatusOK {
			t.Fatalf("Failed to get epics: %d", w.Code)
		}
		
		var epics []map[string]interface{}
		json.NewDecoder(w.Body).Decode(&epics)
		
		for _, epic := range epics {
			if int64(epic["id"].(float64)) == epic1ID {
				t.Error("User 2 can see User 1's epic in listing!")
			}
		}
	})
	
	_ = user2ID // Silence unused variable warning
}

// TestEpicInputValidation tests validation of epic inputs
func TestEpicInputValidation(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	
	runMigrations(db)
	
	app := &App{
		db:          db,
		rateLimiter: NewRateLimiter(),
		config: Config{
			SessionSecret: "test-secret-key-for-testing-only",
		},
	}
	
	_, sessionID, csrfToken := createTestUserSession(t, app)
	
	tests := []struct {
		name       string
		body       string
		wantStatus int
		desc       string
	}{
		{
			name:       "MissingTitle",
			body:       `{"description":"No title"}`,
			wantStatus: http.StatusBadRequest,
			desc:       "Should reject epic without title",
		},
		{
			name:       "InvalidStatus",
			body:       `{"title":"Test","status":"invalid_status"}`,
			wantStatus: http.StatusBadRequest,
			desc:       "Should reject invalid status",
		},
		{
			name:       "XSSInTitle",
			body:       `{"title":"<script>alert('xss')</script>","description":"Test"}`,
			wantStatus: http.StatusOK, // Should accept but sanitize
			desc:       "Should handle XSS attempts in title",
		},
		{
			name:       "SQLInjectionInTitle",
			body:       `{"title":"'; DROP TABLE epics; --","description":"Test"}`,
			wantStatus: http.StatusOK, // Should accept safely due to parameterized queries
			desc:       "Should handle SQL injection attempts",
		},
		{
			name:       "VeryLongTitle",
			body:       fmt.Sprintf(`{"title":"%s","description":"Test"}`, strings.Repeat("a", 10000)),
			wantStatus: http.StatusBadRequest, // Server validates length
			desc:       "Should reject very long titles",
		},
		{
			name:       "InvalidJSON",
			body:       `{"title":"Test", bad json`,
			wantStatus: http.StatusBadRequest,
			desc:       "Should reject malformed JSON",
		},
		{
			name:       "EmptyColor",
			body:       `{"title":"Test","color":""}`,
			wantStatus: http.StatusOK, // Should use default
			desc:       "Should handle empty color with default",
		},
		{
			name:       "ValidEpic",
			body:       `{"title":"Valid Epic","description":"Good","status":"active","color":"#FF0000"}`,
			wantStatus: http.StatusOK,
			desc:       "Should accept valid epic",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/epics", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			addAuthToRequest(req, sessionID, csrfToken)
			w := httptest.NewRecorder()
			
			app.handleAPIEpics(w, req)
			
			if w.Code != tt.wantStatus {
				t.Errorf("%s: got status %d, want %d. Response: %s", 
					tt.desc, w.Code, tt.wantStatus, w.Body.String())
			}
			
			// For XSS test, verify stored data (HTML encoding is OK for security)
			if tt.name == "XSSInTitle" && w.Code == http.StatusOK {
				var response map[string]interface{}
				json.NewDecoder(w.Body).Decode(&response)
				epicID := int64(response["id"].(float64))
				
				var title string
				err := app.db.QueryRow("SELECT title FROM epics WHERE id = ?", epicID).Scan(&title)
				if err != nil {
					t.Fatal(err)
				}
				// Title may be HTML-encoded for safety, which is fine
				// The important thing is it doesn't execute as script
				if strings.Contains(title, "<script>") && !strings.Contains(title, "&lt;script&gt;") {
					t.Errorf("Unescaped script tag in stored title: %s", title)
				}
			}
		})
	}
}

// TestIssueEpicAssignment tests assigning/removing issues to/from epics
func TestIssueEpicAssignment(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	
	// Enable foreign keys for proper constraint enforcement
	db.Exec("PRAGMA foreign_keys = ON")
	
	runMigrations(db)
	
	app := &App{
		db:          db,
		rateLimiter: NewRateLimiter(),
		config: Config{
			SessionSecret: "test-secret-key-for-testing-only",
		},
	}
	
	userID, sessionID, csrfToken := createTestUserSession(t, app)
	
	// Create test epic
	var epicID int64
	result, err := app.db.Exec(`
		INSERT INTO epics (user_id, title, description) VALUES (?, ?, ?)`,
		userID, "Test Epic", "For issue assignment")
	if err != nil {
		t.Fatal(err)
	}
	epicID, _ = result.LastInsertId()
	
	// Create test issues
	var issueID1, issueID2 int64
	result, err = app.db.Exec(`
		INSERT INTO issues (github_id, number, title, state) VALUES (?, ?, ?, ?)`,
		1001, 1, "Issue 1", "open")
	if err != nil {
		t.Fatal(err)
	}
	issueID1, _ = result.LastInsertId()
	
	result, err = app.db.Exec(`
		INSERT INTO issues (github_id, number, title, state) VALUES (?, ?, ?, ?)`,
		1002, 2, "Issue 2", "open")
	if err != nil {
		t.Fatal(err)
	}
	issueID2, _ = result.LastInsertId()
	
	// Test assigning issue to epic
	t.Run("AssignIssueToEpic", func(t *testing.T) {
		body := fmt.Sprintf(`{"issue_id":%d}`, issueID1)
		req := httptest.NewRequest("POST", fmt.Sprintf("/api/epics/%d/issues", epicID), strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		addAuthToRequest(req, sessionID, csrfToken)
		w := httptest.NewRecorder()
		
		app.handleAPIEpic(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("Failed to assign issue: %d - %s", w.Code, w.Body.String())
		}
		
		// Verify assignment in database
		var count int
		err := app.db.QueryRow(`
			SELECT COUNT(*) FROM issue_epics WHERE issue_id = ? AND epic_id = ?`,
			issueID1, epicID).Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Error("Issue not assigned to epic in database")
		}
	})
	
	// Test duplicate assignment (should be idempotent)
	t.Run("DuplicateAssignmentIsIdempotent", func(t *testing.T) {
		body := fmt.Sprintf(`{"issue_id":%d}`, issueID1)
		req := httptest.NewRequest("POST", fmt.Sprintf("/api/epics/%d/issues", epicID), strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		addAuthToRequest(req, sessionID, csrfToken)
		w := httptest.NewRecorder()
		
		app.handleAPIEpic(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("Duplicate assignment failed: %d", w.Code)
		}
		
		// Should still have only one assignment
		var count int
		err := app.db.QueryRow(`
			SELECT COUNT(*) FROM issue_epics WHERE issue_id = ? AND epic_id = ?`,
			issueID1, epicID).Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("Duplicate assignment created multiple records: %d", count)
		}
	})
	
	// Test removing issue from epic
	t.Run("RemoveIssueFromEpic", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", fmt.Sprintf("/api/epics/%d/issues?issue_id=%d", epicID, issueID1), nil)
		addAuthToRequest(req, sessionID, csrfToken)
		w := httptest.NewRecorder()
		
		app.handleAPIEpic(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("Failed to remove issue: %d - %s", w.Code, w.Body.String())
		}
		
		// Verify removal from database
		var count int
		err := app.db.QueryRow(`
			SELECT COUNT(*) FROM issue_epics WHERE issue_id = ? AND epic_id = ?`,
			issueID1, epicID).Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Error("Issue not removed from epic in database")
		}
	})
	
	// Test invalid issue assignment
	t.Run("AssignNonExistentIssue", func(t *testing.T) {
		body := `{"issue_id":99999}`
		req := httptest.NewRequest("POST", fmt.Sprintf("/api/epics/%d/issues", epicID), strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		addAuthToRequest(req, sessionID, csrfToken)
		w := httptest.NewRecorder()
		
		app.handleAPIEpic(w, req)
		
		// Should succeed (INSERT OR IGNORE) but not create invalid reference
		if w.Code == http.StatusOK {
			var count int
			err := app.db.QueryRow(`
				SELECT COUNT(*) FROM issue_epics WHERE issue_id = 99999`,
			).Scan(&count)
			if err != nil {
				t.Fatal(err)
			}
			// Due to foreign key constraint, this should not exist
			if count > 0 {
				t.Error("Created assignment for non-existent issue")
			}
		}
	})
	
	_ = issueID2 // Silence unused variable warning
}

// TestEpicCascadeDelete tests that deleting an epic removes associations
func TestEpicCascadeDelete(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	
	// Enable foreign keys for cascade deletes
	_, err = db.Exec("PRAGMA foreign_keys = ON")
	if err != nil {
		t.Fatal(err)
	}
	
	runMigrations(db)
	
	app := &App{
		db:          db,
		rateLimiter: NewRateLimiter(),
		config: Config{
			SessionSecret: "test-secret-key-for-testing-only",
		},
	}
	
	userID, sessionID, csrfToken := createTestUserSession(t, app)
	
	// Create epic
	result, err := app.db.Exec(`
		INSERT INTO epics (user_id, title) VALUES (?, ?)`,
		userID, "Epic to Delete")
	if err != nil {
		t.Fatal(err)
	}
	epicID, _ := result.LastInsertId()
	
	// Create issue and assign to epic
	result, err = app.db.Exec(`
		INSERT INTO issues (github_id, number, title, state) VALUES (?, ?, ?, ?)`,
		2001, 10, "Test Issue", "open")
	if err != nil {
		t.Fatal(err)
	}
	issueID, _ := result.LastInsertId()
	
	_, err = app.db.Exec(`
		INSERT INTO issue_epics (issue_id, epic_id) VALUES (?, ?)`,
		issueID, epicID)
	if err != nil {
		t.Fatal(err)
	}
	
	// Delete the epic
	req := httptest.NewRequest("DELETE", fmt.Sprintf("/api/epics/%d", epicID), nil)
	addAuthToRequest(req, sessionID, csrfToken)
	w := httptest.NewRecorder()
	
	app.handleAPIEpic(w, req)
	
	if w.Code != http.StatusNoContent {
		t.Errorf("Failed to delete epic: %d", w.Code)
	}
	
	// Verify epic is deleted
	var epicCount int
	err = app.db.QueryRow("SELECT COUNT(*) FROM epics WHERE id = ?", epicID).Scan(&epicCount)
	if err != nil {
		t.Fatal(err)
	}
	if epicCount != 0 {
		t.Error("Epic not deleted")
	}
	
	// Verify issue_epics association is deleted (cascade)
	var assocCount int
	err = app.db.QueryRow("SELECT COUNT(*) FROM issue_epics WHERE epic_id = ?", epicID).Scan(&assocCount)
	if err != nil {
		t.Fatal(err)
	}
	if assocCount != 0 {
		t.Error("Issue-epic associations not cascade deleted")
	}
	
	// Verify issue still exists
	var issueCount int
	err = app.db.QueryRow("SELECT COUNT(*) FROM issues WHERE id = ?", issueID).Scan(&issueCount)
	if err != nil {
		t.Fatal(err)
	}
	if issueCount != 1 {
		t.Error("Issue was incorrectly deleted")
	}
}

// TestEpicUpdateValidation tests epic update operations
func TestEpicUpdateValidation(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	
	// Enable foreign keys
	db.Exec("PRAGMA foreign_keys = ON")
	
	runMigrations(db)
	
	app := &App{
		db:          db,
		rateLimiter: NewRateLimiter(),
		config: Config{
			SessionSecret: "test-secret-key-for-testing-only",
		},
	}
	
	userID, sessionID, csrfToken := createTestUserSession(t, app)
	
	// Create epic
	result, err := app.db.Exec(`
		INSERT INTO epics (user_id, title, description, status) VALUES (?, ?, ?, ?)`,
		userID, "Original Title", "Original Desc", "active")
	if err != nil {
		t.Fatal(err)
	}
	epicID, _ := result.LastInsertId()
	
	tests := []struct {
		name       string
		body       string
		wantStatus int
		check      func(t *testing.T)
	}{
		{
			name:       "ValidUpdate",
			body:       `{"title":"Updated Title","description":"Updated Desc","status":"completed"}`,
			wantStatus: http.StatusOK,
			check: func(t *testing.T) {
				var title, status string
				err := app.db.QueryRow("SELECT title, status FROM epics WHERE id = ?", epicID).Scan(&title, &status)
				if err != nil {
					t.Fatal(err)
				}
				if title != "Updated Title" {
					t.Errorf("Title not updated: %s", title)
				}
				if status != "completed" {
					t.Errorf("Status not updated: %s", status)
				}
			},
		},
		{
			name:       "InvalidStatus",
			body:       `{"title":"Title","status":"invalid_status"}`,
			wantStatus: http.StatusBadRequest,
			check:      func(t *testing.T) {},
		},
		{
			name:       "PartialUpdate",
			body:       `{"title":"Original Title","description":"Only update description","status":"active","color":"","owner":""}`,
			wantStatus: http.StatusOK,
			check: func(t *testing.T) {
				var title, desc, status string
				err := app.db.QueryRow("SELECT title, description, status FROM epics WHERE id = ?", epicID).Scan(&title, &desc, &status)
				if err != nil {
					t.Fatal(err)
				}
				if desc != "Only update description" {
					t.Errorf("Description not updated: %s", desc)
				}
				if title != "Original Title" {
					t.Errorf("Title was changed: %s", title)
				}
				if status != "active" {
					t.Errorf("Status was changed: %s", status)
				}
			},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("PUT", fmt.Sprintf("/api/epics/%d", epicID), strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			addAuthToRequest(req, sessionID, csrfToken)
			w := httptest.NewRecorder()
			
			app.handleAPIEpic(w, req)
			
			if w.Code != tt.wantStatus {
				t.Errorf("Got status %d, want %d. Response: %s", 
					w.Code, tt.wantStatus, w.Body.String())
			}
			
			tt.check(t)
		})
	}
}

// TestThemeEpicRelationship tests theme-epic relationships
func TestThemeEpicRelationship(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	
	// Enable foreign keys
	db.Exec("PRAGMA foreign_keys = ON")
	
	runMigrations(db)
	
	app := &App{
		db:          db,
		rateLimiter: NewRateLimiter(),
		config: Config{
			SessionSecret: "test-secret-key-for-testing-only",
		},
	}
	
	userID, sessionID, csrfToken := createTestUserSession(t, app)
	
	// Create theme
	result, err := app.db.Exec(`
		INSERT INTO themes (user_id, name, quarter) VALUES (?, ?, ?)`,
		userID, "Q1 Theme", "2024-Q1")
	if err != nil {
		t.Fatal(err)
	}
	themeID, _ := result.LastInsertId()
	
	// Create epics
	result, err = app.db.Exec(`
		INSERT INTO epics (user_id, title) VALUES (?, ?)`,
		userID, "Epic 1")
	if err != nil {
		t.Fatal(err)
	}
	epic1ID, _ := result.LastInsertId()
	
	result, err = app.db.Exec(`
		INSERT INTO epics (user_id, title) VALUES (?, ?)`,
		userID, "Epic 2")
	if err != nil {
		t.Fatal(err)
	}
	epic2ID, _ := result.LastInsertId()
	
	// Assign epic to theme
	t.Run("AssignEpicToTheme", func(t *testing.T) {
		body := fmt.Sprintf(`{"epic_id":%d}`, epic1ID)
		req := httptest.NewRequest("POST", fmt.Sprintf("/api/themes/%d/epics", themeID), strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		addAuthToRequest(req, sessionID, csrfToken)
		w := httptest.NewRecorder()
		
		app.handleAPITheme(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("Failed to assign epic to theme: %d - %s", w.Code, w.Body.String())
		}
		
		// Verify in database
		var count int
		err := app.db.QueryRow(`
			SELECT COUNT(*) FROM epic_themes WHERE epic_id = ? AND theme_id = ?`,
			epic1ID, themeID).Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Error("Epic not assigned to theme")
		}
	})
	
	// Remove epic from theme
	t.Run("RemoveEpicFromTheme", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", fmt.Sprintf("/api/themes/%d/epics?epic_id=%d", themeID, epic1ID), nil)
		addAuthToRequest(req, sessionID, csrfToken)
		w := httptest.NewRecorder()
		
		app.handleAPITheme(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("Failed to remove epic from theme: %d", w.Code)
		}
		
		// Verify removal
		var count int
		err := app.db.QueryRow(`
			SELECT COUNT(*) FROM epic_themes WHERE epic_id = ? AND theme_id = ?`,
			epic1ID, themeID).Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Error("Epic not removed from theme")
		}
	})
	
	_ = epic2ID // Silence unused variable warning
}

// TestReportDataIntegrity tests that reports accurately reflect data
func TestReportDataIntegrity(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	
	// Enable foreign keys
	db.Exec("PRAGMA foreign_keys = ON")
	
	runMigrations(db)
	
	app := &App{
		db:          db,
		rateLimiter: NewRateLimiter(),
		config: Config{
			SessionSecret: "test-secret-key-for-testing-only",
		},
	}
	
	userID, sessionID, csrfToken := createTestUserSession(t, app)
	
	// Create test data
	// 2 themes
	result, err := app.db.Exec(`INSERT INTO themes (user_id, name, status) VALUES (?, ?, ?)`,
		userID, "Theme 1", "in_progress")
	if err != nil {
		t.Fatal(err)
	}
	theme1ID, _ := result.LastInsertId()
	
	result, err = app.db.Exec(`INSERT INTO themes (user_id, name, status) VALUES (?, ?, ?)`,
		userID, "Theme 2", "completed")
	if err != nil {
		t.Fatal(err)
	}
	theme2ID, _ := result.LastInsertId()
	
	// 3 epics
	result, err = app.db.Exec(`INSERT INTO epics (user_id, title, status) VALUES (?, ?, ?)`,
		userID, "Epic 1", "active")
	if err != nil {
		t.Fatal(err)
	}
	epic1ID, _ := result.LastInsertId()
	
	result, err = app.db.Exec(`INSERT INTO epics (user_id, title, status) VALUES (?, ?, ?)`,
		userID, "Epic 2", "completed")
	if err != nil {
		t.Fatal(err)
	}
	epic2ID, _ := result.LastInsertId()
	
	result, err = app.db.Exec(`INSERT INTO epics (user_id, title, status) VALUES (?, ?, ?)`,
		userID, "Epic 3", "archived")
	if err != nil {
		t.Fatal(err)
	}
	epic3ID, _ := result.LastInsertId()
	
	// 5 issues
	issueIDs := make([]int64, 5)
	for i := 0; i < 5; i++ {
		state := "open"
		if i > 2 {
			state = "closed"
		}
		result, err = app.db.Exec(`INSERT INTO issues (github_id, number, title, state) VALUES (?, ?, ?, ?)`,
			3000+i, 100+i, fmt.Sprintf("Issue %d", i+1), state)
		if err != nil {
			t.Fatal(err)
		}
		issueIDs[i], _ = result.LastInsertId()
	}
	
	// Assign epics to themes
	app.db.Exec(`INSERT INTO epic_themes (epic_id, theme_id) VALUES (?, ?)`, epic1ID, theme1ID)
	app.db.Exec(`INSERT INTO epic_themes (epic_id, theme_id) VALUES (?, ?)`, epic2ID, theme1ID)
	
	// Assign issues to epics
	app.db.Exec(`INSERT INTO issue_epics (issue_id, epic_id) VALUES (?, ?)`, issueIDs[0], epic1ID)
	app.db.Exec(`INSERT INTO issue_epics (issue_id, epic_id) VALUES (?, ?)`, issueIDs[1], epic1ID)
	app.db.Exec(`INSERT INTO issue_epics (issue_id, epic_id) VALUES (?, ?)`, issueIDs[2], epic2ID)
	
	// Get report summary
	req := httptest.NewRequest("GET", "/api/reports?type=summary", nil)
	addAuthToRequest(req, sessionID, csrfToken)
	w := httptest.NewRecorder()
	
	app.handleAPIReports(w, req)
	
	if w.Code != http.StatusOK {
		t.Fatalf("Failed to get report: %d - %s", w.Code, w.Body.String())
	}
	
	var response struct {
		Summary struct {
			TotalIssues       int     `json:"total_issues"`
			OpenIssues        int     `json:"open_issues"`
			ClosedIssues      int     `json:"closed_issues"`
			TotalEpics        int     `json:"total_epics"`
			ActiveEpics       int     `json:"active_epics"`
			CompletedEpics    int     `json:"completed_epics"`
			TotalThemes       int     `json:"total_themes"`
			CurrentQuarter    string  `json:"current_quarter"`
			OverallProgress   float64 `json:"overall_progress"`
		} `json:"summary"`
	}
	
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	
	report := response.Summary
	
	// Verify counts
	if report.TotalIssues != 5 {
		t.Errorf("TotalIssues: got %d, want 5", report.TotalIssues)
	}
	if report.OpenIssues != 3 {
		t.Errorf("OpenIssues: got %d, want 3", report.OpenIssues)
	}
	if report.ClosedIssues != 2 {
		t.Errorf("ClosedIssues: got %d, want 2", report.ClosedIssues)
	}
	if report.TotalEpics != 3 {
		t.Errorf("TotalEpics: got %d, want 3", report.TotalEpics)
	}
	if report.ActiveEpics != 1 {
		t.Errorf("ActiveEpics: got %d, want 1", report.ActiveEpics)
	}
	if report.CompletedEpics != 1 {
		t.Errorf("CompletedEpics: got %d, want 1", report.CompletedEpics)
	}
	if report.TotalThemes != 2 {
		t.Errorf("TotalThemes: got %d, want 2", report.TotalThemes)
	}
	// Check overall progress calculation
	expectedProgress := (2.0 / 5.0) * 100 // 2 closed out of 5 total
	if report.OverallProgress != expectedProgress {
		t.Errorf("OverallProgress: got %.2f, want %.2f", report.OverallProgress, expectedProgress)
	}
	
	_ = theme2ID
	_ = epic3ID
}
// TestConcurrentEpicOperations tests multiple epic operations  
// SQLite doesn't handle concurrent writes well, so we test sequential operations
func TestConcurrentEpicOperations(t *testing.T) {
	// Use a temporary file for better SQLite behavior
	tmpfile := t.TempDir() + "/test.db"
	db, err := sql.Open("sqlite", tmpfile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	
	// Enable WAL mode for better concurrency
	db.Exec("PRAGMA journal_mode = WAL")
	
	// Enable foreign keys
	_, err = db.Exec("PRAGMA foreign_keys = ON")
	if err != nil {
		t.Fatal(err)
	}
	
	runMigrations(db)
	
	// Verify table exists
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='issue_epics'").Scan(&count)
	if err != nil || count == 0 {
		t.Fatal("issue_epics table not created")
	}
	
	app := &App{
		db:          db,
		rateLimiter: NewRateLimiter(),
		config: Config{
			SessionSecret: "test-secret-key-for-testing-only",
		},
	}
	
	userID, sessionID, csrfToken := createTestUserSession(t, app)
	
	// Create an epic
	result, err := app.db.Exec(`INSERT INTO epics (user_id, title) VALUES (?, ?)`,
		userID, "Concurrent Test Epic")
	if err != nil {
		t.Fatal(err)
	}
	epicID, _ := result.LastInsertId()
	
	// Create multiple issues
	issueIDs := make([]int64, 10)
	for i := 0; i < 10; i++ {
		result, err = app.db.Exec(`INSERT INTO issues (github_id, number, title, state) VALUES (?, ?, ?, ?)`,
			4000+i, 400+i, fmt.Sprintf("Issue %d", i), "open")
		if err != nil {
			t.Fatal(err)
		}
		issueIDs[i], _ = result.LastInsertId()
	}
	
	// Assign issues sequentially (SQLite limitation)
	successCount := 0
	for _, issueID := range issueIDs {
		body := fmt.Sprintf(`{"issue_id":%d}`, issueID)
		req := httptest.NewRequest("POST", fmt.Sprintf("/api/epics/%d/issues", epicID), 
			strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		addAuthToRequest(req, sessionID, csrfToken)
		w := httptest.NewRecorder()
		
		app.handleAPIEpic(w, req)
		
		if w.Code == http.StatusOK {
			successCount++
		}
	}
	
	// All operations should succeed
	if successCount != len(issueIDs) {
		t.Errorf("Not all assignments succeeded: %d/%d", successCount, len(issueIDs))
	}
	
	// Verify all assignments were made
	var assignmentCount int
	err = app.db.QueryRow(`SELECT COUNT(*) FROM issue_epics WHERE epic_id = ?`, epicID).Scan(&assignmentCount)
	if err != nil {
		t.Fatal(err)
	}
	if assignmentCount != len(issueIDs) {
		t.Errorf("Expected %d assignments, got %d", len(issueIDs), assignmentCount)
	}
	
	// Test idempotency
	body := fmt.Sprintf(`{"issue_id":%d}`, issueIDs[0])
	req := httptest.NewRequest("POST", fmt.Sprintf("/api/epics/%d/issues", epicID), 
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	addAuthToRequest(req, sessionID, csrfToken)
	w := httptest.NewRecorder()
	
	app.handleAPIEpic(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Idempotent assignment failed: %d", w.Code)
	}
}
// TestEpicHTMLEscaping verifies HTML content is properly escaped in API responses
func TestEpicHTMLEscaping(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	
	runMigrations(db)
	
	app := &App{
		db:          db,
		rateLimiter: NewRateLimiter(),
		config: Config{
			SessionSecret: "test-secret-key-for-testing-only",
		},
	}
	
	userID, sessionID, _ := createTestUserSession(t, app)
	
	// Create epic with XSS attempt in title and description
	_, err = app.db.Exec(`
		INSERT INTO epics (user_id, title, description) VALUES (?, ?, ?)`,
		userID, 
		`<script>alert('XSS')</script>Epic`, 
		`Description with <img src=x onerror="alert('XSS')">`)
	if err != nil {
		t.Fatal(err)
	}
	
	// Test API endpoint returns properly escaped JSON
	req := httptest.NewRequest("GET", "/api/epics", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: sessionID})
	w := httptest.NewRecorder()
	
	app.handleAPIEpics(w, req)
	
	if w.Code != http.StatusOK {
		t.Fatalf("Failed to get epics: %d", w.Code)
	}
	
	var epics []struct {
		Title       string `json:"title"`
		Description string `json:"description"`
	}
	
	if err := json.NewDecoder(w.Body).Decode(&epics); err != nil {
		t.Fatal(err)
	}
	
	if len(epics) == 0 {
		t.Fatal("No epics returned")
	}
	
	epic := epics[0]
	
	// Verify the XSS payloads are present but safely encoded in JSON
	if epic.Title != `<script>alert('XSS')</script>Epic` {
		t.Errorf("Title incorrectly modified: got %q", epic.Title)
	}
	
	if epic.Description != `Description with <img src=x onerror="alert('XSS')">` {
		t.Errorf("Description incorrectly modified: got %q", epic.Description)
	}
	
	// Test that when rendered in HTML context via template, it would be escaped
	// This tests that we're not pre-escaping in the database
	tmpl := template.Must(template.New("test").Parse(`{{.Title}}`)) 
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, epic); err != nil {
		t.Fatal(err)
	}
	
	// Go's html/template automatically escapes, verify it works
	if strings.Contains(buf.String(), "<script>") {
		t.Error("Template did not escape script tag")
	}
	if strings.Contains(buf.String(), "&lt;script&gt;") {
		t.Log("Template correctly escaped script tag")
	}
}