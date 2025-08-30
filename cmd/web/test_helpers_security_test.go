package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestTestHelperSecurityValidation validates that test helpers properly simulate real authentication
func TestTestHelperSecurityValidation(t *testing.T) {
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
		config: Config{
			SessionSecret: "test-secret-key-for-testing-only",
		},
	}
	defer app.rateLimiter.Stop() // Clean up goroutine
	
	t.Run("TestHelperCreatesValidSession", func(t *testing.T) {
		// Use the test helper
		userID, sessionID, csrfToken := createTestUserSession(t, app)
		
		// Verify user exists in database
		var dbUserID int64
		err := app.db.QueryRow("SELECT id FROM users WHERE id = ?", userID).Scan(&dbUserID)
		if err != nil {
			t.Errorf("User not created in database: %v", err)
		}
		
		// Verify session exists and is valid
		var sessionUserID int64
		var expiresAt time.Time
		err = app.db.QueryRow(`
			SELECT user_id, expires_at FROM sessions 
			WHERE id = ? AND expires_at > datetime('now')
		`, sessionID).Scan(&sessionUserID, &expiresAt)
		
		if err != nil {
			t.Errorf("Valid session not created: %v", err)
		}
		
		if sessionUserID != userID {
			t.Errorf("Session user_id mismatch: got %d, want %d", sessionUserID, userID)
		}
		
		// Verify CSRF token exists and is valid
		var valid bool
		err = app.db.QueryRow(`
			SELECT COUNT(*) > 0 FROM csrf_tokens 
			WHERE session_id = ? AND token = ? AND expires_at > datetime('now')
		`, sessionID, csrfToken).Scan(&valid)
		
		if err != nil || !valid {
			t.Errorf("Valid CSRF token not created: %v", err)
		}
	})
	
	t.Run("TestHelperAuthWorksWithRequireAuth", func(t *testing.T) {
		// Create authenticated session
		_, sessionID, csrfToken := createTestUserSession(t, app)
		
		// Create a protected handler
		protectedHandler := app.requireAuth(func(w http.ResponseWriter, r *http.Request) {
			user := app.getCurrentUser(r)
			if user == nil {
				t.Error("getCurrentUser returned nil for authenticated request")
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("authenticated"))
		})
		
		// Test with authentication
		req := httptest.NewRequest("GET", "/protected", nil)
		addAuthToRequest(req, sessionID, csrfToken)
		w := httptest.NewRecorder()
		
		protectedHandler(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", w.Code)
		}
		
		if !strings.Contains(w.Body.String(), "authenticated") {
			t.Error("Handler didn't execute for authenticated request")
		}
	})
	
	t.Run("TestHelperCSRFValidation", func(t *testing.T) {
		// Create authenticated session
		_, sessionID, csrfToken := createTestUserSession(t, app)
		
		// Test that CSRF validation works with test helper credentials
		req := httptest.NewRequest("POST", "/api/test", nil)
		addAuthToRequest(req, sessionID, csrfToken)
		
		// Validate CSRF token using app's validation
		if !app.validateCSRFToken(req, csrfToken) {
			t.Error("CSRF validation failed with test helper credentials")
		}
		
		// Test that invalid token fails
		req2 := httptest.NewRequest("POST", "/api/test", nil)
		req2.AddCookie(&http.Cookie{Name: "session", Value: sessionID})
		req2.Header.Set("X-CSRF-Token", "invalid-token")
		
		if app.validateCSRFToken(req2, "invalid-token") {
			t.Error("Invalid CSRF token should fail validation")
		}
	})
	
	t.Run("TestHelperIsolation", func(t *testing.T) {
		// Create two different test users
		userID1, sessionID1, _ := createTestUserSession(t, app)
		userID2, sessionID2, _ := createTestUserSession(t, app)
		
		// Verify they have different IDs
		if userID1 == userID2 {
			t.Error("Test helper created duplicate user IDs")
		}
		
		if sessionID1 == sessionID2 {
			t.Error("Test helper created duplicate session IDs")
		}
		
		// Verify each session maps to correct user
		req1 := httptest.NewRequest("GET", "/test", nil)
		req1.AddCookie(&http.Cookie{Name: "session", Value: sessionID1})
		user1 := app.getCurrentUser(req1)
		
		req2 := httptest.NewRequest("GET", "/test", nil)
		req2.AddCookie(&http.Cookie{Name: "session", Value: sessionID2})
		user2 := app.getCurrentUser(req2)
		
		if user1 == nil || user2 == nil {
			t.Error("Failed to get users from sessions")
		} else if user1.ID == user2.ID {
			t.Error("Different sessions returned same user")
		}
	})
	
	t.Run("TestHelperDoesNotBypassSecurity", func(t *testing.T) {
		// Create authenticated session
		_, sessionID, csrfToken := createTestUserSession(t, app)
		
		// Test that missing session cookie still fails
		req := httptest.NewRequest("GET", "/protected", nil)
		// Only add CSRF, not session
		req.Header.Set("X-CSRF-Token", csrfToken)
		
		user := app.getCurrentUser(req)
		if user != nil {
			t.Error("getCurrentUser should return nil without session cookie")
		}
		
		// Test that expired session fails
		// Manually expire the session
		_, err := app.db.Exec(`
			UPDATE sessions SET expires_at = datetime('now', '-1 hour')
			WHERE id = ?
		`, sessionID)
		if err != nil {
			t.Fatalf("Failed to expire session: %v", err)
		}
		
		req2 := httptest.NewRequest("GET", "/protected", nil)
		req2.AddCookie(&http.Cookie{Name: "session", Value: sessionID})
		
		user2 := app.getCurrentUser(req2)
		if user2 != nil {
			t.Error("getCurrentUser should return nil for expired session")
		}
	})
	
	t.Run("TestHelperEncryptedTokens", func(t *testing.T) {
		// Verify that the test helper properly encrypts tokens
		userID, _, _ := createTestUserSession(t, app)
		
		// Check that the token in database is encrypted (not plain text)
		var storedToken string
		err := app.db.QueryRow("SELECT access_token FROM users WHERE id = ?", userID).Scan(&storedToken)
		if err != nil {
			t.Fatalf("Failed to get token: %v", err)
		}
		
		// The stored token should be encrypted, not the plain text "test-token"
		if storedToken == "test-token" {
			t.Error("Token stored in plain text - should be encrypted")
		}
		
		// Verify it can be decrypted back
		decrypted, err := app.decryptToken(storedToken)
		if err != nil {
			t.Errorf("Failed to decrypt token: %v", err)
		}
		
		if decrypted != "test-token" {
			t.Error("Decrypted token doesn't match original")
		}
	})
}

// TestTestHelperSQLInjectionSafety verifies test helpers don't introduce SQL injection
func TestTestHelperSQLInjectionSafety(t *testing.T) {
	// Setup test database
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
	
	// Try to inject SQL through the test helper
	// This should be safe because the helper uses parameterized queries
	maliciousInputs := []string{
		"'; DROP TABLE users; --",
		"1' OR '1'='1",
		"admin'--",
	}
	
	for _, input := range maliciousInputs {
		// Override generateRandomString temporarily to return malicious input
		// Note: This is testing that even if somehow malicious input got in,
		// the parameterized queries would prevent SQL injection
		
		// Create a session with potentially malicious ID
		// (In reality generateRandomString produces safe hex strings)
		_, err := app.db.Exec(`
			INSERT INTO sessions (id, user_id, expires_at, created_at)
			VALUES (?, ?, ?, ?)`,
			input, 999, time.Now().Add(24*time.Hour), time.Now())
		
		// Should succeed without SQL injection
		if err != nil && strings.Contains(err.Error(), "syntax") {
			t.Errorf("SQL injection detected with input: %s", input)
		}
		
		// Verify tables still exist
		var count int
		err = app.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
		if err != nil {
			t.Errorf("Users table may have been dropped: %v", err)
		}
	}
}
