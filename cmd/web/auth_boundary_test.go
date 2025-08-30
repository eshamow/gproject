package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestAuthenticationBoundaries validates that authentication boundaries are properly enforced
func TestAuthenticationBoundaries(t *testing.T) {
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
	defer app.rateLimiter.Stop() // Clean up goroutine

	t.Run("NoAuthBypass", func(t *testing.T) {
		// Create two users
		user1ID, session1ID, csrf1Token := createTestUserSession(t, app)
		user2ID, session2ID, csrf2Token := createTestUserSession(t, app)

		// Create an epic for user1
		body := `{"title":"User1 Epic","description":"Private","color":"#FF0000","owner":"user1","status":"active"}`
		req := httptest.NewRequest("POST", "/api/epics", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		addAuthToRequest(req, session1ID, csrf1Token)
		w := httptest.NewRecorder()

		app.handleAPIEpics(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Failed to create epic: %d", w.Code)
		}

		// Try to access user1's epics with user2's credentials
		req2 := httptest.NewRequest("GET", "/api/epics", nil)
		addAuthToRequest(req2, session2ID, csrf2Token)
		w2 := httptest.NewRecorder()

		app.handleAPIEpics(w2, req2)

		if w2.Code != http.StatusOK {
			t.Fatalf("Failed to get epics: %d", w2.Code)
		}

		var epics []map[string]interface{}
		json.NewDecoder(w2.Body).Decode(&epics)

		// User2 should not see User1's epics
		if len(epics) != 0 {
			t.Errorf("User2 can see User1's epics - data isolation breach!")
		}

		// Verify the epic actually exists for user1
		var count int
		err = app.db.QueryRow("SELECT COUNT(*) FROM epics WHERE user_id = ?", user1ID).Scan(&count)
		if err != nil || count != 1 {
			t.Errorf("Epic not created for user1: %v", err)
		}

		// Verify no epics exist for user2
		err = app.db.QueryRow("SELECT COUNT(*) FROM epics WHERE user_id = ?", user2ID).Scan(&count)
		if err != nil || count != 0 {
			t.Errorf("Unexpected epics for user2: %v", err)
		}
	})

	t.Run("SessionHijackingPrevention", func(t *testing.T) {
		// Create a user
		_, sessionID, csrfToken := createTestUserSession(t, app)

		// Try to use CSRF token with different session
		fakeSessionID := generateRandomString(32)

		req := httptest.NewRequest("POST", "/api/epics", strings.NewReader(`{"title":"test"}`))
		req.AddCookie(&http.Cookie{Name: "session", Value: fakeSessionID})
		req.Header.Set("X-CSRF-Token", csrfToken)

		// Should fail - CSRF token doesn't match the fake session
		if app.validateCSRFToken(req, csrfToken) {
			t.Error("CSRF token validated with wrong session - session hijacking possible!")
		}

		// Try to use session without CSRF token
		req2 := httptest.NewRequest("POST", "/api/epics", strings.NewReader(`{"title":"test"}`))
		req2.AddCookie(&http.Cookie{Name: "session", Value: sessionID})
		// No CSRF token

		if app.validateCSRFToken(req2, "") {
			t.Error("Request without CSRF token validated - CSRF vulnerability!")
		}
	})

	t.Run("ExpiredSessionRejection", func(t *testing.T) {
		// Create a session
		_, sessionID, _ := createTestUserSession(t, app)

		// Expire the session
		_, err := app.db.Exec(`
			UPDATE sessions SET expires_at = datetime('now', '-1 hour')
			WHERE id = ?
		`, sessionID)
		if err != nil {
			t.Fatalf("Failed to expire session: %v", err)
		}

		// Try to use expired session
		req := httptest.NewRequest("GET", "/api/epics", nil)
		req.AddCookie(&http.Cookie{Name: "session", Value: sessionID})

		user := app.getCurrentUser(req)
		if user != nil {
			t.Error("Expired session still valid - session timeout not enforced!")
		}
	})

	t.Run("TokenEncryption", func(t *testing.T) {
		// Create a user
		userID, _, _ := createTestUserSession(t, app)

		// Get the stored token
		var encryptedToken string
		err := app.db.QueryRow("SELECT access_token FROM users WHERE id = ?", userID).Scan(&encryptedToken)
		if err != nil {
			t.Fatalf("Failed to get token: %v", err)
		}

		// Token should not be plaintext
		if encryptedToken == "test-token" {
			t.Error("GitHub access token stored in plaintext - critical security vulnerability!")
		}

		// Token should be decryptable
		decrypted, err := app.decryptToken(encryptedToken)
		if err != nil {
			t.Errorf("Failed to decrypt token: %v", err)
		}

		if decrypted != "test-token" {
			t.Error("Token encryption/decryption mismatch")
		}
	})

	t.Run("CrossUserCSRFPrevention", func(t *testing.T) {
		// Create two users
		_, _, csrf1Token := createTestUserSession(t, app)
		_, session2ID, _ := createTestUserSession(t, app)

		// Try to use user1's CSRF token with user2's session
		req := httptest.NewRequest("POST", "/api/epics", nil)
		req.AddCookie(&http.Cookie{Name: "session", Value: session2ID})
		req.Header.Set("X-CSRF-Token", csrf1Token)

		// Should fail - CSRF token belongs to different session
		if app.validateCSRFToken(req, csrf1Token) {
			t.Error("CSRF token from one user worked with another user's session!")
		}

		// Verify in database that tokens are properly isolated
		var count int
		err := app.db.QueryRow(`
			SELECT COUNT(*) FROM csrf_tokens 
			WHERE session_id = ? AND token = ?
		`, session2ID, csrf1Token).Scan(&count)

		if err != nil || count != 0 {
			t.Error("CSRF tokens not properly isolated by session")
		}
	})

	t.Run("SQLInjectionInAuth", func(t *testing.T) {
		// Try SQL injection through session ID
		maliciousSessionID := "' OR '1'='1"
		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{Name: "session", Value: maliciousSessionID})

		user := app.getCurrentUser(req)
		if user != nil {
			t.Error("SQL injection in session lookup succeeded!")
		}

		// Try SQL injection through CSRF token
		validSession := generateRandomString(32)
		_, err := app.db.Exec(`
			INSERT INTO sessions (id, user_id, expires_at, created_at)
			VALUES (?, ?, ?, ?)`,
			validSession, 1, time.Now().Add(24*time.Hour), time.Now())

		if err != nil {
			t.Fatalf("Failed to create session: %v", err)
		}

		maliciousCSRF := "' OR '1'='1"
		req2 := httptest.NewRequest("POST", "/test", nil)
		req2.AddCookie(&http.Cookie{Name: "session", Value: validSession})

		if app.validateCSRFToken(req2, maliciousCSRF) {
			t.Error("SQL injection in CSRF validation succeeded!")
		}
	})
}

// TestRateLimitingAuth verifies rate limiting on authentication endpoints
func TestRateLimitingAuth(t *testing.T) {
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
	defer app.rateLimiter.Stop() // Clean up goroutine

	t.Run("LoginRateLimit", func(t *testing.T) {
		// Try to login many times from same IP
		clientIP := "192.168.1.1"

		for i := 0; i < 15; i++ {
			req := httptest.NewRequest("GET", "/login", nil)
			req.RemoteAddr = clientIP
			w := httptest.NewRecorder()

			app.handleLogin(w, req)

			// First 10 should succeed (redirect to GitHub)
			if i < 10 {
				if w.Code != http.StatusTemporaryRedirect {
					t.Errorf("Request %d failed unexpectedly: %d", i+1, w.Code)
				}
			} else {
				// After 10, should be rate limited
				if w.Code != http.StatusTooManyRequests {
					t.Errorf("Request %d not rate limited: %d", i+1, w.Code)
				}
			}
		}
	})
}

// TestSecurityHeaders verifies all security headers are present
func TestSecurityHeaders(t *testing.T) {
	// Setup test app
	db, _ := sql.Open("sqlite", ":memory:")
	defer db.Close()
	runMigrations(db)

	app := &App{
		db:          db,
		rateLimiter: NewRateLimiter(),
		config: Config{
			SessionSecret: "test-secret",
			Environment:   "production",
		},
	}

	// Create a request
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	// Wrap handler with security headers middleware
	handler := app.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(w, req)

	// Check all security headers
	headers := map[string]string{
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"X-XSS-Protection":          "1; mode=block",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Content-Security-Policy":   "default-src 'self'",
		"Strict-Transport-Security": "max-age=31536000",
	}

	for header, expected := range headers {
		actual := w.Header().Get(header)
		if actual == "" {
			t.Errorf("Missing security header: %s", header)
		} else if !strings.Contains(actual, expected) {
			t.Errorf("Invalid %s header: got %s, want substring %s", header, actual, expected)
		}
	}
}
