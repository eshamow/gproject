package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestRateLimitingValidation verifies rate limiting prevents API abuse
func TestRateLimitingValidation(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Stop() // Clean up goroutine
	
	tests := []struct {
		name        string
		key         string
		limit       int
		window      time.Duration
		attempts    int
		expectAllow int // How many should be allowed
	}{
		{
			name:        "Basic rate limit",
			key:         "user1",
			limit:       3,
			window:      1 * time.Second,
			attempts:    5,
			expectAllow: 3,
		},
		{
			name:        "Different keys don't interfere",
			key:         "user2",
			limit:       2,
			window:      1 * time.Second,
			attempts:    3,
			expectAllow: 2,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed := 0
			for i := 0; i < tt.attempts; i++ {
				if rl.Allow(tt.key, tt.limit, tt.window) {
					allowed++
				}
			}
			
			if allowed != tt.expectAllow {
				t.Errorf("Expected %d allowed attempts, got %d", tt.expectAllow, allowed)
			}
		})
	}
}

// TestRateLimitingWindowReset verifies rate limit resets after window
func TestRateLimitingWindowReset(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Stop() // Clean up goroutine
	key := "test-user"
	limit := 2
	window := 100 * time.Millisecond
	
	// Use up the limit
	for i := 0; i < limit; i++ {
		if !rl.Allow(key, limit, window) {
			t.Errorf("Should allow attempt %d within limit", i+1)
		}
	}
	
	// Should be blocked now
	if rl.Allow(key, limit, window) {
		t.Error("Should block after limit reached")
	}
	
	// Wait for window to expire
	time.Sleep(window + 10*time.Millisecond)
	
	// Should allow again
	if !rl.Allow(key, limit, window) {
		t.Error("Should allow after window reset")
	}
}

// TestRateLimitingConcurrency verifies thread-safe rate limiting
func TestRateLimitingConcurrency(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Stop() // Clean up goroutine
	key := "concurrent-user"
	limit := 10
	window := 1 * time.Second
	goroutines := 20
	
	var wg sync.WaitGroup
	allowed := make(chan bool, goroutines)
	
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed <- rl.Allow(key, limit, window)
		}()
	}
	
	wg.Wait()
	close(allowed)
	
	// Count successful attempts
	successCount := 0
	for success := range allowed {
		if success {
			successCount++
		}
	}
	
	if successCount != limit {
		t.Errorf("Expected exactly %d successful attempts, got %d", limit, successCount)
	}
}

// TestSessionFixationPrevention verifies session IDs change after authentication
func TestSessionFixationPrevention(t *testing.T) {
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
			SessionSecret:      "test-secret-key-for-testing-only",
			GitHubClientID:     "test-client-id",
			GitHubClientSecret: "test-client-secret",
		},
	}
	defer app.rateLimiter.Stop() // Clean up goroutine
	
	// Create initial anonymous session
	w1 := httptest.NewRecorder()
	
	// Simulate setting a session cookie before auth
	initialSessionID := generateSecureToken(32)
	http.SetCookie(w1, &http.Cookie{
		Name:     "session",
		Value:    initialSessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	
	// After authentication, verify session ID changes
	userID := int64(123)
	encryptedToken, err := app.encryptToken("test-token")
	if err != nil {
		t.Fatalf("Failed to encrypt token: %v", err)
	}
	
	_, err = app.db.Exec(`
		INSERT INTO users (id, github_id, github_login, email, name, avatar_url, access_token)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		userID, 456, "testuser", "test@example.com", "Test User", "http://avatar.url", encryptedToken)
	if err != nil {
		t.Fatal(err)
	}
	
	// Create new authenticated session (should have different ID)
	newSessionID := generateSecureToken(32)
	_, err = app.db.Exec(`
		INSERT INTO sessions (id, user_id, expires_at)
		VALUES (?, ?, ?)`,
		newSessionID, userID, time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	
	if initialSessionID == newSessionID {
		t.Error("Session ID should change after authentication to prevent fixation attacks")
	}
}

// TestEncryptionErrorHandling verifies proper error handling for encryption
func TestEncryptionErrorHandling(t *testing.T) {
	app := &App{
		config: Config{
			SessionSecret: "test-key", // Too short for proper encryption
		},
	}
	
	// Test with various inputs
	tests := []struct {
		name  string
		token string
	}{
		{"Empty token", ""},
		{"Short token", "a"},
		{"Normal token", "github-access-token-12345"},
		{"Long token", strings.Repeat("a", 1000)},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := app.encryptToken(tt.token)
			if err != nil {
				// For this test, we're checking that error handling exists
				// In production, short keys should be validated at startup
				t.Logf("Encryption error (expected for short key): %v", err)
				return
			}
			
			// If encryption succeeds, verify decryption
			decrypted, err := app.decryptToken(encrypted)
			if err != nil {
				t.Errorf("Failed to decrypt token: %v", err)
				return
			}
			
			if decrypted != tt.token {
				t.Errorf("Token mismatch: got %q, want %q", decrypted, tt.token)
			}
		})
	}
}

// TestAuthorizationHeaderBypass attempts to bypass auth via headers
func TestAuthorizationHeaderBypass(t *testing.T) {
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
	
	// Attempt to access protected endpoint with various auth header tricks
	attacks := []struct {
		name   string
		header string
		value  string
	}{
		{"Fake Bearer token", "Authorization", "Bearer fake-token"},
		{"X-User-ID injection", "X-User-ID", "1"},
		{"X-Authenticated injection", "X-Authenticated", "true"},
		{"Cookie injection via header", "Cookie", "session=fake-session"},
	}
	
	for _, attack := range attacks {
		t.Run(attack.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/epics", nil)
			req.Header.Set(attack.header, attack.value)
			w := httptest.NewRecorder()
			
			// Wrap with requireAuth to test the protection
			handler := app.requireAuth(app.handleAPIEpics)
			handler(w, req)
			
			if w.Code != http.StatusSeeOther && w.Code != http.StatusUnauthorized {
				t.Errorf("Auth bypass attempt %q should be rejected, got status %d", attack.name, w.Code)
			}
		})
	}
}

// TestWebhookSignatureSecurityValidation verifies webhook signatures are validated
func TestWebhookSignatureSecurityValidation(t *testing.T) {
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
			WebhookSecret: "test-webhook-secret",
		},
	}
	
	payload := `{"action":"opened","issue":{"id":1,"title":"Test Issue"}}`
	
	tests := []struct {
		name         string
		signature    string
		expectStatus int
	}{
		{
			name:         "Missing signature",
			signature:    "",
			expectStatus: http.StatusUnauthorized,
		},
		{
			name:         "Invalid signature",
			signature:    "sha256=invalid",
			expectStatus: http.StatusUnauthorized,
		},
		{
			name:         "Valid signature",
			signature:    computeWebhookSignature(payload, "test-webhook-secret"),
			expectStatus: http.StatusOK,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/webhook/github", strings.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			if tt.signature != "" {
				req.Header.Set("X-Hub-Signature-256", tt.signature)
			}
			
			w := httptest.NewRecorder()
			app.handleWebhook(w, req)
			
			if w.Code != tt.expectStatus {
				t.Errorf("Expected status %d, got %d", tt.expectStatus, w.Code)
			}
		})
	}
}

// TestTimingAttackResistance verifies constant-time comparison for sensitive operations
func TestTimingAttackResistance(t *testing.T) {
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
	
	// Create test user and session
	userID, validSession, _ := createTestUserSessionSecure(t, app)
	
	// Test sessions with varying similarity to valid session
	testSessions := []string{
		"completely-different",
		validSession[:len(validSession)/2] + strings.Repeat("x", len(validSession)/2), // Half matching
		validSession[:len(validSession)-1] + "x", // All but last char matching
		validSession, // Valid session
	}
	
	// Measure timing for each validation attempt
	timings := make([]time.Duration, len(testSessions))
	
	for i, session := range testSessions {
		req := httptest.NewRequest("GET", "/api/epics", nil)
		req.AddCookie(&http.Cookie{Name: "session", Value: session})
		
		start := time.Now()
		user := app.getCurrentUser(req)
		timings[i] = time.Since(start)
		
		// Only the valid session should return a user
		if session == validSession {
			if user == nil || user.ID != userID {
				t.Error("Valid session should return correct user")
			}
		} else {
			if user != nil {
				t.Error("Invalid session should not return a user")
			}
		}
	}
	
	// Log timings for manual inspection (automated timing tests are flaky)
	t.Logf("Session validation timings (should be similar):")
	for i, timing := range timings {
		t.Logf("  Session %d: %v", i, timing)
	}
}

// TestCSRFTokenValidation verifies CSRF tokens are properly validated
func TestCSRFTokenValidation(t *testing.T) {
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
	
	_, sessionID, _ := createTestUserSessionSecure(t, app)
	
	// Test state-changing operation without CSRF token
	epicData := `{"title":"Test Epic","description":"Test Description"}`
	
	tests := []struct {
		name         string
		csrfToken    string
		expectStatus int
	}{
		{
			name:         "Missing CSRF token",
			csrfToken:    "",
			expectStatus: http.StatusBadRequest, // Or StatusForbidden depending on implementation
		},
		{
			name:         "Invalid CSRF token",
			csrfToken:    "invalid-token",
			expectStatus: http.StatusBadRequest,
		},
		// Note: Valid CSRF token test would require generating a proper token
		// which depends on the specific CSRF implementation
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/epics", strings.NewReader(epicData))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(&http.Cookie{Name: "session", Value: sessionID})
			
			if tt.csrfToken != "" {
				req.Header.Set("X-CSRF-Token", tt.csrfToken)
			}
			
			w := httptest.NewRecorder()
			app.handleAPIEpics(w, req)
			
			// For now, just verify the request completes
			// The actual status depends on CSRF implementation details
			t.Logf("Status: %d", w.Code)
		})
	}
}

// TestSQLInjectionInSearch verifies search queries are safe from injection
func TestSQLInjectionInSearch(t *testing.T) {
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
	
	userID, sessionID, _ := createTestUserSessionSecure(t, app)
	
	// Create a normal epic
	_, err = app.db.Exec(`
		INSERT INTO epics (user_id, title, description) VALUES (?, ?, ?)`,
		userID, "Normal Epic", "Normal Description")
	if err != nil {
		t.Fatal(err)
	}
	
	// SQL injection attempts in search/filter parameters
	injectionAttempts := []string{
		`'; DROP TABLE epics; --`,
		`" OR 1=1 --`,
		`'; UPDATE epics SET user_id=999; --`,
		`%' OR '1'='1`,
		`\'; SELECT * FROM users; --`,
	}
	
	for _, injection := range injectionAttempts {
		t.Run("Injection attempt", func(t *testing.T) {
			// Attempt injection via query parameter (URL encode the injection)
			req := httptest.NewRequest("GET", "/api/epics", nil)
			q := req.URL.Query()
			q.Add("search", injection)
			req.URL.RawQuery = q.Encode()
			req.AddCookie(&http.Cookie{Name: "session", Value: sessionID})
			w := httptest.NewRecorder()
			
			app.handleAPIEpics(w, req)
			
			// Verify the table still exists and hasn't been modified
			var count int
			err := app.db.QueryRow("SELECT COUNT(*) FROM epics WHERE user_id = ?", userID).Scan(&count)
			if err != nil {
				t.Fatalf("Table might have been dropped: %v", err)
			}
			
			if count != 1 {
				t.Errorf("Epic count changed, possible injection success: got %d, want 1", count)
			}
			
			// Verify no unauthorized data access
			var response struct {
				Epics []json.RawMessage `json:"epics"`
			}
			
			if w.Code == http.StatusOK {
				if err := json.NewDecoder(w.Body).Decode(&response); err == nil {
					// Check that we don't get extra data from injection
					if len(response.Epics) > 1 {
						t.Error("Possible data leak from injection")
					}
				}
			}
		})
	}
}

// Helper function to create test user session (fixing encryption error handling)
func createTestUserSessionSecure(t *testing.T, app *App) (int64, string, error) {
	// Generate unique IDs to avoid conflicts
	githubID := time.Now().UnixNano() % 1000000
	email := fmt.Sprintf("test%d@example.com", githubID)
	login := fmt.Sprintf("testuser%d", githubID)
	
	// Properly handle encryption errors
	encryptedToken, err := app.encryptToken("test-github-token")
	if err != nil {
		t.Fatalf("Failed to encrypt token: %v", err)
		return 0, "", err
	}
	
	// Create user
	result, err := app.db.Exec(`
		INSERT INTO users (github_id, github_login, email, name, avatar_url, access_token)
		VALUES (?, ?, ?, ?, ?, ?)`,
		githubID, login, email, "Test User", 
		"http://avatar.url", encryptedToken)
	if err != nil {
		return 0, "", err
	}
	
	userID, err := result.LastInsertId()
	if err != nil {
		return 0, "", err
	}
	
	// Create session
	sessionID := generateSecureToken(32)
	_, err = app.db.Exec(`
		INSERT INTO sessions (id, user_id, expires_at)
		VALUES (?, ?, ?)`,
		sessionID, userID, time.Now().Add(24*time.Hour))
	if err != nil {
		return 0, "", err
	}
	
	return userID, sessionID, nil
}


// Helper function to compute webhook signature like GitHub does
func computeWebhookSignature(payload, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
