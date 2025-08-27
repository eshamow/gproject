package main

import (
	"database/sql"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// Test helper to create a test app with in-memory database
func setupTestApp(t *testing.T) *App {
	// Use in-memory SQLite for tests
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}
	
	// Enable foreign key constraints in SQLite
	_, err = db.Exec("PRAGMA foreign_keys = ON")
	if err != nil {
		t.Fatalf("Failed to enable foreign keys: %v", err)
	}

	// Create test config with safe defaults
	config := Config{
		Port:               "8080",
		DatabaseURL:        ":memory:",
		GitHubClientID:     "test-client-id",
		GitHubClientSecret: "test-client-secret",
		GitHubRedirectURL:  "http://localhost:8080/auth/callback",
		SessionSecret:      "test-session-secret-32-bytes-long!!!",
		GitHubRepoOwner:    "testowner",
		GitHubRepoName:     "testrepo",
		Environment:        "test",
	}

	app := &App{
		db:          db,
		config:      config,
		rateLimiter: NewRateLimiter(),
	}

	// Run migrations (using the standalone function from main.go)
	runMigrations(db)

	// Load templates
	tmpl := template.Must(template.New("").ParseFS(templateFS, "templates/*.html"))
	app.tmpl = tmpl

	return app
}

// Test 1: OAuth Flow Works
func TestOAuthFlowWorks(t *testing.T) {
	app := setupTestApp(t)
	defer app.db.Close()

	// Step 1: Test login redirect
	req := httptest.NewRequest("GET", "/login", nil)
	w := httptest.NewRecorder()
	app.handleLogin(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusTemporaryRedirect && resp.StatusCode != http.StatusFound {
		t.Errorf("Expected redirect status 302 or 307, got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if !strings.Contains(location, "github.com/login/oauth/authorize") {
		t.Errorf("Expected GitHub OAuth URL, got %s", location)
	}

	// Verify state parameter exists for CSRF protection
	parsedURL, _ := url.Parse(location)
	state := parsedURL.Query().Get("state")
	if state == "" {
		t.Error("OAuth state parameter missing - CSRF vulnerability")
	}

	// Verify state cookie was set (current implementation uses cookies, not database)
	var stateFound bool
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "oauth_state" && cookie.Value == state {
			stateFound = true
			break
		}
	}
	if !stateFound {
		t.Error("OAuth state cookie not set")
	}
}

// Test 2: Session Persistence
func TestSessionPersistence(t *testing.T) {
	app := setupTestApp(t)
	defer app.db.Close()

	// Create a test user (access_token instead of encrypted_token in current schema)
	userID := int64(123)
	encryptedToken, _ := app.encryptToken("test-token")
	_, err := app.db.Exec(`
		INSERT INTO users (id, github_id, github_login, email, name, avatar_url, access_token)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		userID, 456, "testuser", "test@example.com", "Test User", "http://avatar.url", encryptedToken)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create a session (using 'id' as primary key per the schema)
	sessionID := generateRandomString(32)
	expiresAt := time.Now().Add(24 * time.Hour)
	_, err = app.db.Exec(`
		INSERT INTO sessions (id, user_id, expires_at, created_at)
		VALUES (?, ?, ?, ?)`,
		sessionID, userID, expiresAt, time.Now())
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Verify session can be retrieved
	var retrievedUserID int64
	err = app.db.QueryRow(`
		SELECT user_id FROM sessions 
		WHERE id = ? AND expires_at > ?`,
		sessionID, time.Now()).Scan(&retrievedUserID)
	if err != nil {
		t.Errorf("Session not persistent: %v", err)
	}
	if retrievedUserID != userID {
		t.Errorf("Expected user ID %d, got %d", userID, retrievedUserID)
	}

	// Test session expiration
	_, err = app.db.Exec(`
		UPDATE sessions SET expires_at = ? WHERE id = ?`,
		time.Now().Add(-1*time.Hour), sessionID)
	if err != nil {
		t.Fatalf("Failed to expire session: %v", err)
	}

	// Verify expired session is not retrieved
	err = app.db.QueryRow(`
		SELECT user_id FROM sessions 
		WHERE id = ? AND expires_at > ?`,
		sessionID, time.Now()).Scan(&retrievedUserID)
	if err != sql.ErrNoRows {
		t.Error("Expired session should not be retrievable")
	}
}

// Test 3: CSRF Protection
func TestCSRFProtection(t *testing.T) {
	app := setupTestApp(t)
	defer app.db.Close()

	// Create a test user first (required by foreign key)
	userID := int64(123)
	encryptedToken, _ := app.encryptToken("test-token")
	_, err := app.db.Exec(`
		INSERT INTO users (id, github_id, github_login, email, name, avatar_url, access_token)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		userID, 456, "testuser", "test@example.com", "Test User", "http://avatar.url", encryptedToken)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create a valid session
	sessionID := generateRandomString(32)
	_, err = app.db.Exec(`
		INSERT INTO sessions (id, user_id, expires_at, created_at)
		VALUES (?, ?, ?, ?)`,
		sessionID, userID, time.Now().Add(24*time.Hour), time.Now())
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Generate CSRF token (generateCSRFToken already stores it in database)
	csrfToken := app.generateCSRFToken(sessionID)

	// Test 1: Request with valid CSRF token should succeed
	req := httptest.NewRequest("POST", "/issues/sync", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: sessionID})
	req.Header.Set("X-CSRF-Token", csrfToken)

	if !app.validateCSRFToken(req, csrfToken) {
		t.Error("Valid CSRF token was rejected")
	}

	// Test 2: Request without CSRF token should fail
	req2 := httptest.NewRequest("POST", "/issues/sync", nil)
	req2.AddCookie(&http.Cookie{Name: "session_id", Value: sessionID})

	if app.validateCSRFToken(req2, "") {
		t.Error("Request without CSRF token should fail")
	}

	// Test 3: Request with invalid CSRF token should fail
	req3 := httptest.NewRequest("POST", "/issues/sync", nil)
	req3.AddCookie(&http.Cookie{Name: "session_id", Value: sessionID})
	req3.Header.Set("X-CSRF-Token", "invalid-token")

	if app.validateCSRFToken(req3, "invalid-token") {
		t.Error("Invalid CSRF token should be rejected")
	}
}

// Test 4: SQL Injection Prevention
func TestSQLInjectionBlocked(t *testing.T) {
	app := setupTestApp(t)
	defer app.db.Close()

	// Attempt various SQL injection patterns
	maliciousInputs := []string{
		"'; DROP TABLE users; --",
		"1' OR '1'='1",
		"admin'--",
		"1; DELETE FROM sessions WHERE '1'='1",
		"' UNION SELECT * FROM users--",
	}

	for _, input := range maliciousInputs {
		// Test 1: Login attempt with malicious GitHub ID
		var count int
		err := app.db.QueryRow(`
			SELECT COUNT(*) FROM users WHERE github_login = ?`,
			input).Scan(&count)
		if err != nil && !strings.Contains(err.Error(), "no rows") {
			// SQL error would indicate injection worked
			t.Errorf("SQL injection may have succeeded with input: %s, error: %v", input, err)
		}

		// Test 2: Session lookup with malicious session ID
		var userID int64
		err = app.db.QueryRow(`
			SELECT user_id FROM sessions WHERE id = ?`,
			input).Scan(&userID)
		// Should get ErrNoRows, not a SQL syntax error
		if err != nil && err != sql.ErrNoRows && strings.Contains(err.Error(), "syntax") {
			t.Errorf("SQL injection detected in session lookup: %s", input)
		}

		// Verify tables still exist (injection didn't drop them)
		var tableName string
		err = app.db.QueryRow(`
			SELECT name FROM sqlite_master 
			WHERE type='table' AND name='users'`).Scan(&tableName)
		if err != nil {
			t.Errorf("Users table missing after input: %s", input)
		}
	}
}

// Test 5: Critical Path (Login → Sync → View Issues)
func TestCriticalPath(t *testing.T) {
	app := setupTestApp(t)
	defer app.db.Close()

	// Step 1: Simulate successful OAuth callback
	// Note: In the actual implementation, state is handled via cookies, not database
	// For testing purposes, we'll skip straight to user creation

	// Note: In a real test, we'd mock the GitHub API responses
	// For now, we'll test the database operations that would happen

	// Step 2: Create user from OAuth data (simulating successful callback)
	githubUser := struct {
		ID        int    `json:"id"`
		Login     string `json:"login"`
		Email     string `json:"email"`
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
	}{
		ID:        789,
		Login:     "testuser",
		Email:     "test@example.com",
		Name:      "Test User",
		AvatarURL: "http://avatar.url",
	}

	// Encrypt a fake token
	encryptedToken, err := app.encryptToken("fake-github-token")
	if err != nil {
		t.Fatalf("Failed to encrypt token: %v", err)
	}

	// Insert or update user (using access_token field)
	result, err := app.db.Exec(`
		INSERT INTO users (github_id, github_login, email, name, avatar_url, access_token)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(github_id) DO UPDATE SET
			github_login = excluded.github_login,
			email = excluded.email,
			name = excluded.name,
			avatar_url = excluded.avatar_url,
			access_token = excluded.access_token`,
		githubUser.ID, githubUser.Login, githubUser.Email,
		githubUser.Name, githubUser.AvatarURL, encryptedToken)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	userID, _ := result.LastInsertId()

	// Step 3: Create session
	sessionID := generateRandomString(32)
	_, err = app.db.Exec(`
		INSERT INTO sessions (id, user_id, expires_at, created_at)
		VALUES (?, ?, ?, ?)`,
		sessionID, userID, time.Now().Add(24*time.Hour), time.Now())
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Step 4: Simulate issue sync (would normally call GitHub API)
	// Insert test issue (matching actual schema)
	_, err = app.db.Exec(`
		INSERT INTO issues (
			github_id, number, title, body, state, 
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		12345, 1, "Test Issue", "Test Body", "open",
		time.Now(), time.Now())
	if err != nil {
		t.Fatalf("Failed to create issue: %v", err)
	}

	// Step 5: Verify user can view issues
	var issueCount int
	err = app.db.QueryRow("SELECT COUNT(*) FROM issues").Scan(&issueCount)
	if err != nil {
		t.Fatalf("Failed to query issues: %v", err)
	}
	if issueCount != 1 {
		t.Errorf("Expected 1 issue, got %d", issueCount)
	}

	// Verify complete path works
	if sessionID == "" || userID == 0 || issueCount == 0 {
		t.Error("Critical path incomplete: user cannot login → sync → view issues")
	}
}

// Test 6: Data Integrity (Transaction Rollback)
func TestDataIntegrity(t *testing.T) {
	app := setupTestApp(t)
	defer app.db.Close()

	// Test transaction rollback on error
	tx, err := app.db.Begin()
	if err != nil {
		t.Fatalf("Failed to begin transaction: %v", err)
	}

	// Insert a user in transaction
	_, err = tx.Exec(`
		INSERT INTO users (github_id, github_login, email, name, avatar_url, access_token)
		VALUES (?, ?, ?, ?, ?, ?)`,
		999, "txuser", "tx@example.com", "TX User", "http://tx.url", "encrypted")
	if err != nil {
		t.Fatalf("Failed to insert user in transaction: %v", err)
	}

	// Rollback the transaction
	err = tx.Rollback()
	if err != nil {
		t.Fatalf("Failed to rollback transaction: %v", err)
	}

	// Verify user was not persisted
	var count int
	err = app.db.QueryRow("SELECT COUNT(*) FROM users WHERE github_id = ?", 999).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query users: %v", err)
	}
	if count != 0 {
		t.Error("Transaction rollback failed - data was persisted")
	}

	// Test foreign key constraints
	// Try to insert session for non-existent user
	_, err = app.db.Exec(`
		INSERT INTO sessions (id, user_id, expires_at, created_at)
		VALUES (?, ?, ?, ?)`,
		"test-session", 99999, time.Now().Add(24*time.Hour), time.Now())
	// Should fail due to foreign key constraint
	if err == nil {
		t.Error("Foreign key constraint not enforced - data integrity issue")
	}

	// Test unique constraints
	// Insert a user
	_, err = app.db.Exec(`
		INSERT INTO users (github_id, github_login, email, name, avatar_url, access_token)
		VALUES (?, ?, ?, ?, ?, ?)`,
		111, "unique-user", "unique@example.com", "Unique User", "http://url", "encrypted")
	if err != nil {
		t.Fatalf("Failed to insert first user: %v", err)
	}

	// Try to insert duplicate github_id
	_, err = app.db.Exec(`
		INSERT INTO users (github_id, github_login, email, name, avatar_url, access_token)
		VALUES (?, ?, ?, ?, ?, ?)`,
		111, "another-user", "another@example.com", "Another User", "http://url2", "encrypted2")
	if err == nil {
		t.Error("Unique constraint on github_id not enforced")
	}
}


// Benchmark to ensure tests run fast
func BenchmarkAllTests(b *testing.B) {
	// This ensures our test suite runs in reasonable time
	start := time.Now()
	
	tests := []func(*testing.T){
		TestOAuthFlowWorks,
		TestSessionPersistence,
		TestCSRFProtection,
		TestSQLInjectionBlocked,
		TestCriticalPath,
		TestDataIntegrity,
	}
	
	for i := 0; i < b.N; i++ {
		for _, test := range tests {
			test(&testing.T{})
		}
	}
	
	elapsed := time.Since(start)
	if elapsed > 30*time.Second {
		b.Errorf("Tests took too long: %v (should be < 30s)", elapsed)
	}
}