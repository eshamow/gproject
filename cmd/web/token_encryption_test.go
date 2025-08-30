package main

import (
	"database/sql"
	"strings"
	"testing"
	
	_ "modernc.org/sqlite"
)

// TestTokenEncryption verifies GitHub token encryption/decryption
// CRITICAL: This protects user GitHub tokens in the database
func TestTokenEncryption(t *testing.T) {
	// Set up session secret used for encryption
	testSecret := "test-session-secret-for-encryption"

	app := &App{
		config: Config{
			SessionSecret: testSecret,
			EncryptionKey: testSecret,
		},
	}
	// No rate limiter created, so no cleanup needed

	tests := []struct {
		name      string
		token     string
		wantError bool
	}{
		{
			name:      "Valid GitHub token",
			token:     "ghp_testtoken123456789abcdef",
			wantError: false,
		},
		{
			name:      "Empty token",
			token:     "",
			wantError: false,
		},
		{
			name:      "Token with special characters",
			token:     "token-with-!@#$%^&*()_+-=",
			wantError: false,
		},
		{
			name:      "Very long token",
			token:     strings.Repeat("a", 500),
			wantError: false,
		},
		{
			name:      "Token with newlines",
			token:     "token\nwith\nnewlines",
			wantError: false,
		},
		{
			name:      "Token with unicode",
			token:     "token-with-émoji-🔒",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt the token
			encrypted, err := app.encryptToken(tt.token)
			if (err != nil) != tt.wantError {
				t.Errorf("encryptToken() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if tt.wantError {
				return
			}

			// Verify encryption actually changed the value (unless empty)
			if tt.token != "" && encrypted == tt.token {
				t.Error("CRITICAL: Token not encrypted - stored as plaintext!")
			}

			// Verify encrypted token is base64-like (no raw binary)
			if strings.ContainsAny(encrypted, "\x00\x01\x02\x03\x04\x05\x06\x07\x08") {
				t.Error("Encrypted token contains raw binary - should be base64")
			}

			// Decrypt the token
			decrypted, err := app.decryptToken(encrypted)
			if err != nil {
				t.Errorf("decryptToken() error = %v", err)
				return
			}

			// Verify round-trip encryption/decryption
			if decrypted != tt.token {
				t.Errorf("Token round-trip failed: got %q, want %q", decrypted, tt.token)
			}
		})
	}
}

// TestTokenEncryptionWithoutKey verifies behavior when session secret is missing
// CRITICAL: Should fail safely rather than store plaintext
func TestTokenEncryptionWithoutKey(t *testing.T) {
	app := &App{
		config: Config{
			SessionSecret: "", // Empty session secret
			EncryptionKey: "", // Empty encryption key
		},
	}

	token := "ghp_testtokenshouldnotbestoredinplaintext"
	
	// Attempt to encrypt without a session secret
	encrypted, err := app.encryptToken(token)
	
	// With empty secret, should still encrypt (uses zero key) but not store plaintext
	if encrypted == token {
		t.Error("CRITICAL: Token stored in plaintext when session secret missing!")
	}
	
	// Verify it's actually encrypted even with empty key
	if err == nil && token != "" && encrypted == token {
		t.Error("CRITICAL: Non-empty token matches ciphertext - no encryption applied!")
	}
}

// TestTokenEncryptionKeyRotation verifies tokens can't be decrypted with wrong key
// IMPORTANT: Ensures key rotation doesn't expose old tokens
func TestTokenEncryptionKeyRotation(t *testing.T) {
	// Encrypt with first encryption key
	app1 := &App{
		config: Config{
			SessionSecret: "first-session-secret-key",
			EncryptionKey: "first-encryption-key-for-tokens",
		},
	}
	
	token := "ghp_secrettoken"
	encrypted, err := app1.encryptToken(token)
	if err != nil {
		t.Fatalf("Failed to encrypt with first key: %v", err)
	}
	
	// Try to decrypt with different encryption key
	app2 := &App{
		config: Config{
			SessionSecret: "second-different-session-secret",
			EncryptionKey: "second-different-encryption-key",
		},
	}
	
	decrypted, err := app2.decryptToken(encrypted)
	
	// Should fail to decrypt with wrong key
	if err == nil && decrypted == token {
		t.Error("CRITICAL: Token decrypted with wrong key - encryption broken!")
	}
	
	// Should get an error when decrypting with wrong key
	if err == nil {
		t.Error("Expected error when decrypting with wrong key, got none")
	}
}

// TestEncryptionConsistency verifies same input produces different ciphertext
// IMPORTANT: Ensures proper IV/nonce usage
func TestEncryptionConsistency(t *testing.T) {
	app := &App{
		config: Config{
			SessionSecret: "test-session-secret-for-consistency",
			EncryptionKey: "test-encryption-key-consistency",
		},
	}
	token := "ghp_sametoken"
	
	// Encrypt same token twice
	encrypted1, err1 := app.encryptToken(token)
	encrypted2, err2 := app.encryptToken(token)
	
	if err1 != nil || err2 != nil {
		t.Fatalf("Encryption failed: %v, %v", err1, err2)
	}
	
	// Ciphertext should be different due to IV/nonce
	if encrypted1 == encrypted2 {
		t.Error("Same token produces identical ciphertext - IV/nonce not used properly")
	}
	
	// But both should decrypt to same value
	decrypted1, _ := app.decryptToken(encrypted1)
	decrypted2, _ := app.decryptToken(encrypted2)
	
	if decrypted1 != token || decrypted2 != token {
		t.Error("Encrypted tokens don't decrypt to original value")
	}
}

// TestDatabaseTokenStorage verifies tokens are encrypted when stored in database
// CRITICAL: Ensures no plaintext tokens in database
func TestDatabaseTokenStorage(t *testing.T) {
	// Setup test database
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	defer db.Close()

	// Create users table with token field
	_, err = db.Exec(`
		CREATE TABLE users (
			id INTEGER PRIMARY KEY,
			email TEXT,
			github_token TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create users table: %v", err)
	}

	app := &App{
		config: Config{
			SessionSecret: "test-secret-for-db-storage",
			EncryptionKey: "test-encryption-key-for-storage",
		},
		db: db,
	}

	// Test data
	testToken := "ghp_verysecretgithubtoken123456789"
	testEmail := "test@example.com"

	// Encrypt token before storage
	encryptedToken, err := app.encryptToken(testToken)
	if err != nil {
		t.Fatalf("Failed to encrypt token: %v", err)
	}

	// Store encrypted token
	_, err = db.Exec("INSERT INTO users (email, github_token) VALUES (?, ?)", 
		testEmail, encryptedToken)
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}

	// Verify what's actually in the database
	var storedToken string
	err = db.QueryRow("SELECT github_token FROM users WHERE email = ?", testEmail).Scan(&storedToken)
	if err != nil {
		t.Fatalf("Failed to retrieve token: %v", err)
	}

	// Critical checks
	if storedToken == testToken {
		t.Error("CRITICAL: GitHub token stored in plaintext in database!")
	}

	if !strings.Contains(storedToken, "ghp_") {
		// Good - token is encrypted
		t.Log("✓ Token is properly encrypted in database")
	} else {
		t.Error("Token appears to contain plaintext GitHub token prefix")
	}

	// Verify we can decrypt it back
	decryptedToken, err := app.decryptToken(storedToken)
	if err != nil {
		t.Errorf("Failed to decrypt stored token: %v", err)
	}

	if decryptedToken != testToken {
		t.Errorf("Decrypted token doesn't match original: got %q, want %q", 
			decryptedToken, testToken)
	}
}
