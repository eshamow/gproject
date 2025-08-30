package main

import (
	"os"
	"strings"
	"testing"
)

// TestEncryptionKeyConfiguration verifies ENCRYPTION_KEY is properly configured
func TestEncryptionKeyConfiguration(t *testing.T) {
	t.Run("EncryptionKey falls back to SessionSecret", func(t *testing.T) {
		// Set up environment
		os.Setenv("GITHUB_CLIENT_ID", "test-client")
		os.Setenv("GITHUB_CLIENT_SECRET", "test-secret")
		os.Setenv("SESSION_SECRET", "test-session-secret-32-bytes-long")
		os.Setenv("GITHUB_REPO_OWNER", "test-owner")
		os.Setenv("GITHUB_REPO_NAME", "test-repo")
		defer func() {
			os.Unsetenv("GITHUB_CLIENT_ID")
			os.Unsetenv("GITHUB_CLIENT_SECRET")
			os.Unsetenv("SESSION_SECRET")
			os.Unsetenv("ENCRYPTION_KEY")
			os.Unsetenv("GITHUB_REPO_OWNER")
			os.Unsetenv("GITHUB_REPO_NAME")
		}()

		// Test without ENCRYPTION_KEY (should fall back to SESSION_SECRET)
		config := Config{
			SessionSecret: mustGetEnv("SESSION_SECRET"),
			EncryptionKey: getEnv("ENCRYPTION_KEY", mustGetEnv("SESSION_SECRET")),
		}
		
		if config.EncryptionKey != config.SessionSecret {
			t.Error("EncryptionKey should fall back to SessionSecret when not set")
		}
		
		// Test with ENCRYPTION_KEY set
		os.Setenv("ENCRYPTION_KEY", "separate-encryption-key-32-bytes")
		config.EncryptionKey = getEnv("ENCRYPTION_KEY", mustGetEnv("SESSION_SECRET"))
		
		if config.EncryptionKey == config.SessionSecret {
			t.Error("EncryptionKey should be different from SessionSecret when explicitly set")
		}
		
		if config.EncryptionKey != "separate-encryption-key-32-bytes" {
			t.Errorf("EncryptionKey not set correctly: got %s", config.EncryptionKey)
		}
	})

	t.Run("Token encryption uses EncryptionKey", func(t *testing.T) {
		// Set up test app with separate keys
		app := &App{
			config: Config{
				SessionSecret: "session-secret-for-cookies-only",
				EncryptionKey: "encryption-key-for-tokens-only!!",
			},
		}
		
		// Encrypt a test token
		testToken := "github-access-token-12345"
		encrypted, err := app.encryptToken(testToken)
		if err != nil {
			t.Fatalf("Failed to encrypt token: %v", err)
		}
		
		// Decrypt it back
		decrypted, err := app.decryptToken(encrypted)
		if err != nil {
			t.Fatalf("Failed to decrypt token: %v", err)
		}
		
		if decrypted != testToken {
			t.Errorf("Token not encrypted/decrypted correctly: got %s, want %s", decrypted, testToken)
		}
		
		// Verify that using wrong key fails
		appWrongKey := &App{
			config: Config{
				SessionSecret: "wrong-session-secret",
				EncryptionKey: "wrong-encryption-key",
			},
		}
		
		_, err = appWrongKey.decryptToken(encrypted)
		if err == nil {
			t.Error("Decryption should fail with wrong encryption key")
		}
	})

	t.Run("Encryption key requirements", func(t *testing.T) {
		// Test that encryption works with various key lengths
		// AES-256 requires 32-byte key after SHA-256 hashing
		
		testKeys := []string{
			"short", // Will be hashed to 32 bytes
			"medium-length-key-here",
			"this-is-a-32-byte-key-exactly!!",
			"this-is-a-very-long-key-that-exceeds-32-bytes-but-will-be-hashed",
		}
		
		for _, key := range testKeys {
			app := &App{
				config: Config{
					EncryptionKey: key,
				},
			}
			
			// All keys should work after SHA-256 hashing
			testData := "test-token-data"
			encrypted, err := app.encryptToken(testData)
			if err != nil {
				t.Errorf("Encryption failed with key length %d: %v", len(key), err)
				continue
			}
			
			decrypted, err := app.decryptToken(encrypted)
			if err != nil {
				t.Errorf("Decryption failed with key length %d: %v", len(key), err)
				continue
			}
			
			if decrypted != testData {
				t.Errorf("Round trip failed with key length %d", len(key))
			}
		}
	})
}

// TestEncryptionSeparationOfConcerns verifies keys are used for their intended purposes
func TestEncryptionSeparationOfConcerns(t *testing.T) {
	t.Run("SessionSecret not used for token encryption", func(t *testing.T) {
		app := &App{
			config: Config{
				SessionSecret: "only-for-session-cookies",
				EncryptionKey: "only-for-token-encryption",
			},
		}
		
		// Encrypt with EncryptionKey
		token := "github-token"
		encrypted, _ := app.encryptToken(token)
		
		// Try to decrypt with SessionSecret (simulate using wrong key)
		appWrongKey := &App{
			config: Config{
				EncryptionKey: app.config.SessionSecret, // Wrong! Using SessionSecret
			},
		}
		
		_, err := appWrongKey.decryptToken(encrypted)
		if err == nil {
			t.Error("CRITICAL: SessionSecret can decrypt tokens - keys not properly separated")
		}
	})
}

// TestEncryptionKeyDocumentation verifies .env.example has proper documentation
func TestEncryptionKeyDocumentation(t *testing.T) {
	// Read .env.example from project root
	content, err := os.ReadFile("../../.env.example")
	if err != nil {
		// Try current directory as fallback
		content, err = os.ReadFile(".env.example")
		if err != nil {
			t.Skip(".env.example not found in test context")
			return
		}
	}
	
	envExample := string(content)
	
	// Check for ENCRYPTION_KEY
	if !strings.Contains(envExample, "ENCRYPTION_KEY=") {
		t.Error(".env.example missing ENCRYPTION_KEY")
	}
	
	// Check for security note
	if !strings.Contains(envExample, "Security Keys") || !strings.Contains(envExample, "REQUIRED") {
		t.Error(".env.example should mark security keys as REQUIRED")
	}
	
	// Check for generation instructions
	if !strings.Contains(envExample, "openssl rand") || !strings.Contains(envExample, "32") {
		t.Error(".env.example should include instructions for generating secure keys")
	}
}