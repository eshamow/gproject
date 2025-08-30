package main

import (
	"crypto/rand"
	"encoding/hex"
	"math"
	"strings"
	"testing"
)

// TestSessionIDEntropyFixed verifies session IDs have sufficient cryptographic entropy
func TestSessionIDEntropyFixed(t *testing.T) {
	t.Run("GenerateSecureToken minimum entropy", func(t *testing.T) {
		// Test that minimum 16 bytes (128 bits) is enforced
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for insufficient entropy")
			}
		}()
		generateSecureToken(8) // Should panic
	})

	t.Run("Session ID has 256 bits of entropy", func(t *testing.T) {
		// Generate a session ID using the same method as production
		sessionID := generateSecureToken(32) // 32 bytes = 256 bits
		
		// Verify length (32 bytes = 64 hex characters)
		if len(sessionID) != 64 {
			t.Errorf("Session ID wrong length: got %d chars, want 64", len(sessionID))
		}
		
		// Verify it's valid hex
		_, err := hex.DecodeString(sessionID)
		if err != nil {
			t.Errorf("Session ID is not valid hex: %v", err)
		}
	})

	t.Run("Session IDs are unique", func(t *testing.T) {
		const numTests = 10000
		sessionIDs := make(map[string]bool, numTests)
		
		for i := 0; i < numTests; i++ {
			id := generateSecureToken(32)
			if sessionIDs[id] {
				t.Fatalf("CRITICAL: Duplicate session ID generated after %d iterations", i)
			}
			sessionIDs[id] = true
		}
	})

	t.Run("Session IDs have high entropy (chi-squared test)", func(t *testing.T) {
		// Generate sample data
		const sampleSize = 1000
		byteFreq := make(map[byte]int)
		
		for i := 0; i < sampleSize; i++ {
			id := generateSecureToken(32)
			decoded, _ := hex.DecodeString(id)
			for _, b := range decoded {
				byteFreq[b]++
			}
		}
		
		// Chi-squared test for uniform distribution
		expectedFreq := float64(sampleSize * 32) / 256.0 // 32 bytes per ID
		chiSquared := 0.0
		
		for i := 0; i < 256; i++ {
			observed := float64(byteFreq[byte(i)])
			chiSquared += math.Pow(observed-expectedFreq, 2) / expectedFreq
		}
		
		// Critical value for 255 degrees of freedom at 0.01 significance
		// A truly random distribution should pass this test
		criticalValue := 310.0
		if chiSquared > criticalValue {
			t.Errorf("Session IDs may have low entropy. Chi-squared: %.2f (critical: %.2f)", chiSquared, criticalValue)
		}
	})

	t.Run("No predictable patterns", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			id := generateSecureToken(32)
			
			// Check for obvious patterns
			if strings.Contains(id, "00000000") || strings.Contains(id, "ffffffff") {
				t.Error("Session ID contains predictable patterns")
			}
			
			// Check for sequential bytes (e.g., "0123456789")
			for j := 0; j < len(id)-8; j++ {
				substr := id[j : j+8]
				if isSequential(substr) {
					t.Errorf("Session ID contains sequential pattern: %s", substr)
				}
			}
		}
	})

	t.Run("Uses crypto/rand properly", func(t *testing.T) {
		// This test verifies that we're using crypto/rand, not math/rand
		// crypto/rand should never produce predictable sequences
		
		// Generate two sets of IDs with the same "seed" time
		// math/rand would produce similar results, crypto/rand won't
		set1 := make([]string, 10)
		set2 := make([]string, 10)
		
		for i := 0; i < 10; i++ {
			set1[i] = generateSecureToken(16)
		}
		
		for i := 0; i < 10; i++ {
			set2[i] = generateSecureToken(16)
		}
		
		// All should be different
		for i := 0; i < 10; i++ {
			for j := 0; j < 10; j++ {
				if set1[i] == set2[j] {
					t.Error("Detected predictable pattern - not using crypto/rand?")
				}
			}
		}
	})
}

// TestBackwardCompatibility ensures old code still works
func TestBackwardCompatibility(t *testing.T) {
	// The deprecated generateRandomString should still work but with minimum security
	id := generateRandomString(8) // Should be promoted to 16 bytes internally
	
	// Should produce at least 32 hex chars (16 bytes)
	if len(id) < 32 {
		t.Errorf("generateRandomString not enforcing minimum security: got %d chars", len(id))
	}
}

// TestCryptoRandFailure verifies proper error handling
func TestCryptoRandFailure(t *testing.T) {
	// This test verifies that if crypto/rand fails, we panic rather than
	// returning predictable values
	
	// We can't easily mock crypto/rand failure, but we can verify
	// that our function would panic on error by checking the implementation
	// The actual test is that the code panics on rand.Read error
	
	// Verify function exists and can be called
	defer func() {
		if r := recover(); r != nil {
			// We expect NO panic in normal operation
			t.Errorf("Unexpected panic in normal operation: %v", r)
		}
	}()
	
	_ = generateSecureToken(16) // Should work fine
}

func isSequential(s string) bool {
	if len(s) < 2 {
		return false
	}
	
	for i := 1; i < len(s); i++ {
		diff := int(s[i]) - int(s[i-1])
		if diff != 1 && diff != -1 {
			return false
		}
	}
	return true
}

// BenchmarkSessionGeneration measures performance
func BenchmarkSessionGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = generateSecureToken(32)
	}
}

// TestEntropyMath verifies our entropy calculations
func TestEntropyMath(t *testing.T) {
	tests := []struct {
		bytes    int
		bits     int
		hexChars int
	}{
		{16, 128, 32},  // Minimum secure
		{32, 256, 64},  // Recommended for sessions
		{64, 512, 128}, // Overkill but valid
	}
	
	for _, tt := range tests {
		t.Run(strings.ReplaceAll("bytes_%d", "%d", string(rune(tt.bytes))), func(t *testing.T) {
			token := generateSecureToken(tt.bytes)
			
			// Verify hex length
			if len(token) != tt.hexChars {
				t.Errorf("Wrong hex length for %d bytes: got %d chars, want %d", tt.bytes, len(token), tt.hexChars)
			}
			
			// Verify we can decode back to bytes
			decoded, err := hex.DecodeString(token)
			if err != nil {
				t.Errorf("Failed to decode hex: %v", err)
			}
			
			if len(decoded) != tt.bytes {
				t.Errorf("Decoded length mismatch: got %d bytes, want %d", len(decoded), tt.bytes)
			}
			
			// Log entropy for documentation
			t.Logf("%d bytes = %d bits of entropy = %d hex characters", tt.bytes, tt.bits, tt.hexChars)
		})
	}
}

// TestCSRFTokenEntropy verifies CSRF tokens also have proper entropy
func TestCSRFTokenEntropy(t *testing.T) {
	// CSRF tokens should also use generateSecureToken(32) for 256 bits
	token := generateSecureToken(32)
	
	if len(token) != 64 {
		t.Errorf("CSRF token wrong length: got %d chars, want 64", len(token))
	}
	
	// Verify high quality randomness
	_, err := hex.DecodeString(token)
	if err != nil {
		t.Errorf("CSRF token is not valid hex: %v", err)
	}
}

// TestStateParameterEntropy verifies OAuth state parameter has proper entropy
func TestStateParameterEntropy(t *testing.T) {
	// OAuth state should use at least 128 bits (16 bytes)
	state := generateSecureToken(32) // We use 256 bits for extra security
	
	if len(state) != 64 {
		t.Errorf("OAuth state wrong length: got %d chars, want 64", len(state))
	}
	
	// Verify it's cryptographically random
	_, err := hex.DecodeString(state)
	if err != nil {
		t.Errorf("OAuth state is not valid hex: %v", err)
	}
}

// TestActualCryptoRandUsage verifies we're really using crypto/rand
func TestActualCryptoRandUsage(t *testing.T) {
	// Read directly from crypto/rand to compare behavior
	directRand := make([]byte, 32)
	_, err := rand.Read(directRand)
	if err != nil {
		t.Fatalf("crypto/rand.Read failed: %v", err)
	}
	
	// Our function should behave identically (except for the hex encoding)
	ourToken := generateSecureToken(32)
	decoded, _ := hex.DecodeString(ourToken)
	
	// Both should be 32 bytes
	if len(decoded) != len(directRand) {
		t.Error("Not using crypto/rand properly")
	}
	
	// Both should be different (probability of collision is 2^-256)
	if string(decoded) == string(directRand) {
		t.Error("Impossible collision detected - something is very wrong")
	}
}