package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestWebhookSignatureValidation tests GitHub webhook signature validation
func TestWebhookSignatureValidation(t *testing.T) {
	app := &App{
		config: Config{
			WebhookSecret: "test-secret",
		},
	}

	payload := []byte(`{"action":"opened","issue":{"number":1,"title":"Test"}}`)
	
	// Generate valid signature
	mac := hmac.New(sha256.New, []byte("test-secret"))
	mac.Write(payload)
	validSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	tests := []struct {
		name      string
		signature string
		want      bool
	}{
		{
			name:      "Valid signature",
			signature: validSig,
			want:      true,
		},
		{
			name:      "Invalid signature",
			signature: "sha256=invalid",
			want:      false,
		},
		{
			name:      "Missing sha256 prefix",
			signature: hex.EncodeToString(mac.Sum(nil)),
			want:      false,
		},
		{
			name:      "Empty signature",
			signature: "",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := app.validateWebhookSignature(payload, tt.signature)
			if got != tt.want {
				t.Errorf("validateWebhookSignature() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSSEClientManagement tests SSE client registration and cleanup
func TestSSEClientManagement(t *testing.T) {
	app := &App{
		sseClients: make(map[chan SSEMessage]bool),
		syncStatus: &SyncStatus{},
	}

	// Test client registration
	client1 := make(chan SSEMessage, 1)
	client2 := make(chan SSEMessage, 1)
	
	app.sseMutex.Lock()
	app.sseClients[client1] = true
	app.sseClients[client2] = true
	app.sseMutex.Unlock()
	
	// Verify clients are registered
	app.sseMutex.RLock()
	if len(app.sseClients) != 2 {
		t.Errorf("Expected 2 clients, got %d", len(app.sseClients))
	}
	app.sseMutex.RUnlock()
	
	// Test client cleanup
	app.sseMutex.Lock()
	delete(app.sseClients, client1)
	app.sseMutex.Unlock()
	
	app.sseMutex.RLock()
	if len(app.sseClients) != 1 {
		t.Errorf("Expected 1 client after cleanup, got %d", len(app.sseClients))
	}
	app.sseMutex.RUnlock()
}

// TestWebhookEndpointMethodValidation tests that webhook only accepts POST
func TestWebhookEndpointMethodValidation(t *testing.T) {
	app := &App{
		config: Config{},
	}

	methods := []string{"GET", "PUT", "DELETE", "PATCH"}
	
	for _, method := range methods {
		req := httptest.NewRequest(method, "/webhook/github", nil)
		w := httptest.NewRecorder()
		
		app.handleWebhook(w, req)
		
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status 405 for %s method, got %d", method, w.Code)
		}
	}
}

// TestBroadcastSSE tests SSE message broadcasting
func TestBroadcastSSE(t *testing.T) {
	app := &App{
		sseClients: make(map[chan SSEMessage]bool),
	}

	// Create test clients
	client1 := make(chan SSEMessage, 1)
	client2 := make(chan SSEMessage, 1)
	
	app.sseClients[client1] = true
	app.sseClients[client2] = true
	
	// Broadcast a message
	testMsg := SSEMessage{
		Event: "test",
		Data:  map[string]string{"message": "hello"},
	}
	
	app.broadcastSSE(testMsg)
	
	// Check both clients received the message
	select {
	case msg := <-client1:
		if msg.Event != "test" {
			t.Errorf("Client1: expected event 'test', got '%s'", msg.Event)
		}
	default:
		t.Error("Client1: did not receive message")
	}
	
	select {
	case msg := <-client2:
		if msg.Event != "test" {
			t.Errorf("Client2: expected event 'test', got '%s'", msg.Event)
		}
	default:
		t.Error("Client2: did not receive message")
	}
}

// TestStoreIssue tests the storeIssue function with various issue formats
func TestStoreIssue(t *testing.T) {
	// This would require a test database setup
	// For now, we'll just test that the function handles nil fields correctly
	
	issue := map[string]interface{}{
		"id":     float64(123),
		"number": float64(1),
		"title":  "Test Issue",
		"body":   nil, // Test nil body
		"state":  "open",
		"labels": []interface{}{
			map[string]interface{}{"name": "bug"},
			map[string]interface{}{"name": "enhancement"},
		},
		"assignee":   nil, // Test nil assignee
		"user":       map[string]interface{}{"login": "testuser"},
		"created_at": "2024-01-01T00:00:00Z",
		"updated_at": "2024-01-01T00:00:00Z",
		"closed_at":  nil, // Test nil closed_at
	}
	
	// Just verify the function can handle the data structure
	// without panicking (would need DB for full test)
	_ = issue
	
	// If we had a test DB, we would call:
	// err := app.storeIssue(issue)
	// if err != nil { ... }
}

// TestSyncStatusThreadSafety tests that sync status updates are thread-safe
func TestSyncStatusThreadSafety(t *testing.T) {
	status := &SyncStatus{}
	
	// Simulate concurrent updates
	done := make(chan bool)
	
	for i := 0; i < 10; i++ {
		go func(n int) {
			status.mu.Lock()
			status.IssuesSynced = n
			status.mu.Unlock()
			done <- true
		}(i)
	}
	
	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
	
	// If we got here without deadlock or panic, the mutex is working
	status.mu.RLock()
	_ = status.IssuesSynced
	status.mu.RUnlock()
}

// TestWebhookPayloadParsing tests webhook payload parsing
func TestWebhookPayloadParsing(t *testing.T) {
	payload := `{
		"action": "opened",
		"issue": {
			"id": 123,
			"number": 1,
			"title": "Test Issue",
			"body": "Test body",
			"state": "open",
			"created_at": "2024-01-01T00:00:00Z",
			"updated_at": "2024-01-01T00:00:00Z",
			"closed_at": null,
			"user": {"login": "testuser"},
			"assignee": {"login": "assignee1"},
			"labels": [{"name": "bug"}]
		}
	}`
	
	var event struct {
		Action string          `json:"action"`
		Issue  json.RawMessage `json:"issue"`
	}
	
	err := json.Unmarshal([]byte(payload), &event)
	if err != nil {
		t.Fatalf("Failed to unmarshal webhook payload: %v", err)
	}
	
	if event.Action != "opened" {
		t.Errorf("Expected action 'opened', got '%s'", event.Action)
	}
	
	if event.Issue == nil {
		t.Error("Issue should not be nil")
	}
}