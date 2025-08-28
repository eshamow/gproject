#!/bin/bash

# Test that webhook updates are reflected in the UI
# Usage: ./test_issue_update.sh

echo "Testing issue update via webhook..."
echo "================================="
echo ""

# Check current issues in database
echo "Current issues in database:"
sqlite3 data/gproject.db "SELECT number, title, state, datetime(synced_at, 'localtime') as synced FROM issues ORDER BY number DESC LIMIT 5;" 2>/dev/null || echo "Database not accessible"
echo ""

# Create test webhook for closing an issue
WEBHOOK_SECRET=$(grep GITHUB_WEBHOOK_SECRET .env 2>/dev/null | cut -d '=' -f2 | tr -d '"' | tr -d "'")

# Close issue #100 (or update if already closed)
PAYLOAD='{
  "action": "closed",
  "issue": {
    "id": 12345678,
    "number": 100,
    "title": "Test Issue from Webhook Script - CLOSED",
    "body": "This issue was closed via webhook",
    "state": "closed",
    "created_at": "2025-08-28T10:00:00Z",
    "updated_at": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
    "closed_at": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
    "user": {
      "login": "testuser"
    },
    "assignee": null,
    "labels": []
  },
  "repository": {
    "owner": {
      "login": "eshamow"
    },
    "name": "gproject"
  }
}'

if [ -n "$WEBHOOK_SECRET" ]; then
    SIGNATURE="sha256=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | cut -d' ' -f2)"
    
    echo "Sending webhook to close issue #100..."
    curl -s -X POST http://localhost:8080/webhook/github \
        -H "Content-Type: application/json" \
        -H "X-GitHub-Event: issues" \
        -H "X-GitHub-Delivery: test-close-$(date +%s)" \
        -H "X-Hub-Signature-256: $SIGNATURE" \
        -d "$PAYLOAD" \
        -w "HTTP Status: %{http_code}\n"
else
    echo "Sending webhook to close issue #100..."
    curl -s -X POST http://localhost:8080/webhook/github \
        -H "Content-Type: application/json" \
        -H "X-GitHub-Event: issues" \
        -H "X-GitHub-Delivery: test-close-$(date +%s)" \
        -d "$PAYLOAD" \
        -w "HTTP Status: %{http_code}\n"
fi

echo ""
sleep 1

# Check if the issue was updated
echo "Checking database after webhook..."
sqlite3 data/gproject.db "SELECT number, title, state, datetime(synced_at, 'localtime') as synced FROM issues WHERE number=100;" 2>/dev/null || echo "Issue not found"

echo ""
echo "Now check the dashboard at http://localhost:8080/dashboard"
echo "The issue should show as closed. If not visible immediately:"
echo "  1. Wait up to 60 seconds for auto-refresh"
echo "  2. Or manually refresh the page"
echo "  3. Or click 'Sync with GitHub Issues' button"
echo ""
echo "You can also check the API directly:"
echo "  curl -s http://localhost:8080/api/issues | jq '.issues[] | select(.number==100)'"