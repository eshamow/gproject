#!/bin/bash

# Test webhook locally - simulates GitHub sending an issue event
# Usage: ./test_webhook.sh

echo "Testing webhook with a sample issue event..."

# Get webhook secret from .env if it exists
WEBHOOK_SECRET=$(grep GITHUB_WEBHOOK_SECRET .env 2>/dev/null | cut -d '=' -f2 | tr -d '"' | tr -d "'")

# Sample issue payload (minimal valid GitHub issue webhook)
PAYLOAD='{
  "action": "opened",
  "issue": {
    "id": 12345678,
    "number": 100,
    "title": "Test Issue from Webhook Script",
    "body": "This is a test issue body to verify webhook processing",
    "state": "open",
    "created_at": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
    "updated_at": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
    "closed_at": null,
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

# Calculate signature if secret exists
if [ -n "$WEBHOOK_SECRET" ]; then
    SIGNATURE="sha256=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | cut -d' ' -f2)"
    echo "Using webhook secret for signature validation"
    
    curl -X POST http://localhost:8080/webhook/github \
        -H "Content-Type: application/json" \
        -H "X-GitHub-Event: issues" \
        -H "X-GitHub-Delivery: test-$(date +%s)" \
        -H "X-Hub-Signature-256: $SIGNATURE" \
        -d "$PAYLOAD" \
        -w "\nHTTP Status: %{http_code}\n"
else
    echo "No webhook secret configured, sending without signature"
    
    curl -X POST http://localhost:8080/webhook/github \
        -H "Content-Type: application/json" \
        -H "X-GitHub-Event: issues" \
        -H "X-GitHub-Delivery: test-$(date +%s)" \
        -d "$PAYLOAD" \
        -w "\nHTTP Status: %{http_code}\n"
fi

echo ""
echo "Check the application logs to see if the webhook was processed."
echo "Then check the database:"
echo "  sqlite3 data/gproject.db \"SELECT number, title, state FROM issues WHERE number=100;\""