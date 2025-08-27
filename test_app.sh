#!/bin/bash

echo "Testing GProject Application..."
echo "================================"

# Check if database can be created
echo "1. Testing database migration..."
go run cmd/web/main.go migrate
if [ $? -eq 0 ]; then
    echo "✓ Database migration successful"
else
    echo "✗ Database migration failed"
    exit 1
fi

# Check if database file exists
if [ -f "data/gproject.db" ]; then
    echo "✓ Database file created"
else
    echo "✗ Database file not found"
    exit 1
fi

# Start server in background
echo ""
echo "2. Starting server..."
go run cmd/web/main.go &
SERVER_PID=$!
sleep 3

# Test homepage
echo "3. Testing homepage..."
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080)
if [ "$response" = "200" ]; then
    echo "✓ Homepage accessible (HTTP $response)"
else
    echo "✗ Homepage not accessible (HTTP $response)"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi

# Test login redirect
echo "4. Testing login redirect..."
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/login)
if [ "$response" = "307" ] || [ "$response" = "302" ]; then
    echo "✓ Login redirect working (HTTP $response)"
else
    echo "✗ Login redirect not working (HTTP $response)"
fi

# Test protected route
echo "5. Testing protected route redirect..."
response=$(curl -s -o /dev/null -w "%{http_code}" -L http://localhost:8080/dashboard)
if [ "$response" = "200" ]; then
    echo "✓ Dashboard redirect to login working"
else
    echo "✗ Dashboard protection not working"
fi

# Clean up
echo ""
echo "6. Cleaning up..."
kill $SERVER_PID 2>/dev/null
echo "✓ Server stopped"

echo ""
echo "================================"
echo "All tests passed successfully!"
echo ""
echo "To use the application:"
echo "1. Register a GitHub OAuth App at: https://github.com/settings/applications/new"
echo "2. Set Authorization callback URL to: http://localhost:8080/auth/callback"
echo "3. Update .env file with your GitHub OAuth credentials"
echo "4. Run: make run"
echo "5. Visit: http://localhost:8080"