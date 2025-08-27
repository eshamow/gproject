# Quick Start Guide

## Prerequisites

- Go 1.21 or higher
- GitHub account
- A GitHub repository to track issues from

## Setup Instructions

### 1. Register GitHub OAuth Application

1. Go to GitHub Settings → Developer settings → OAuth Apps → New OAuth App
2. Fill in:
   - **Application name**: GProject (or your choice)
   - **Homepage URL**: http://localhost:8080
   - **Authorization callback URL**: http://localhost:8080/auth/callback
3. Click "Register application"
4. Copy the Client ID and generate a Client Secret

### 2. Configure Environment

Create a `.env` file in the project root:

```bash
# GitHub OAuth (from step 1)
GITHUB_CLIENT_ID=your_client_id_here
GITHUB_CLIENT_SECRET=your_client_secret_here

# Session secret (generate a 32-byte random string)
SESSION_SECRET=your-32-character-session-secret-here!!

# Repository to sync
GITHUB_REPO_OWNER=owner_name
GITHUB_REPO_NAME=repo_name

# Optional configuration
PORT=8080
DATABASE_PATH=./data/gproject.db
```

### 3. Build and Run

```bash
# Build the application
make build

# Or build directly
go build -o gproject cmd/web/main.go

# Run the application
./gproject
```

### 4. Use the Application

1. Open http://localhost:8080
2. Click "Login with GitHub"
3. Authorize the application
4. Click "Sync with GitHub" on the dashboard
5. Browse and search your issues!

## Development Mode

For development with auto-reload:

```bash
# Install air (if not already installed)
go install github.com/air-verse/air@latest

# Run with auto-reload
make dev
```

## Testing

Run the test suite:

```bash
make test
```

## Production Deployment

### Single Binary Deployment

```bash
# Build for Linux (most servers)
GOOS=linux GOARCH=amd64 go build -o gproject cmd/web/main.go

# Copy to server and run
scp gproject user@server:/path/to/app/
ssh user@server
cd /path/to/app
./gproject
```

### Systemd Service (Linux)

Create `/etc/systemd/system/gproject.service`:

```ini
[Unit]
Description=GProject GitHub Issues Frontend
After=network.target

[Service]
Type=simple
User=gproject
WorkingDirectory=/opt/gproject
ExecStart=/opt/gproject/gproject
Restart=on-failure
Environment="PORT=8080"
EnvironmentFile=/opt/gproject/.env

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable gproject
sudo systemctl start gproject
```

## Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| GITHUB_CLIENT_ID | Yes | GitHub OAuth App Client ID | `abc123def456` |
| GITHUB_CLIENT_SECRET | Yes | GitHub OAuth App Client Secret | `secret123...` |
| SESSION_SECRET | Yes | 32-byte secret for sessions | `must-be-exactly-32-bytes-long!!` |
| GITHUB_REPO_OWNER | Yes | Repository owner/organization | `facebook` |
| GITHUB_REPO_NAME | Yes | Repository name | `react` |
| DATABASE_PATH | No | SQLite database location | `./data/gproject.db` |
| PORT | No | HTTP server port | `8080` |
| GITHUB_REDIRECT_URL | No | OAuth callback URL | `http://localhost:8080/auth/callback` |

## Common Issues

### "Invalid OAuth state"
- Clear your cookies and try logging in again
- Ensure your redirect URL matches exactly in GitHub settings

### "Rate limit exceeded"
- The app handles rate limits gracefully
- Wait for the limit to reset (usually within an hour)

### "Database locked"
- Only one sync operation can run at a time
- Wait for the current sync to complete

## Next Steps

- Week 2: Add epics and themes for issue organization
- Week 3: Add custom fields and enrichments
- Week 4: Build reporting and analytics features

## Support

For issues or questions, check the `/docs` directory for detailed documentation.