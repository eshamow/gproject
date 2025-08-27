# GProject - GitHub Issues Frontend

A simple and fast web application for syncing and managing GitHub Issues with OAuth authentication, built with Go, SQLite, HTMX, and Tailwind CSS.

## Features

- **GitHub OAuth Authentication** - Secure login with GitHub
- **Issue Synchronization** - Sync issues from any GitHub repository
- **Real-time Statistics** - Track open and closed issues
- **Fast & Simple** - Built with HTMX for smooth interactions
- **SQLite Database** - No external database dependencies
- **CSRF Protection** - Secure against cross-site request forgery

## Quick Start

### Prerequisites

- Go 1.21 or higher
- A GitHub account
- Git

### Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd gproject
   ```

2. **Register a GitHub OAuth App**
   - Go to https://github.com/settings/applications/new
   - Application name: `GProject` (or your choice)
   - Homepage URL: `http://localhost:8080`
   - Authorization callback URL: `http://localhost:8080/auth/callback`
   - Click "Register application"
   - Note down the Client ID and Client Secret

3. **Configure environment**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` and update:
   - `GITHUB_CLIENT_ID`: Your GitHub OAuth App Client ID
   - `GITHUB_CLIENT_SECRET`: Your GitHub OAuth App Client Secret
   - `GITHUB_REPO_OWNER`: Your GitHub username or organization
   - `GITHUB_REPO_NAME`: The repository name to sync issues from
   - `SESSION_SECRET`: Generate a random 32-character string

4. **Install dependencies**
   ```bash
   make deps
   ```

5. **Run the application**
   ```bash
   make run
   ```

6. **Visit the application**
   Open http://localhost:8080 in your browser

## Project Structure

```
gproject/
├── cmd/
│   └── web/
│       ├── main.go          # Application entry point
│       └── templates/        # HTML templates
├── data/                     # SQLite database location
├── web/
│   └── templates/           # Original template location
├── .env.example             # Environment variables template
├── .air.toml               # Hot reload configuration
├── Makefile                # Build and run commands
└── go.mod                  # Go module dependencies
```

## Available Commands

```bash
make run        # Run the application
make dev        # Run with hot reload (requires air)
make test       # Run tests
make build      # Build binary
make db-reset   # Reset database
make clean      # Clean build artifacts
```

## Database Schema

The application uses SQLite with the following main tables:

- **users** - GitHub authenticated users
- **sessions** - User sessions for authentication
- **issues** - Synced GitHub issues
- **repositories** - Repository information

## Development

### Hot Reload

For development with hot reload:

```bash
go install github.com/air-verse/air@latest
make dev
```

### Testing

Run the test suite:

```bash
./test_app.sh
```

## Technologies Used

- **Go** - Backend language
- **SQLite** (modernc.org/sqlite) - Pure Go SQLite driver
- **HTMX** - Dynamic HTML without JavaScript
- **Tailwind CSS** - Utility-first CSS framework
- **GitHub OAuth2** - Authentication
- **Go HTML Templates** - Server-side rendering

## Security

- CSRF protection on OAuth flow
- Secure session management
- HttpOnly cookies
- SQL injection protection via parameterized queries

## Configuration

All configuration is done through environment variables:

| Variable | Description | Required |
|----------|-------------|----------|
| PORT | Server port (default: 8080) | No |
| DATABASE_URL | SQLite database path | No |
| GITHUB_CLIENT_ID | GitHub OAuth App Client ID | Yes |
| GITHUB_CLIENT_SECRET | GitHub OAuth App Secret | Yes |
| GITHUB_REDIRECT_URL | OAuth callback URL | No |
| SESSION_SECRET | Session encryption key | Yes |
| GITHUB_REPO_OWNER | GitHub repository owner | Yes |
| GITHUB_REPO_NAME | GitHub repository name | Yes |
| ENVIRONMENT | Environment (development/production) | No |

## Troubleshooting

### Port already in use
```bash
lsof -ti:8080 | xargs kill -9
```

### Database issues
```bash
make db-reset
```

### Missing dependencies
```bash
go mod download
go mod tidy
```

## License

MIT License - see LICENSE file for details